package main

import (
	"flag"
	"fmt"
	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"yisshd/lpasswd"
	"yisshd/tools"
)

var DefaultShell = "sh"

func main() {
	var (
		addr = flag.String("l", ":22", "绑定Host地址")
	)
	flag.Parse()

	//denyLogin := sync.Map{}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	err = tools.CreateKey()
	if err != nil {
		log.Fatal(err)
		return
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ctx := lpasswd.NewAuthCtx()
			ok, err := lpasswd.VerifyPass(ctx, c.User(), string(pass))
			if ok {
				return new(ssh.Permissions), nil
			}
			return nil, fmt.Errorf("password rejected for %s", err)
		},
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := os.ReadFile(dir + "/private.pem")
	if err != nil {
		log.Fatal("Failed to load private key (./private.pem)")
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen (%s)", err)
	}

	log.Printf("Listening on port %s", *addr)
	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				//log.Printf("Failed to accept incoming connection (%s)", err)
				continue
			}
			_, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
			if err != nil {
				//log.Printf("Failed to handshake (%s)", err)
				continue
			}

			//log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
			// Discard all global out-of-band Requests
			go ssh.DiscardRequests(reqs)
			// Accept all channels
			go handleChannels(chans)
		}
	}()

	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range signalChan {
			fmt.Println("safe exit")
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Allocate a terminal for this channel
	//log.Print("Creating pty...")
	f, tty, err := pty.Open()
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		return
	}

	var shell string
	shell = os.Getenv("SHELL")
	if shell == "" {
		shell = DefaultShell
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			ok := false
			switch req.Type {
			case "exec":
				ok = true
				command := string(req.Payload[4 : req.Payload[3]+4])
				cmd := exec.Command(shell, []string{"-c", command}...)

				cmd.Stdout = connection
				cmd.Stderr = connection
				cmd.Stdin = connection

				err = cmd.Start()
				if err != nil {
					log.Printf("could not start command (%s)", err)
					continue
				}

				// teardown session
				go func() {
					err = cmd.Wait()
					if err != nil {
						log.Printf("failed to exit bash (%s)", err)
					}
					_ = connection.Close()
					log.Printf("session closed")
				}()
			case "shell":
				cmd := exec.Command(shell)
				cmd.Env = []string{"TERM=xterm"}
				err := PtyRun(cmd, tty)
				if err != nil {
					log.Printf("%s", err)
				}

				// Teardown session
				var once sync.Once
				cl := func() {
					_ = connection.Close()
					log.Printf("session closed")
				}

				// Pipe session to bash and visa-versa
				go func() {
					_, _ = io.Copy(connection, f)
					once.Do(cl)
				}()

				go func() {
					_, _ = io.Copy(f, connection)
					once.Do(cl)
				}()

				// We don't accept any commands (Payload),
				// only the default shell.
				if len(req.Payload) == 0 {
					ok = true
				}
			case "pty-req":
				// Responding 'ok' here will let the client
				// know we have a pty ready for input
				ok = true
				// Parse body...
				termLen := req.Payload[3]
				_ = string(req.Payload[4 : termLen+4])
				w, h := tools.ParseDims(req.Payload[termLen+4:])
				tools.SetWinsize(f.Fd(), w, h)
				//log.Printf("pty-req '%s'", termEnv)
			case "subsystem":
				if string(req.Payload[4:]) == "sftp" {
					ok = true
					go func() {
						debugStream := io.Discard
						serverOptions := []sftp.ServerOption{
							sftp.WithDebug(debugStream),
						}
						server, err := sftp.NewServer(
							connection,
							serverOptions...,
						)
						if err != nil {
							log.Printf("sftp server init error: %s\n", err)
							return
						}
						if err := server.Serve(); err == io.EOF {
							_ = server.Close()
							fmt.Println("sftp client exited session.")
						} else if err != nil {
							fmt.Println("sftp server completed with error:", err)
						}
					}()
				}
			case "window-change":
				w, h := tools.ParseDims(req.Payload)
				tools.SetWinsize(f.Fd(), w, h)
				continue //no response
			}
			if !ok {
				log.Printf("declining %s request...", req.Type)
			}
			_ = req.Reply(ok, nil)
		}
	}()
}

func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer func(tty *os.File) {
		_ = tty.Close()
	}(tty)
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	return c.Start()
}
