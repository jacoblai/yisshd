package forward

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type forwardData struct {
	DestinationHost string
	DestinationPort uint32

	OriginatorHost string
	OriginatorPort uint32
}

func DirectTcpIpHandler(newChan ssh.NewChannel) {
	d := forwardData{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	//if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestinationHost, d.DestinationPort) {
	//	newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
	//	return
	//}

	dest := fmt.Sprintf("%s:%d", d.DestinationHost, d.DestinationPort)

	var dialer net.Dialer
	dconn, err := dialer.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = dconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	// Teardown session
	var once sync.Once
	cl := func() {
		_ = ch.Close()
		_ = dconn.Close()
	}
	go func() {
		_, _ = io.Copy(ch, dconn)
		once.Do(cl)
	}()
	go func() {
		_, _ = io.Copy(dconn, ch)
		once.Do(cl)
	}()
}
