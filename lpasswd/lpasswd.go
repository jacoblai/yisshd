// lpasswd - lib to handle storage and lookup of app-local users
// with passwords akin to /etc/passwd.
//
// Copyright (c) 2017-2020 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package lpasswd

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"runtime"
	"strings"

	passlib "gopkg.in/hlandau/passlib.v1"

	"github.com/jameskeane/bcrypt"
)

type AuthCtx struct {
	reader     func(string) ([]byte, error)     // eg. ioutil.ReadFile()
	userlookup func(string) (*user.User, error) // eg. os/user.Lookup()
}

func NewAuthCtx( /*reader func(string) ([]byte, error), userlookup func(string) (*user.User, error)*/ ) (ret *AuthCtx) {
	ret = &AuthCtx{os.ReadFile, user.Lookup}
	return
}

// --------- System passwd/shadow auth routine(s) --------------

// VerifyPass verifies a password against system standard shadow file
// Note auxilliary fields for expiry policy are *not* inspected.
func VerifyPass(ctx *AuthCtx, user, password string) (bool, error) {
	if ctx.reader == nil {
		ctx.reader = os.ReadFile // dependency injection hides that this is required
	}
	passlib.UseDefaults(passlib.Defaults20180601) //nolint:errcheck
	var pwFileName string
	if runtime.GOOS == "linux" {
		pwFileName = "/etc/shadow"
	} else if runtime.GOOS == "freebsd" {
		pwFileName = "/etc/master.passwd"
	} else {
		pwFileName = "unsupported"
	}
	pwFileData, e := ctx.reader(pwFileName)
	if e != nil {
		return false, e
	}
	pwLines := strings.Split(string(pwFileData), "\n")
	if len(pwLines) < 1 {
		return false, errors.New("Empty shadow file!")
	} else {
		var line string
		var hash string
		var idx int
		for idx = range pwLines {
			line = pwLines[idx]
			lFields := strings.Split(line, ":")
			if lFields[0] == user {
				hash = lFields[1]
				break
			}
		}
		if len(hash) == 0 {
			return false, errors.New("nil hash!")
		} else {
			pe := passlib.VerifyNoUpgrade(password, hash)
			if pe != nil {
				return false, pe
			}
		}
	}
	return true, nil
}

// --------- End System passwd/shadow auth routine(s) ----------

// --------- Local passwd auth routine(s) --------------

// AuthUserByPasswd checks user login information using a password.
// This checks file _fname_ for auth info, and optionally system /etc/passwd
// to cross-check the user actually exists, if sysacct == true.
// nolint: gocyclo
func AuthUserByPasswd(ctx *AuthCtx, sysacct bool, username string, auth string, fname string) (valid bool, err error) {
	if ctx.reader == nil {
		ctx.reader = os.ReadFile // dependency injection hides that this is required
	}
	if ctx.userlookup == nil {
		ctx.userlookup = user.Lookup // again for dependency injection as dep is now hidden
	}
	b, e := ctx.reader(fname) // nolint: gosec
	if e != nil {
		return false, fmt.Errorf("cannot read %s", fname)
	}
	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 3 // username:salt:authCookie
	for {
		var record []string
		record, err = r.Read()
		if errors.Is(err, io.EOF) {
			// Use dummy entry if user not found
			// (prevent user enumeration attack via obvious timing diff;
			// ie., not attempting any auth at all)
			record = []string{"$nosuchuser$",
				"$2a$12$l0coBlRDNEJeQVl6GdEPbU",
				"$2a$12$l0coBlRDNEJeQVl6GdEPbUC/xmuOANvqgmrMVum6S4i.EXPgnTXy6"}
			username = "$nosuchuser$"
			err = nil
		}
		if err != nil {
			return false, err
		}

		if username == record[0] {
			var tmp string
			tmp, err = bcrypt.Hash(auth, record[1])
			if err != nil {
				break
			}
			if tmp == record[2] && username != "$nosuchuser$" {
				valid = true
			} else {
				err = fmt.Errorf("auth failure")
			}
			break
		}
	}
	// Security scrub
	for i := range b {
		b[i] = 0
	}
	r = nil
	runtime.GC()

	if sysacct {
		_, userErr := ctx.userlookup(username)
		if userErr != nil {
			valid = false
		}
	}
	return
}

// SetPasswd enters _uname_ with the specified _passwd_ into the
// local password file _passwdFName_.
func SetPasswd(uname, passwd, passwdFName string) (e error) { // nolint: gocyclo
	if uname == "" {
		return errors.New("must specify a username")
	}
	// generate a random salt with specific rounds of complexity
	// (default in jameskeane/bcrypt is 12 but we'll be explicit here)
	salt, err := bcrypt.Salt(12)
	if err != nil {
		return fmt.Errorf("bcrypt.Salt() failed: %w", err)
	}
	// hash and verify a password with explicit (random) salt
	hash, err := bcrypt.Hash(passwd, salt)
	if err != nil || !bcrypt.Match(passwd, hash) {
		return fmt.Errorf("bcrypt.Match() failed: %w", err)
	}
	b, err := os.ReadFile(passwdFName) // nolint: gosec
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile(): %w", err)
	}
	r := csv.NewReader(bytes.NewReader(b))

	r.Comma = ':'
	r.Comment = '#'
	r.FieldsPerRecord = 3 // username:salt:authCookie]

	records, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("r.ReadAll(): %w", err)
	}

	recFound := false
	for i := range records {
		if records[i][0] == uname {
			recFound = true
			records[i][1] = salt
			records[i][2] = hash
		}
		//// csv lib doesn't preserve comment in record, so put it back
		//if records[i][0][0] == '!' {
		//	records[i][0] = "#" + records[i][0]
		//}
	}
	if !recFound {
		newRec := []string{uname, salt, hash}
		records = append(records, newRec)
	}

	outFile, err := ioutil.TempFile("", "xs-passwd")
	if err != nil {
		return fmt.Errorf("ioutil.TempFile(): %w", err)
	}
	w := csv.NewWriter(outFile)
	w.Comma = ':'
	//w.FieldsPerRecord = 4 // username:salt:authCookie:disallowedCmdList (a,b,...)
	err = w.Write([]string{"#username", "salt", "authCookie" /*, "disallowedCmdList"*/})
	if err != nil {
		return fmt.Errorf("w.Write(): %w", err)
	}
	err = w.WriteAll(records)
	if err != nil {
		return fmt.Errorf("w.WriteAll: %w", err)
	}
	err = os.Remove(passwdFName)
	if err != nil {
		return fmt.Errorf("os.Remove(): %w", err)
	}
	err = os.Rename(outFile.Name(), passwdFName)
	if err != nil {
		return fmt.Errorf("os.Rename(): %w", err)
	}
	return nil
}

// --------- End Local passwd auth routine(s) --------------
