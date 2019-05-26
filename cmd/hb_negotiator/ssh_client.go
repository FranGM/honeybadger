package main

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"net"

	"github.com/FranGM/pfkey"

	"golang.org/x/crypto/ssh"
)

func (s *SSHNegotiator) validateHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// XXX: Do actual validation
	return nil
}

func (s *SSHNegotiator) initSSHClientConfig() *ssh.ClientConfig {
	// TODO: User shouldn't be hardcoded, at least it should be configurable
	clientConfig := &ssh.ClientConfig{
		HostKeyCallback: s.validateHostKey,
		User:            "honeybadger",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(s.privateKey),
		},
	}

	return clientConfig
}

// RequestNegotiation starts a negotiation with dst to try to establish an SA
// Will return the encryptKey that has been negotiated.
func (s *SSHNegotiator) RequestNegotiation(spi uint32, dst pfkey.Node) (encryptKey []byte, err error) {
	// Build half the key
	encryptHalf := make([]byte, 16)
	rand.Read(encryptHalf)

	addr := fmt.Sprintf("%s:1337", dst.Addr.String())

	clientConfig := s.initSSHClientConfig()
	conn, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return encryptKey, err
	}
	defer conn.Close()

	req := negotiationResponse(spi, encryptHalf)

	b := new([]byte)
	buf := bytes.NewBuffer(*b)

	enc := gob.NewEncoder(buf)
	err = enc.Encode(req)

	ok, resp, err := conn.SendRequest("negotiation", true, buf.Bytes())
	if !ok || err != nil {
		return encryptKey, err
	}

	buf = bytes.NewBuffer(resp)

	dec := gob.NewDecoder(buf)
	var response NetworkRequest

	dec.Decode(&response)

	encryptKey = assembleEncryptKey(encryptHalf, response.EncryptKey)

	return encryptKey, err
}
