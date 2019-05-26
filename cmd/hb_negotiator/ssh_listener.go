package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/FranGM/pfkey"
	"github.com/FranGM/simplelog"

	"golang.org/x/crypto/ssh"
)

type SSHNegotiator struct {
	privateKey ssh.Signer
	ngChan     chan NegotiationRequest
	AuthKeys   map[string][]ssh.PublicKey
}

type Negotiator interface {
	StartListener()
	RequestNegotiation(uint32, pfkey.Node) ([]byte, error)
}

func (s *SSHNegotiator) initPrivateKey() error {
	// TODO: This needs to be a config option
	privateKeyFile := "honeybadger/id_rsa"

	privateBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		if !os.IsNotExist(err) {

			return fmt.Errorf("Can't load private key: %v", err)
		}
		simplelog.Debug.Printf("Generating random private key...")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		s.privateKey, _ = ssh.NewSignerFromKey(key)
		simplelog.Debug.Printf("Done")

		// At this point we've generated new key so we store it for the next run

		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			},
		)

		// TODO: Error checking
		// TODO: Writing the generated private key to disk should be configurable
		os.MkdirAll(filepath.Dir(privateKeyFile), 0700)
		ioutil.WriteFile(privateKeyFile, pemdata, 0644)

	} else {
		s.privateKey, err = ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("Failed to parse private key: %v", err)
		}
	}

	return nil
}

func (s *SSHNegotiator) publicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

	remotehost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	simplelog.Error.Printf("====== remote is %+v", remotehost)

	listKeys, ok := s.AuthKeys[remotehost]
	if !ok {
		return nil, fmt.Errorf("No keys for %q", remotehost)
	}

	for _, authorizedKey := range listKeys {
		if bytes.Compare(key.Marshal(), authorizedKey.Marshal()) == 0 {
			// TODO: We should return a ssh.Permissions object instead, to allow for more fine-grained permissions in the future,
			//         such as accepting connections from users that are not allowed to negogiate associations
			//         (maybe so we can expose a stats interface instead)
			return nil, nil
		}

	}
	// TODO: This shouldn't be error, more like Info at best
	simplelog.Info.Printf("Rejecting auth for %q", remotehost)

	// At this point we're rejecting authentication for this user
	return nil, fmt.Errorf("Key rejected for %q", remotehost)
}

// initSSHServerConfig initializes the internal config for our SSH service,
// including reading/setting our own primary key and the list of authorized keys.
func (s *SSHNegotiator) initSSHServerConfig() *ssh.ServerConfig {
	// An SSH server is represented by a ServerConfig,
	// which holds certificate details and handles authentication of ServerConns.
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyAuth,
	}

	// Initialise map of authorized keys
	s.AuthKeys = make(map[string][]ssh.PublicKey)

	s.populateAuthorizedKeys()

	err := s.initPrivateKey()
	if err != nil {
		simplelog.Fatal.Printf("Error generating private key: %q", err)
	}

	serverConfig.AddHostKey(s.privateKey)

	return serverConfig
}

// StartListener starts our SSH service listener and waits for incoming negotiation requests.
func (s *SSHNegotiator) StartListener() {
	serverConfig := s.initSSHServerConfig()
	// TODO: Port should not be hardcoded here
	listener, err := net.Listen("tcp", "0.0.0.0:1337")
	if err != nil {
		simplelog.Fatal.Printf("Failed to listen for connections: %q", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			simplelog.Error.Printf("Failed to accept incoming connection: %q", err)
			continue
		}
		go s.handleConn(nConn, serverConfig)
	}
}

// populateAuthorizedKeys will populate our internal mapping of authorizedkeys with the public keys we have
// in our authorizedkeys directory.
func (s *SSHNegotiator) populateAuthorizedKeys() {
	fileList := []string{}
	// TODO: Path should not be hardcoded
	err := filepath.Walk("honeybadger/authorized", func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		// TODO: This shouldn't be a fatal error, we can recover gracefully from this
		simplelog.Fatal.Println(err)
	}

	for _, file := range fileList {
		b, err := ioutil.ReadFile(file)
		name := filepath.Base(file)

		// TODO: We should allow the possibility of more than one key per file
		pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			simplelog.Error.Printf("Error parsing authorized keys: %+v", err)
			continue
		}
		s.AuthKeys[name] = []ssh.PublicKey{pk}
	}
}

func (s *SSHNegotiator) handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		simplelog.Error.Printf("Error during handshake: %v", err)
		return
	}

	// TODO: Maybe we should receive this inside a channel
	// TODO: Should we validate there's only one request here?
	for req := range reqs {
		// With SSH we can usually receive several types of requests, such as "exec", "shell", or "env".
		switch req.Type {
		case "negotiation":
			b := bytes.NewBuffer(req.Payload)
			dec := gob.NewDecoder(b)
			var negReq NetworkRequest
			err := dec.Decode(&negReq)
			if err != nil {
				// TODO: Should reply with an error here.
				simplelog.Error.Printf("Error decoding message: %+v", err)
				return
			}

			spi := negReq.SPI

			srchost, _, _ := net.SplitHostPort(nConn.RemoteAddr().String())
			dsthost, _, _ := net.SplitHostPort(nConn.LocalAddr().String())

			srcIP := net.ParseIP(srchost)
			dstIP := net.ParseIP(dsthost)

			src := pfkey.Node{
				Addr: srcIP,
			}

			dst := pfkey.Node{
				Addr: dstIP,
			}

			simplelog.Info.Printf("spi=%d src=%+v dst=%+v", spi, src, dst)

			encryptSecondHalf := make([]byte, 16)
			rand.Read(encryptSecondHalf)

			response := NetworkRequest{
				SPI:        spi,
				EncryptKey: encryptSecondHalf,
			}

			respBytes := new([]byte)
			respBuf := bytes.NewBuffer(*respBytes)
			enc := gob.NewEncoder(respBuf)
			err = enc.Encode(response)
			if err != nil {
				simplelog.Error.Println(err)
				return
			}

			err = req.Reply(true, respBuf.Bytes())
			if err != nil {
				simplelog.Error.Println(err)
				return
			}

			// TODO: This is really terrible and should be done properly within its own function
			var encryptKey []byte
			encryptKey = make([]byte, len(negReq.EncryptKey))
			copy(negReq.EncryptKey, encryptKey)
			encryptKey = append(encryptKey, encryptSecondHalf...)

			// We should actually negotiate here things like encryption/auth keys/algorithms
			s.ngChan <- NegotiationRequest{SPI: spi,
				src:        src,
				dst:        dst,
				encryptKey: encryptKey,
			}

		default:
			// TODO: We could detect regular ssh connections and give some information/debugging options (provided authentication has succeeded, of course)
			//channel.Write([]byte("Malformed Request\n"))
			req.Reply(false, nil)
		}
	}

	// XXX: Does this even make sense in this context? Will having more than one incoming channel be something we'll support?
	for newChannel := range chans {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
	}
}

func (s *SSHNegotiator) handleNewChannel(newChannel ssh.NewChannel) {
	// TODO: Can we make this something other than session to make it explicit what we use it for?
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		// TODO: Is there any other cleanup I should do here?
		simplelog.Error.Printf("Could not accept SSH channel: %q", err)
		return
	}

	// TODO: Should we allow more than one request?
	for req := range requests {
		// With SSH we can usually receive several types of requests, such as "exec", "shell", or "env".
		switch req.Type {
		case "negotiation":
			go s.handleSSHRequest(channel, req)

		default:
			// TODO: We could detect regular ssh connections and give some information/debugging options (provided authentication has succeeded, of course)
			channel.Write([]byte("Malformed Request\n"))
			req.Reply(false, nil)
		}
	}
}

func (s *SSHNegotiator) handleSSHRequest(channel ssh.Channel, req *ssh.Request) {
	ok := true
	simplelog.Info.Printf("Payload received is %+v", req.Payload)
	defer channel.Close()
	req.Reply(ok, nil)
}
