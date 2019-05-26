package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"github.com/FranGM/pfkey"
	"github.com/FranGM/simplelog"
)

func init() {
	simplelog.SetThreshold(simplelog.LevelDebug)
}

// Get preferred outbound ip of this machine
// h4x from http://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()
	addr, _, _ := net.SplitHostPort(localAddr)

	return addr
}

// Returns true if our IP address is the one used as source for this association
// TODO: This is really naive, and I can't see it working well on systems with multiple IP addresses or possibly even when NAT is involved.
//         A smarter implementation is needed.
func amISrc(p pfkey.Msg) bool {
	myIP := getOutboundIP()
	// TODO: We should probably validate that the AddressSrc extension is present, otherwise we're just checking garbage.
	src := p.Extensions.SockAddrSrc.BuildNode()

	return myIP == src.Addr.String()
}

// RegisterPFKEY register with the kernel's PF_KEY socket to signal we're ready to negotiate SAs
func RegisterPFKEY(negotiator Negotiator) error {
	sock, err := pfkey.NewPFKEY()
	if err != nil {
		return err
	}
	defer sock.Close()

	sock.SendSADBRegisterMsg()

	// TODO: Can I actually receive other messages before the initial SADB_REGISTER response?
	regMsg, err := sock.ReadMsg()
	if err != nil {
		return err
	}

	// TODO: Can I even get an error here?
	if regMsg.Msg.Errno != 0 {
		return fmt.Errorf("Got an error when registering through PFKEY socket. Errno=%d", regMsg.Msg.Errno)
	}

	// TODO: Actually use this information
	var registration pfkey.Registration
	registration.AuthAlgorithms = regMsg.Extensions.AuthAlgorithms
	registration.EncrAlgorithms = regMsg.Extensions.EncryptAlgorithms

	simplelog.Debug.Printf("Registration done: %+v", registration)

	// XXX: This is just for dev purposes, it's easier to always start with a fresh SADB
	err = sock.SendSADBFLUSH()
	if err != nil {
		simplelog.Fatal.Println(err)
	}

	// TODO: Need to be able to exit this loop
	for {
		// TODO: Maybe we want this to run in a different goroutine that will send us the messages via a channel
		msg, err := sock.ReadMsg()
		if err != nil {
			return err
		}

		switch msg.Msg.Type {
		case pfkey.SADB_REGISTER:
			receiveREGISTERMessage(msg)

		case pfkey.SADB_UPDATE:
			// TODO: If it's a response to one of our UPDATE messages we should do something about it.
			simplelog.Info.Printf("Got SADB_UPDATE with errno=%d", msg.Msg.Errno)
		case pfkey.SADB_EXPIRE:
			err = receiveEXPIREMessage(msg, sock)
			if err != nil {
				simplelog.Error.Printf("Error processing EXPIRE message: %+v", err)
			}
		case pfkey.SADB_GETSPI:
			err = receiveGETSPIMessage(msg, sock, negotiator)
			if err != nil {
				simplelog.Error.Printf("Error processing GETSPI message: %+v", err)
			}

		case pfkey.SADB_ACQUIRE:

			err = receiveACQUIREMessage(msg, sock)
			if err != nil {
				return err
			}

			// TODO: We should make an internal note here of the SPI we're trying to build

		default:
			simplelog.Warning.Printf("NOT IMPLEMENTED. Received unexpected msg type: %d", msg.Msg.Type)
		}
	}

	//return nil
}

func receiveREGISTERMessage(msg pfkey.Msg) error {
	// From	RFC2367: "This message may arrive asynchronously due to an algorithm being loaded or unloaded into a dynamically linked kernel."
	simplelog.Info.Printf("NOT IMPLEMENTED. Got SADB_REGISTER message when we didn't expect it.")
	return nil
}

// receiveGETSPIMessage receives and process the response to a GETSPI message received from the kernel.
func receiveGETSPIMessage(msg pfkey.Msg, sock pfkey.PFKEY, negotiator Negotiator) error {
	// The kernel has responded to one of our GETSPI messages,
	// meaning we need to finish the negotiation with the other side.
	// TODO: Validate that it has our PID (can we even receive a GETSPI message meant for another process?)
	// TODO: Validate that it's for a Seq that we're waiting for
	// TODO: Validate that errno is set to 0

	src := msg.Extensions.SockAddrSrc.BuildNode()
	dst := msg.Extensions.SockAddrDst.BuildNode()

	// Now that we have an spi we should start negotiating with the other side
	encryptBits, err := negotiator.RequestNegotiation(msg.Extensions.SA.SPI, dst)
	if err != nil {
		// TODO: Here we actually have two options, either retry (after a suitable timeout) or ask the kernel to delete the SA. We should probably do both here.
		return err
	}

	// TODO: This oviously needs more args, like lifetime, encrypt/auth keys, encrypt/auth algorithms etc
	updateMsg, err := pfkey.BuildSADBUPDATE(msg.Msg.Seq, msg.Extensions.SA.SPI, src, dst, encryptBits)
	if err != nil {
		return err
	}
	err = sock.SendMsg(*updateMsg)

	return err
}

func receiveEXPIREMessage(msg pfkey.Msg, sock pfkey.PFKEY) error {
	// An SA has expired or is about to expire. Here's what we need to do:
	// 1. If the SA has already expired (past its hard lifetime)
	//      we ask the kernel to remove it from the SAD.
	// 2. If the SA is close to expiring but we're not the "source",
	//      we ignore it (and assume the other side will handle it).
	// 3. If the SA is close to expiring and we're the "source",
	//      we try to negotiate a new one (almost as if we just
	//      received an ACQUIRE mesage from the kernel)

	src := msg.Extensions.SockAddrSrc.BuildNode()
	dst := msg.Extensions.SockAddrDst.BuildNode()

	// If this message includes a hard lifetime extension that means
	// that the SA has already expired, so we need to clean it up.
	if msg.HasLifetimeHard() {
		deleteMsg, err := pfkey.BuildSADBDELETE(msg.Extensions.SA.SPI, src, dst)
		if err != nil {
			return err
		}
		err = sock.SendMsg(*deleteMsg)
		if err != nil {
			return err
		}
		return nil
	}

	// The message only includes a soft expiry, so we might need to
	// renegotiate another SA.
	// Only renegotiate a new SA if we're the source of the SA
	// that's expiring (the assumption being that the src of an SA
	// is the initiator)
	if amISrc(msg) {
		err := sock.SendSADBGETSPI(msg.Msg.Seq, src, dst)
		return err
	}

	return nil
}

//receiveACQUIREMessage processes an ACQUIRE message received from the kernel.
func receiveACQUIREMessage(msg pfkey.Msg, sock pfkey.PFKEY) error {
	// The kernel sent us an ACQUIRE message, which means that it wants
	// to stablish an SA, so our next step is to ask for an SPI to be
	// assigned to it.

	src := msg.Extensions.SockAddrSrc.BuildNode()
	dst := msg.Extensions.SockAddrDst.BuildNode()

	err := sock.SendSADBGETSPI(msg.Msg.Seq, src, dst)
	return err
}

func negotiator(ngChan chan NegotiationRequest) {
	sock, err := pfkey.NewPFKEY()
	if err != nil {
		simplelog.Fatal.Println(err)
	}

	for {
		select {
		case n := <-ngChan:
			simplelog.Info.Printf("Received negotiation request: %+v", n)
			msg, err := pfkey.BuildSADBADD(0, n.SPI, n.src, n.dst, n.encryptKey)
			if err != nil {
				simplelog.Error.Println(err)
			}
			err = sock.SendMsg(*msg)
			if err != nil {
				simplelog.Error.Println(err)
			}
			// TODO: Check for the result
		}
	}
}

// TODO: Needs a better name
type NetworkRequest struct {
	SPI        uint32
	EncryptKey []byte
	AuthKey    []byte
}

// getBytes returns an arbitrary object as a slice of bytes
func getBytes(object interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, object)
	return buf.Bytes(), err
}

// NegotiationRequest is our internal representation of an attempt to negotiate
// an SA with another node.
type NegotiationRequest struct {
	SPI        uint32
	src        pfkey.Node
	dst        pfkey.Node
	encryptKey []byte
}

// confRefresher catches any HUP signal that we might receive and
//   reloads our config and/or authorized keys.
func confRefresher(s *SSHNegotiator, c chan os.Signal) {
	for {
		<-c
		s.populateAuthorizedKeys()
	}
}

func main() {
	ngChan := make(chan NegotiationRequest, 10)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Signal(unix.SIGHUP))

	s := &SSHNegotiator{ngChan: ngChan}

	go negotiator(ngChan)
	go s.StartListener()

	go confRefresher(s, sigChan)

	err := RegisterPFKEY(s)
	if err != nil {
		simplelog.Fatal.Println(err)
	}
}
