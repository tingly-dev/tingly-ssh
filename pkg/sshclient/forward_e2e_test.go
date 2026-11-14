package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is a minimal in-process SSH server that accepts any public key
// and supports direct-tcpip (local forwarding) channels.
type testSSHServer struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSSHServer{ln: ln}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, nc)
			s.mu.Unlock()
			go s.serve(nc, cfg)
		}
	}()
	t.Cleanup(func() { ln.Close(); s.dropAll() })
	return s
}

func (s *testSSHServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "direct-tcpip" {
			nch.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		var target struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		ssh.Unmarshal(nch.ExtraData(), &target)
		dst, err := net.Dial("tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
		if err != nil {
			nch.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() {
			defer ch.Close()
			defer dst.Close()
			go io.Copy(dst, ch)
			io.Copy(ch, dst)
		}()
	}
}

// dropAll kills every client connection, simulating the network going away
func (s *testSSHServer) dropAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
}

func (s *testSSHServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// startEchoServer echoes a single line back, then closes (server closes first)
func startEchoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				c.Write(buf[:n])
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func testClientKey(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

type lostRecorder struct{ ch chan string }

func (l *lostRecorder) OnConnectionLost(reason string) { l.ch <- reason }

func connectAndForward(t *testing.T, srv *testSSHServer, echoPort int) (*Client, int) {
	t.Helper()
	c := NewClient()
	err := c.Connect(&Config{Host: "127.0.0.1", Port: srv.port(), Username: "u", PrivateKey: testClientKey(t)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(c.Disconnect)
	state, err := c.EstablishTunnel(&TunnelConfig{RemoteHost: "127.0.0.1", RemotePort: echoPort})
	if err != nil {
		t.Fatalf("establish tunnel: %v", err)
	}
	return c, state.ForwardingPort
}

func roundTrip(localPort int, msg string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		return "", err
	}
	got, err := io.ReadAll(conn)
	return string(got), err
}

func TestForwardingEndToEnd(t *testing.T) {
	srv := newTestSSHServer(t)
	echoPort := startEchoServer(t)
	_, localPort := connectAndForward(t, srv, echoPort)

	// Several sequential requests: each one has the remote side close first,
	// which used to panic the whole process.
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("hello-%d", i)
		got, err := roundTrip(localPort, msg)
		if err != nil || got != msg {
			t.Fatalf("round trip %d: got %q, err %v", i, got, err)
		}
	}
}

func TestForwardingFixedPortReusableAfterReconnect(t *testing.T) {
	srv := newTestSSHServer(t)
	echoPort := startEchoServer(t)

	// Grab a free port to use as the fixed local port
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	fixed := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	key := testClientKey(t)
	for i := 0; i < 2; i++ {
		c := NewClient()
		if err := c.Connect(&Config{Host: "127.0.0.1", Port: srv.port(), Username: "u", PrivateKey: key}); err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		state, err := c.EstablishTunnel(&TunnelConfig{ForwardingLocalPort: fixed, RemoteHost: "127.0.0.1", RemotePort: echoPort})
		if err != nil {
			t.Fatalf("establish %d: %v", i, err)
		}
		if state.ForwardingPort != fixed {
			t.Fatalf("got port %d, want %d", state.ForwardingPort, fixed)
		}
		if got, err := roundTrip(fixed, "x"); err != nil || got != "x" {
			t.Fatalf("round trip %d: got %q, err %v", i, got, err)
		}
		c.Disconnect()
	}
}

func TestConnectionLostNotifiesListener(t *testing.T) {
	srv := newTestSSHServer(t)
	echoPort := startEchoServer(t)
	c, localPort := connectAndForward(t, srv, echoPort)

	rec := &lostRecorder{ch: make(chan string, 1)}
	c.SetConnectionListener(rec)

	srv.dropAll()

	select {
	case <-rec.ch:
	case <-time.After(3 * time.Second):
		t.Fatal("listener not notified after server dropped the connection")
	}
	if c.IsConnected() {
		t.Error("client still reports connected")
	}
	if _, err := roundTrip(localPort, "x"); err == nil {
		t.Error("forward port should be closed after connection loss")
	}
}

func TestDisconnectDoesNotNotifyListener(t *testing.T) {
	srv := newTestSSHServer(t)
	echoPort := startEchoServer(t)
	c, _ := connectAndForward(t, srv, echoPort)

	rec := &lostRecorder{ch: make(chan string, 1)}
	c.SetConnectionListener(rec)
	c.Disconnect()

	select {
	case r := <-rec.ch:
		t.Fatalf("listener called on intentional disconnect: %s", r)
	case <-time.After(300 * time.Millisecond):
	}
}
