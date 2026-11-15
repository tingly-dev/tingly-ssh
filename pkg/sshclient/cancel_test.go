package sshclient

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// stalledServer accepts TCP connections but never speaks SSH, like a server
// hanging in the handshake. Returns its port.
func stalledServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, nc)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func errCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return -1
}

// connectAsync starts c.Connect and returns its result channel
func connectAsync(c *Client, cfg *Config) <-chan error {
	errc := make(chan error, 1)
	go func() { errc <- c.Connect(cfg) }()
	return errc
}

func waitErr(t *testing.T, errc <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(within):
		t.Fatalf("Connect still running after %s", within)
		return nil
	}
}

func TestDisconnectCancelsStalledConnect(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: stalledServer(t), Username: "u", PrivateKey: testClientKey(t)}
	c := NewClient()
	errc := connectAsync(c, cfg)

	time.Sleep(200 * time.Millisecond) // let it reach the handshake
	start := time.Now()
	c.Disconnect()
	if d := time.Since(start); d > time.Second {
		t.Errorf("Disconnect blocked %s while connecting", d)
	}
	if err := waitErr(t, errc, 2*time.Second); errCode(err) != ErrCancelled {
		t.Fatalf("got %v, want ErrCancelled", err)
	}
	if c.IsConnected() {
		t.Fatal("connected after cancel")
	}

	// The client is usable again afterwards
	srv := newTestSSHServer(t)
	if err := c.Connect(&Config{Host: "127.0.0.1", Port: srv.port(), Username: "u", PrivateKey: cfg.PrivateKey}); err != nil {
		t.Fatalf("connect after cancel: %v", err)
	}
	c.Disconnect()
}

func TestDisconnectCancelsConnectViaJumpHost(t *testing.T) {
	jump := newTestSSHServer(t)
	key := testClientKey(t)
	cfg := &Config{
		Host: "127.0.0.1", Port: stalledServer(t), Username: "target", PrivateKey: key,
		Jump: &Config{Host: "127.0.0.1", Port: jump.port(), Username: "jump", PrivateKey: key},
	}
	c := NewClient()
	errc := connectAsync(c, cfg)

	time.Sleep(300 * time.Millisecond)
	c.Disconnect()
	if err := waitErr(t, errc, 2*time.Second); errCode(err) != ErrCancelled {
		t.Fatalf("got %v, want ErrCancelled", err)
	}
}

func TestStalledHandshakeTimesOut(t *testing.T) {
	old := connectTimeout
	connectTimeout = 300 * time.Millisecond
	t.Cleanup(func() { connectTimeout = old })

	cfg := &Config{Host: "127.0.0.1", Port: stalledServer(t), Username: "u", PrivateKey: testClientKey(t)}
	if err := waitErr(t, connectAsync(NewClient(), cfg), 3*time.Second); errCode(err) != ErrTimeout {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
}

func TestConcurrentConnectRejected(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: stalledServer(t), Username: "u", PrivateKey: testClientKey(t)}
	c := NewClient()
	errc := connectAsync(c, cfg)
	time.Sleep(200 * time.Millisecond)

	if err := c.Connect(cfg); errCode(err) != ErrAlreadyConnected {
		t.Errorf("second Connect: got %v, want ErrAlreadyConnected", err)
	}
	c.Disconnect()
	waitErr(t, errc, 2*time.Second)
}
