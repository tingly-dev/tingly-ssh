package sshclient

import (
	"io"
	"net"
	"testing"
	"time"
)

// pipeAndWait runs pipeConnections in the background and returns a channel closed when it returns.
func pipeAndWait(a, b net.Conn) <-chan struct{} {
	finished := make(chan struct{})
	go func() {
		pipeConnections(a, b)
		close(finished)
	}()
	return finished
}

func waitFinished(t *testing.T, finished <-chan struct{}) {
	t.Helper()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeConnections did not return")
	}
	// Give any straggling goroutine a moment to (not) panic
	time.Sleep(50 * time.Millisecond)
}

// Regression: remote closing first used to panic with "send on closed channel",
// killing the whole app process.
func TestPipeConnectionsRemoteClosesFirst(t *testing.T) {
	local, localPeer := net.Pipe()
	remote, remotePeer := net.Pipe()
	defer localPeer.Close()

	finished := pipeAndWait(local, remote)
	remotePeer.Close()

	waitFinished(t, finished)
}

func TestPipeConnectionsLocalClosesFirst(t *testing.T) {
	local, localPeer := net.Pipe()
	remote, remotePeer := net.Pipe()
	defer remotePeer.Close()

	finished := pipeAndWait(local, remote)
	localPeer.Close()

	waitFinished(t, finished)
}

func TestPipeConnectionsCopiesBothWays(t *testing.T) {
	local, localPeer := net.Pipe()
	remote, remotePeer := net.Pipe()

	finished := pipeAndWait(local, remote)

	go localPeer.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(remotePeer, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("local->remote: got %q, err %v", buf, err)
	}

	go remotePeer.Write([]byte("pong"))
	if _, err := io.ReadFull(localPeer, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("remote->local: got %q, err %v", buf, err)
	}

	remotePeer.Close()
	waitFinished(t, finished)
	localPeer.Close()
}
