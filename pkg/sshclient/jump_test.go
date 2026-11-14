package sshclient

import (
	"strings"
	"testing"
	"time"
)

func jumpConfig(t *testing.T, jump, target *testSSHServer) *Config {
	t.Helper()
	key := testClientKey(t)
	return &Config{
		Host: "127.0.0.1", Port: target.port(), Username: "target", PrivateKey: key,
		Jump: &Config{Host: "127.0.0.1", Port: jump.port(), Username: "jump", PrivateKey: key},
	}
}

func TestJumpForwardsThroughJumpHost(t *testing.T) {
	jump, target := newTestSSHServer(t), newTestSSHServer(t)
	echoPort := startEchoServer(t)

	c := NewClient()
	if err := c.Connect(jumpConfig(t, jump, target)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(c.Disconnect)

	// The connection to the target itself went through the jump host
	if got := jump.forwards.Load(); got != 1 {
		t.Fatalf("jump host saw %d forwards after connect, want 1", got)
	}

	state, err := c.EstablishTunnel(&TunnelConfig{RemoteHost: "127.0.0.1", RemotePort: echoPort})
	if err != nil {
		t.Fatalf("establish tunnel: %v", err)
	}
	for i := 0; i < 3; i++ {
		if got, err := roundTrip(state.ForwardingPort, "ping"); err != nil || got != "ping" {
			t.Fatalf("round trip %d: got %q, err %v", i, got, err)
		}
	}
	// Forwarded traffic is opened on the target, not on the jump host
	if got := target.forwards.Load(); got != 3 {
		t.Errorf("target saw %d forwards, want 3", got)
	}
	if got := jump.forwards.Load(); got != 1 {
		t.Errorf("jump host saw %d forwards, want still 1", got)
	}
}

func TestJumpHostLossNotifiesListener(t *testing.T) {
	jump, target := newTestSSHServer(t), newTestSSHServer(t)
	c := NewClient()
	if err := c.Connect(jumpConfig(t, jump, target)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(c.Disconnect)
	rec := &lostRecorder{ch: make(chan string, 1)}
	c.SetConnectionListener(rec)

	jump.dropAll()

	select {
	case reason := <-rec.ch:
		if !strings.Contains(reason, "jump host") {
			t.Errorf("reason %q should name the jump host", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener not notified after the jump host dropped")
	}
	if c.IsConnected() {
		t.Error("client still reports connected")
	}
}

func TestDisconnectReleasesJumpHosts(t *testing.T) {
	jump, target := newTestSSHServer(t), newTestSSHServer(t)
	c := NewClient()
	if err := c.Connect(jumpConfig(t, jump, target)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	c.Disconnect()
	if len(c.jumps) != 0 {
		t.Errorf("jumps not released: %d", len(c.jumps))
	}
}

func TestJumpFailureNamesHop(t *testing.T) {
	jump, target := newTestSSHServer(t), newTestSSHServer(t)
	cfg := jumpConfig(t, jump, target)

	// Unreachable jump host
	dead := newTestSSHServer(t)
	deadCfg := *cfg
	deadJump := *cfg.Jump
	deadJump.Port = dead.port()
	deadCfg.Jump = &deadJump
	dead.ln.Close()
	if err := NewClient().Connect(&deadCfg); err == nil || !strings.Contains(err.Error(), "jump host") {
		t.Errorf("jump host failure: got %v, want mention of jump host", err)
	}

	// Reachable jump host, dead target
	target.ln.Close()
	if err := NewClient().Connect(cfg); err == nil || !strings.Contains(err.Error(), "target host") {
		t.Errorf("target failure: got %v, want mention of target host", err)
	}
}

func TestJumpConfigValidation(t *testing.T) {
	key := "k"
	hop := func(host string, jump *Config) *Config {
		return &Config{Host: host, Port: 22, Username: "u", PrivateKey: key, Jump: jump}
	}

	if err := hop("b", hop("a", nil)).Validate(); err != nil {
		t.Errorf("two hosts should be valid: %v", err)
	}
	if err := hop("c", hop("b", hop("a", nil))).Validate(); err == nil {
		t.Error("three hosts should exceed MaxHops")
	}

	bad := hop("b", &Config{Host: "a", Port: 22, Username: "", PrivateKey: key})
	if err := bad.Validate(); err == nil || !strings.HasPrefix(err.Error(), "jump host: ") {
		t.Errorf("invalid jump: got %v, want jump host prefix", err)
	}
	bad = hop("", hop("a", nil))
	if err := bad.Validate(); err == nil || !strings.HasPrefix(err.Error(), "target host: ") {
		t.Errorf("invalid target: got %v, want target host prefix", err)
	}

	// A single host keeps unprefixed errors
	if err := (&Config{Port: 22, Username: "u", PrivateKey: key}).Validate(); err == nil || strings.Contains(err.Error(), "host:") {
		t.Errorf("single host error should be unprefixed: %v", err)
	}

	// A cycle is rejected rather than followed forever
	a := hop("a", nil)
	a.Jump = a
	if err := a.Validate(); err == nil {
		t.Error("cyclic jump chain should be rejected")
	}
}
