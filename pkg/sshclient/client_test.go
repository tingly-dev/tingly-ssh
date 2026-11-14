package sshclient

import (
	"testing"
)

func TestNewSshClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestSshClientIsConnectedInitially(t *testing.T) {
	client := NewClient()

	if client.IsConnected() {
		t.Error("New client should not be connected")
	}
}

func TestSshClientDisconnectWhenNotConnected(t *testing.T) {
	client := NewClient()

	// Should not panic
	client.Disconnect()
}

func TestSshClientConnectWithNilConfig(t *testing.T) {
	client := NewClient()

	err := client.Connect(nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
}

func TestSshConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "empty host",
			config: &Config{
				Port:       22,
				Username:   "user",
				PrivateKey: "key",
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			config: &Config{
				Host:       "example.com",
				Port:       -1,
				Username:   "user",
				PrivateKey: "key",
			},
			wantErr: true,
		},
		{
			name: "port too high",
			config: &Config{
				Host:       "example.com",
				Port:       70000,
				Username:   "user",
				PrivateKey: "key",
			},
			wantErr: true,
		},
		{
			name: "empty username",
			config: &Config{
				Host:       "example.com",
				Port:       22,
				PrivateKey: "key",
			},
			wantErr: true,
		},
		{
			name: "empty private key",
			config: &Config{
				Host:     "example.com",
				Port:     22,
				Username: "user",
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &Config{
				Host:       "example.com",
				Port:       22,
				Username:   "user",
				PrivateKey: "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config == nil {
				// Test nil separately
				return
			}
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTunnelConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *TunnelConfig
		wantErr bool
	}{
		{
			name: "nil config",
			config: &TunnelConfig{
				// All zeros should be valid for ports (auto-assign)
				RemoteHost: "example.com",
				RemotePort: 80,
			},
			wantErr: false,
		},
		{
			name: "invalid tunnel port",
			config: &TunnelConfig{
				TunnelLocalPort: -1,
				RemoteHost:      "example.com",
				RemotePort:      80,
			},
			wantErr: true,
		},
		{
			name: "invalid forwarding port",
			config: &TunnelConfig{
				ForwardingLocalPort: 70000,
				RemoteHost:          "example.com",
				RemotePort:          80,
			},
			wantErr: true,
		},
		{
			name: "empty remote host",
			config: &TunnelConfig{
				RemotePort: 80,
			},
			wantErr: true,
		},
		{
			name: "invalid remote port",
			config: &TunnelConfig{
				RemoteHost: "example.com",
				RemotePort: 0,
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: &TunnelConfig{
				TunnelLocalPort:     8080,
				ForwardingLocalPort: 9090,
				RemoteHost:          "example.com",
				RemotePort:          80,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSshClientGetTunnelStateWhenNotConnected(t *testing.T) {
	client := NewClient()

	state := client.GetTunnelState()
	if state == nil {
		t.Fatal("GetTunnelState returned nil")
	}

	if state.IsConnected {
		t.Error("State should not be connected")
	}
}

func TestSshClientExecuteCommandWhenNotConnected(t *testing.T) {
	client := NewClient()

	_, err := client.ExecuteCommand("ls")
	if err == nil {
		t.Error("Expected error when not connected")
	}

	sshErr, ok := err.(*Error)
	if !ok {
		t.Error("Expected Error type")
	} else if sshErr.Code != ErrNotConnected {
		t.Errorf("Expected error code %d, got %d", ErrNotConnected, sshErr.Code)
	}
}

func TestSshClientEstablishTunnelWhenNotConnected(t *testing.T) {
	client := NewClient()

	config := &TunnelConfig{
		RemoteHost: "example.com",
		RemotePort: 80,
	}

	_, err := client.EstablishTunnel(config)
	if err == nil {
		t.Error("Expected error when not connected")
	}
}

func TestSshClientCloseTunnelWhenNotConnected(t *testing.T) {
	client := NewClient()

	// Should not panic
	client.CloseTunnel()
}

func TestSshConfigFields(t *testing.T) {
	config := &Config{}

	config.Host = "example.com"
	if config.Host != "example.com" {
		t.Error("Host field access failed")
	}

	config.Port = 2222
	if config.Port != 2222 {
		t.Error("Port field access failed")
	}

	config.Username = "testuser"
	if config.Username != "testuser" {
		t.Error("Username field access failed")
	}

	config.PrivateKey = "test-key"
	if config.PrivateKey != "test-key" {
		t.Error("PrivateKey field access failed")
	}

	config.Passphrase = "test-pass"
	if config.Passphrase != "test-pass" {
		t.Error("Passphrase field access failed")
	}

	config.KnownHosts = "test-hosts"
	if config.KnownHosts != "test-hosts" {
		t.Error("KnownHosts field access failed")
	}
}

func TestTunnelConfigFields(t *testing.T) {
	config := &TunnelConfig{}

	config.TunnelLocalPort = 8080
	if config.TunnelLocalPort != 8080 {
		t.Error("TunnelLocalPort field access failed")
	}

	config.ForwardingLocalPort = 9090
	if config.ForwardingLocalPort != 9090 {
		t.Error("ForwardingLocalPort field access failed")
	}

	config.RemoteHost = "example.com"
	if config.RemoteHost != "example.com" {
		t.Error("RemoteHost field access failed")
	}

	config.RemotePort = 443
	if config.RemotePort != 443 {
		t.Error("RemotePort field access failed")
	}
}

func TestTunnelStateFields(t *testing.T) {
	state := &TunnelState{
		IsConnected:    true,
		TunnelPort:     8080,
		ForwardingPort: 9090,
		ErrorMessage:   "test error",
	}

	if !state.IsConnected {
		t.Error("IsConnected field access failed")
	}

	if state.TunnelPort != 8080 {
		t.Error("TunnelPort field access failed")
	}

	if state.ForwardingPort != 9090 {
		t.Error("ForwardingPort field access failed")
	}

	if state.ErrorMessage != "test error" {
		t.Error("ErrorMessage field access failed")
	}
}

// Benchmarks
func BenchmarkSshConfigValidate(b *testing.B) {
	config := &Config{
		Host:       "example.com",
		Port:       22,
		Username:   "user",
		PrivateKey: "test-key",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Validate()
	}
}
