// Package mobile is the gomobile shell over pkg/sshclient for Android and iOS apps.
// It only mirrors types and forwards calls; implementation belongs in pkg/sshclient.
//
// Build with `make -C mobile android` or `make -C mobile ios`.
//
// Features:
//   - SSH connection with public key authentication
//   - Support for all key formats: RSA, Ed25519, ECDSA, DSA
//   - Support for encrypted keys (passphrase protected)
//   - Local port forwarding (tunneling)
//   - Remote port forwarding (reverse tunneling)
//   - Dynamic port forwarding (SOCKS5 proxy)
//   - Command execution on remote server
//
// Usage in Kotlin (Android):
//
//	val client = SshClient()
//	val config = SshConfig().apply {
//	    host = "example.com"
//	    port = 22
//	    username = "user"
//	    privateKey = "-----BEGIN RSA PRIVATE KEY-----..."
//	}
//	client.connect(config)
//	client.establishTunnel(TunnelConfig().apply {
//	    remoteHost = "internal.example.com"
//	    remotePort = 8080
//	})
package mobile

// Re-export types for gomobile
// This file ensures all types are properly exported

// Version information
const (
	Version   = "1.0.0"
	BuildDate = "2026-02-19"
)

// GetVersion returns the library version
func GetVersion() string {
	return Version
}

// GetBuildDate returns the build date
func GetBuildDate() string {
	return BuildDate
}

// LibraryInfo returns information about the library
type LibraryInfo struct {
	Version   string
	BuildDate string
	Features  []string
}

// GetLibraryInfo returns library information
func GetLibraryInfo() *LibraryInfo {
	return &LibraryInfo{
		Version:   Version,
		BuildDate: BuildDate,
		Features: []string{
			"SSH2 Protocol",
			"Public Key Authentication",
			"RSA/Ed25519/ECDSA/DSA Keys",
			"Encrypted Key Support",
			"Local Port Forwarding",
			"Remote Port Forwarding",
			"SOCKS5 Proxy",
			"Command Execution",
		},
	}
}

// Convenience functions for quick operations

// QuickVerify quickly verifies SSH credentials
// Returns nil on success, error on failure
func QuickVerify(host string, port int, username, privateKey, passphrase string) error {
	client := NewSshClient()
	defer client.Disconnect()

	config := &SshConfig{
		Host:       host,
		Port:       port,
		Username:   username,
		PrivateKey: privateKey,
		Passphrase: passphrase,
	}

	return client.VerifyConnection(config)
}

// QuickTunnel quickly establishes a tunnel and returns the result with local port
// Caller is responsible for calling result.GetClient().Disconnect() when done
func QuickTunnel(sshConfig *SshConfig, remoteHost string, remotePort int) (*QuickTunnelResult, error) {
	client := NewSshClient()

	if err := client.Connect(sshConfig); err != nil {
		return nil, err
	}

	tunnelConfig := &TunnelConfig{
		RemoteHost: remoteHost,
		RemotePort: remotePort,
	}

	state, err := client.EstablishTunnel(tunnelConfig)
	if err != nil {
		client.Disconnect()
		return nil, err
	}

	return &QuickTunnelResult{
		Client: client,
		Port:   state.ForwardingPort,
	}, nil
}

// QuickExecute executes a command on a remote server
func QuickExecute(sshConfig *SshConfig, command string) (string, error) {
	client := NewSshClient()
	defer client.Disconnect()

	if err := client.Connect(sshConfig); err != nil {
		return "", err
	}

	return client.ExecuteCommand(command)
}
