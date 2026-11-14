package sshclient

import "fmt"

// Config holds SSH connection configuration
// Matches dev.tingly.box_mobile.data.model.Config for easy Kotlin interop
type Config struct {
	Host       string // SSH server hostname or IP
	Port       int    // SSH server port (default: 22)
	Username   string // SSH username
	PrivateKey string // Private key content (PEM format)
	Passphrase string // Passphrase for encrypted private key (optional)
	KnownHosts string // Known hosts content (optional, for host verification)
}

// Validate validates the SSH configuration
func (c *Config) Validate() error {
	if c.Host == "" {
		return newError(ErrInvalidConfig, "host is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return newError(ErrInvalidConfig, "port must be between 1 and 65535")
	}
	if c.Username == "" {
		return newError(ErrInvalidConfig, "username is required")
	}
	if c.PrivateKey == "" {
		return newError(ErrInvalidConfig, "private key is required")
	}
	return nil
}

// TunnelConfig holds port forwarding configuration
// Matches dev.tingly.box_mobile.data.model.TunnelConfig for easy Kotlin interop
type TunnelConfig struct {
	TunnelLocalPort     int    // Local port for SOCKS tunnel (0 for auto-assign)
	ForwardingLocalPort int    // Local port for direct forwarding (0 for auto-assign)
	RemoteHost          string // Remote host for port forwarding
	RemotePort          int    // Remote port for port forwarding
}

// Validate validates the tunnel configuration
func (c *TunnelConfig) Validate() error {
	if c.TunnelLocalPort < 0 || c.TunnelLocalPort > 65535 {
		return newError(ErrInvalidConfig, "tunnel local port must be between 0 and 65535")
	}
	if c.ForwardingLocalPort < 0 || c.ForwardingLocalPort > 65535 {
		return newError(ErrInvalidConfig, "forwarding local port must be between 0 and 65535")
	}
	if c.RemoteHost == "" {
		return newError(ErrInvalidConfig, "remote host is required")
	}
	if c.RemotePort <= 0 || c.RemotePort > 65535 {
		return newError(ErrInvalidConfig, "remote port must be between 1 and 65535")
	}
	return nil
}

// TunnelState represents the current state of a tunnel
type TunnelState struct {
	IsConnected    bool   // Whether SSH connection is active
	TunnelPort     int    // Assigned local port for tunnel (0 if not active)
	ForwardingPort int    // Assigned local port for forwarding (0 if not active)
	ErrorMessage   string // Last error message (empty if no error)
}

// KeyInfo holds information about a parsed SSH key
type KeyInfo struct {
	Format        string // Key format: "RSA", "Ed25519", "ECDSA", "DSA"
	Bits          int    // Key size in bits
	Fingerprint   string // SHA256 fingerprint
	PublicKey     string // Public key in OpenSSH format
	Comment       string // Key comment (if any)
	HasPassphrase bool   // Whether the key is encrypted
}

// String returns a human-readable representation
func (i *KeyInfo) String() string {
	return fmt.Sprintf("%s-%d %s", i.Format, i.Bits, i.Fingerprint)
}

// KeyPairResult holds the result of key pair generation
// Used because gomobile only supports max 2 return values (result, error)
type KeyPairResult struct {
	PrivateKey string // The generated private key in PEM format
	PublicKey  string // The generated public key in OpenSSH format
}
