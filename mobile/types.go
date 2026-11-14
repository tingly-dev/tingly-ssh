package mobile

import "github.com/tingly-dev/tingly-ssh/pkg/sshclient"

// Data types are mirrored here because gomobile cannot export type aliases.
// Field sets must stay identical to their sshclient counterparts: conversions
// below rely on it, so any drift fails to compile.

// SshConfig holds SSH connection configuration.
type SshConfig struct {
	Host       string
	Port       int
	Username   string
	PrivateKey string
	Passphrase string
	KnownHosts string
}

// TunnelConfig holds port forwarding configuration.
type TunnelConfig struct {
	TunnelLocalPort     int
	ForwardingLocalPort int
	RemoteHost          string
	RemotePort          int
}

// TunnelState represents the current state of a tunnel.
type TunnelState struct {
	IsConnected    bool
	TunnelPort     int
	ForwardingPort int
	ErrorMessage   string
}

// SshKeyInfo holds information about a parsed SSH key.
type SshKeyInfo struct {
	Format        string
	Bits          int
	Fingerprint   string
	PublicKey     string
	Comment       string
	HasPassphrase bool
}

// KeyPairResult holds a generated key pair (gomobile allows max 2 return values).
type KeyPairResult struct {
	PrivateKey string
	PublicKey  string
}

// QuickTunnelResult holds the result of QuickTunnel.
type QuickTunnelResult struct {
	Client *SshClient
	Port   int
}

// Error codes, re-exported from sshclient.
const (
	ErrUnknown          = sshclient.ErrUnknown
	ErrConnectionFailed = sshclient.ErrConnectionFailed
	ErrAuthFailed       = sshclient.ErrAuthFailed
	ErrKeyInvalid       = sshclient.ErrKeyInvalid
	ErrTunnelFailed     = sshclient.ErrTunnelFailed
	ErrTimeout          = sshclient.ErrTimeout
	ErrNotConnected     = sshclient.ErrNotConnected
	ErrAlreadyConnected = sshclient.ErrAlreadyConnected
	ErrInvalidConfig    = sshclient.ErrInvalidConfig
)

func (c *SshConfig) Validate() error    { return (*sshclient.Config)(c).Validate() }
func (c *TunnelConfig) Validate() error { return (*sshclient.TunnelConfig)(c).Validate() }

func toTunnelState(s *sshclient.TunnelState) *TunnelState {
	if s == nil {
		return nil
	}
	t := TunnelState(*s)
	return &t
}

func toKeyInfo(i *sshclient.KeyInfo) *SshKeyInfo {
	if i == nil {
		return nil
	}
	k := SshKeyInfo(*i)
	return &k
}

func (i *SshKeyInfo) String() string { return (*sshclient.KeyInfo)(i).String() }
