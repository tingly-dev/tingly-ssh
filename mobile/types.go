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
	// Jump is an optional jump host this connection is opened through (ProxyJump).
	Jump *SshConfig
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

// KeyInspection describes a private key without needing its passphrase.
type KeyInspection struct {
	Container   string
	KeyType     string
	Bits        int
	Encrypted   bool
	Fingerprint string
	Unsupported string
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
	ErrCancelled        = sshclient.ErrCancelled
)

func (c *SshConfig) Validate() error    { return toConfig(c).Validate() }
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

// toConfig converts including the jump chain. Hops past sshclient.MaxHops are
// dropped from the copy, so a cyclic chain still ends and is then rejected by
// sshclient's own hop-count validation.
func toConfig(c *SshConfig) *sshclient.Config {
	if c == nil {
		return nil
	}
	head := &sshclient.Config{}
	cur := head
	for src, n := c, 0; src != nil && n <= sshclient.MaxHops; src, n = src.Jump, n+1 {
		cur.Host, cur.Port, cur.Username = src.Host, src.Port, src.Username
		cur.PrivateKey, cur.Passphrase, cur.KnownHosts = src.PrivateKey, src.Passphrase, src.KnownHosts
		if src.Jump != nil && n < sshclient.MaxHops {
			cur.Jump = &sshclient.Config{}
			cur = cur.Jump
		}
	}
	return head
}
