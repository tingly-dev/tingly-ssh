package mobile

import "github.com/tingly-dev/tingly-ssh/pkg/sshclient"

// ConnectionListener receives connection events. Implemented on the Kotlin/Swift side.
type ConnectionListener interface {
	// OnConnectionLost is called when the SSH connection dies on its own.
	OnConnectionLost(reason string)
}

// SshClient is a thin gomobile facade over sshclient.Client.
type SshClient struct {
	c *sshclient.Client
}

func NewSshClient() *SshClient { return &SshClient{c: sshclient.NewClient()} }

func (s *SshClient) Connect(config *SshConfig) error {
	return s.c.Connect((*sshclient.Config)(config))
}

func (s *SshClient) VerifyConnection(config *SshConfig) error {
	return s.c.VerifyConnection((*sshclient.Config)(config))
}

func (s *SshClient) SetConnectionListener(l ConnectionListener) {
	if l == nil {
		s.c.SetConnectionListener(nil)
		return
	}
	s.c.SetConnectionListener(l)
}

func (s *SshClient) Disconnect()              { s.c.Disconnect() }
func (s *SshClient) IsConnected() bool        { return s.c.IsConnected() }
func (s *SshClient) GetConnectionTime() int64 { return s.c.GetConnectionTime() }
func (s *SshClient) CloseTunnel()             { s.c.CloseTunnel() }
func (s *SshClient) GetTunnelPort() int       { return s.c.GetTunnelPort() }
func (s *SshClient) GetForwardingPort() int   { return s.c.GetForwardingPort() }
func (s *SshClient) GetServerVersion() string { return s.c.GetServerVersion() }
func (s *SshClient) GetRemoteAddr() string    { return s.c.GetRemoteAddr() }
func (s *SshClient) GetLocalAddr() string     { return s.c.GetLocalAddr() }
func (s *SshClient) SendKeepalive() error     { return s.c.SendKeepalive() }

func (s *SshClient) EstablishTunnel(config *TunnelConfig) (*TunnelState, error) {
	st, err := s.c.EstablishTunnel((*sshclient.TunnelConfig)(config))
	if err != nil {
		return nil, err
	}
	return toTunnelState(st), nil
}

func (s *SshClient) GetTunnelState() *TunnelState { return toTunnelState(s.c.GetTunnelState()) }

func (s *SshClient) ExecuteCommand(command string) (string, error) {
	return s.c.ExecuteCommand(command)
}
