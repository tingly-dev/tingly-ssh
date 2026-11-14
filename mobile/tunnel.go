package mobile

import "github.com/tingly-dev/tingly-ssh/pkg/sshclient"

// SocksServer is a SOCKS5 proxy over an SshClient.
type SocksServer struct{ s *sshclient.SocksServer }

func NewSocksServer(client *SshClient) *SocksServer {
	return &SocksServer{s: sshclient.NewSocksServer(client.c)}
}
func (s *SocksServer) Start(port int) (int, error) { return s.s.Start(port) }
func (s *SocksServer) Stop()                       { s.s.Stop() }
func (s *SocksServer) IsRunning() bool             { return s.s.IsRunning() }
func (s *SocksServer) GetPort() int                { return s.s.GetPort() }

// DynamicTunnel is dynamic port forwarding over an SshClient.
type DynamicTunnel struct{ t *sshclient.DynamicTunnel }

func NewDynamicTunnel(client *SshClient) *DynamicTunnel {
	return &DynamicTunnel{t: sshclient.NewDynamicTunnel(client.c)}
}
func (t *DynamicTunnel) Start(port int) (int, error) { return t.t.Start(port) }
func (t *DynamicTunnel) Stop()                       { t.t.Stop() }
func (t *DynamicTunnel) IsRunning() bool             { return t.t.IsRunning() }
func (t *DynamicTunnel) GetPort() int                { return t.t.GetPort() }

// RemoteForwarding is remote (reverse) port forwarding over an SshClient.
type RemoteForwarding struct{ r *sshclient.RemoteForwarding }

func NewRemoteForwarding(client *SshClient) *RemoteForwarding {
	return &RemoteForwarding{r: sshclient.NewRemoteForwarding(client.c)}
}
func (r *RemoteForwarding) Start(remotePort int, localAddr string) error {
	return r.r.Start(remotePort, localAddr)
}
func (r *RemoteForwarding) Stop()                 { r.r.Stop() }
func (r *RemoteForwarding) IsRunning() bool       { return r.r.IsRunning() }
func (r *RemoteForwarding) GetRemoteAddr() string { return r.r.GetRemoteAddr() }
