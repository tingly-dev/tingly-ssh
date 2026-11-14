package sshclient

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client is the main SSH client providing connection and tunneling functionality
// Thread-safe for concurrent use
type Client struct {
	mu sync.RWMutex

	// Connection state
	client      *ssh.Client
	jumps       []*ssh.Client // hosts client is tunnelled through, outermost first
	config      *Config
	connected   bool
	connectTime time.Time

	// Tunnel state
	tunnelListener     net.Listener
	forwardingListener net.Listener
	tunnelConfig       *TunnelConfig
	tunnelPort         int
	forwardingPort     int

	// Callbacks for status updates (optional)
	onDisconnected func()
	onTunnelClosed func()

	// Notified when the connection drops unexpectedly (not on Disconnect)
	listener ConnectionListener
}

// ConnectionListener receives connection events. Implemented on the Kotlin/Swift side.
type ConnectionListener interface {
	// OnConnectionLost is called when the SSH connection dies on its own
	// (keepalive failure, server closed it, network gone). Tunnels are already closed.
	OnConnectionLost(reason string)
}

const (
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 10 * time.Second
)

// NewClient creates a new SSH client instance
func NewClient() *Client {
	return &Client{}
}

// Connect establishes an SSH connection with the given configuration, going
// through config.Jump first when set.
// Returns error if connection fails or already connected
func (c *Client) Connect(config *Config) error {
	if config == nil {
		return newError(ErrInvalidConfig, "config is nil")
	}

	if err := config.Validate(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return newError(ErrAlreadyConnected, "already connected, disconnect first")
	}

	hops := config.chain()
	var jumps []*ssh.Client
	var via *ssh.Client
	for i, hop := range hops {
		client, err := dialHop(hop, via, hopLabel(i, len(hops)))
		if err != nil {
			closeClients(jumps)
			return err
		}
		if i < len(hops)-1 {
			jumps = append(jumps, client)
		}
		via = client
	}
	client := via

	c.client = client
	c.jumps = jumps
	c.config = config
	c.connected = true
	c.connectTime = time.Now()

	log.Printf("tinglyssh: connected %s@%s (server %s, %d jump)", config.Username,
		net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), client.ServerVersion(), len(jumps))

	go c.monitor(client, jumps)

	return nil
}

// dialHop opens one SSH connection: directly, or through via when it is set.
// label prefixes errors so a failure names its hop.
func dialHop(config *Config, via *ssh.Client, label string) (*ssh.Client, error) {
	// Parse private key
	var signer ssh.Signer
	var err error

	if config.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(config.PrivateKey), []byte(config.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(config.PrivateKey))
	}

	if err != nil {
		return nil, wrapError(ErrKeyInvalid, fmt.Errorf("%sfailed to parse private key: %w", label, err))
	}

	// Build SSH client config
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Timeout:         30 * time.Second,
		ClientVersion:   "SSH-2.0-TinglySSH_1.0",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For simplicity, like JSch's StrictHostKeyChecking=no
	}

	// If known hosts provided, use host key verification
	if config.KnownHosts != "" {
		hostKeyCallback, err := parseKnownHosts(config.Host, config.KnownHosts)
		if err != nil {
			// Log warning but continue with insecure mode
			// In production, you might want to fail here
		} else {
			sshConfig.HostKeyCallback = hostKeyCallback
		}
	}

	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	if via == nil {
		client, err := ssh.Dial("tcp", addr, sshConfig)
		if err != nil {
			return nil, wrapError(ErrConnectionFailed, fmt.Errorf("%sfailed to connect to %s: %w", label, addr, err))
		}
		return client, nil
	}

	// Through a jump host: open a direct-tcpip channel and run the SSH handshake over it.
	// Channel conns have no deadlines, so the timeout is enforced around the whole attempt.
	type result struct {
		client *ssh.Client
		err    error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := via.Dial("tcp", addr)
		if err != nil {
			done <- result{err: err}
			return
		}
		cc, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
		if err != nil {
			conn.Close()
			done <- result{err: err}
			return
		}
		done <- result{client: ssh.NewClient(cc, chans, reqs)}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, wrapError(ErrConnectionFailed, fmt.Errorf("%sfailed to connect to %s via jump host: %w", label, addr, r.err))
		}
		return r.client, nil
	case <-time.After(sshConfig.Timeout):
		go func() {
			if r := <-done; r.client != nil {
				r.client.Close()
			}
		}()
		return nil, newErrorf(ErrTimeout, "%sconnect to %s via jump host timed out after %s", label, addr, sshConfig.Timeout)
	}
}

// closeClients closes clients innermost-last-opened first
func closeClients(clients []*ssh.Client) {
	for i := len(clients) - 1; i >= 0; i-- {
		clients[i].Close()
	}
}

// SetConnectionListener registers a listener for unexpected connection loss (nil to clear)
func (c *Client) SetConnectionListener(l ConnectionListener) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listener = l
}

// monitor sends keepalives and watches for the connection to end.
// jumps are the hosts client is tunnelled through: any of them dying ends the
// connection, and each is kept alive on its own.
// If client is still the active connection when it ends, state is reset
// and the listener is notified.
func (c *Client) monitor(client *ssh.Client, jumps []*ssh.Client) {
	closed := make(chan string, 1)
	jumpClosed := make(chan string, len(jumps)+1)
	go func() {
		reason := "connection closed"
		if err := client.Wait(); err != nil {
			reason = err.Error()
		}
		closed <- reason
	}()
	for i, j := range jumps {
		go func(i int, j *ssh.Client) {
			reason := fmt.Sprintf("jump host %d connection closed", i+1)
			if err := j.Wait(); err != nil {
				reason += ": " + err.Error()
			}
			jumpClosed <- reason
		}(i, j)
	}

	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	reason := "connection closed"
	for running := true; running; {
		select {
		case reason = <-closed:
			// A dead jump host also kills the connection through it; prefer naming the jump
			if len(jumps) > 0 {
				select {
				case reason = <-jumpClosed:
				case <-time.After(200 * time.Millisecond):
				}
			}
			running = false
		case reason = <-jumpClosed:
			running = false
		case <-ticker.C:
			for i, j := range jumps {
				if err := sendKeepalive(j); err != nil {
					reason = fmt.Sprintf("jump host %d keepalive failed: %s", i+1, err)
					running = false
					break
				}
			}
			if running {
				if err := sendKeepalive(client); err != nil {
					reason = "keepalive failed: " + err.Error()
					running = false
				}
			}
		}
	}
	client.Close()
	closeClients(jumps)

	c.mu.Lock()
	if c.client != client {
		// Already replaced or disconnected on purpose
		c.mu.Unlock()
		return
	}
	c.closeTunnelsLocked()
	c.client = nil
	c.jumps = nil
	c.connected = false
	c.config = nil
	listener := c.listener
	c.mu.Unlock()

	log.Printf("tinglyssh: connection lost: %s", reason)

	if listener != nil {
		listener.OnConnectionLost(reason)
	}
}

// sendKeepalive sends an OpenSSH keepalive request and waits for the reply
func sendKeepalive(client *ssh.Client) error {
	errc := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-time.After(keepaliveTimeout):
		return fmt.Errorf("no reply in %s", keepaliveTimeout)
	}
}

// VerifyConnection tests the connection without keeping it open
// Useful for validating credentials before establishing a persistent connection.
// Uses a throwaway client so an active connection on c is left untouched.
func (c *Client) VerifyConnection(config *Config) error {
	probe := NewClient()
	if err := probe.Connect(config); err != nil {
		return err
	}
	probe.Disconnect()
	return nil
}

// Disconnect closes the SSH connection and all tunnels
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close tunnels first
	c.closeTunnelsLocked()

	// Close SSH connection
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	closeClients(c.jumps)
	c.jumps = nil

	c.connected = false
	c.config = nil

	// Notify callback
	if c.onDisconnected != nil {
		go c.onDisconnected()
	}
}

// IsConnected returns whether the client is currently connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.client != nil
}

// GetConnectionTime returns when the connection was established
func (c *Client) GetConnectionTime() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.connected {
		return c.connectTime.Unix()
	}
	return 0
}

// EstablishTunnel creates port forwarding tunnels
// Both SOCKS-like tunnel and direct TCP forwarding can be established
func (c *Client) EstablishTunnel(config *TunnelConfig) (*TunnelState, error) {
	if config == nil {
		return nil, newError(ErrInvalidConfig, "tunnel config is nil")
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.client == nil {
		return nil, newError(ErrNotConnected, "not connected to SSH server")
	}

	// Close existing tunnels
	c.closeTunnelsLocked()

	state := &TunnelState{IsConnected: true}

	// Establish direct TCP forwarding (local -> remote)
	if config.ForwardingLocalPort > 0 {
		port, err := c.setupForwardingLocked(config)
		if err != nil {
			return nil, err
		}
		state.ForwardingPort = port
		c.forwardingPort = port
	} else {
		// Auto-assign port
		port, err := c.setupForwardingLocked(config)
		if err != nil {
			return nil, err
		}
		state.ForwardingPort = port
		c.forwardingPort = port
	}

	// Establish tunnel port (for SOCKS/proxy use)
	if config.TunnelLocalPort > 0 {
		// Use specified port
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", config.TunnelLocalPort))
		if err != nil {
			c.closeTunnelsLocked()
			return nil, newErrorf(ErrTunnelFailed, "failed to listen on port %d: %v", config.TunnelLocalPort, err)
		}
		c.tunnelListener = ln
		c.tunnelPort = config.TunnelLocalPort
		state.TunnelPort = config.TunnelLocalPort

		// Start accepting connections
		go acceptAndForward(ln, c.client, config)
	} else {
		// Auto-assign port
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			c.closeTunnelsLocked()
			return nil, wrapError(ErrTunnelFailed, err)
		}
		c.tunnelListener = ln
		c.tunnelPort = ln.Addr().(*net.TCPAddr).Port
		state.TunnelPort = c.tunnelPort

		// Start accepting connections
		go acceptAndForward(ln, c.client, config)
	}

	c.tunnelConfig = config

	return state, nil
}

// setupForwardingLocked sets up direct TCP port forwarding
func (c *Client) setupForwardingLocked(config *TunnelConfig) (int, error) {
	localAddr := "127.0.0.1:0"
	if config.ForwardingLocalPort > 0 {
		localAddr = fmt.Sprintf("127.0.0.1:%d", config.ForwardingLocalPort)
	}

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return 0, newErrorf(ErrTunnelFailed, "failed to listen: %v", err)
	}

	c.forwardingListener = ln
	port := ln.Addr().(*net.TCPAddr).Port

	// Start accepting connections
	go acceptAndForward(ln, c.client, config)

	return port, nil
}

// remoteDialTimeout bounds how long a forwarded connection waits for the SSH server
// to open the remote side (e.g. when the SSH connection silently died)
const remoteDialTimeout = 15 * time.Second

// acceptAndForward accepts local connections and forwards each to the remote target.
// The ssh.Client is captured at setup so a concurrent Disconnect (which nils c.client)
// can't cause a nil dereference; a closed client just makes Dial fail.
func acceptAndForward(ln net.Listener, client *ssh.Client, config *TunnelConfig) {
	remoteAddr := net.JoinHostPort(config.RemoteHost, fmt.Sprint(config.RemotePort))
	for {
		localConn, err := ln.Accept()
		if err != nil {
			// Listener closed
			return
		}

		id := forwardSeq.Add(1)
		go func() {
			defer localConn.Close()

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), remoteDialTimeout)
			remoteConn, err := client.DialContext(ctx, "tcp", remoteAddr)
			cancel()
			if err != nil {
				log.Printf("tinglyssh: fwd#%d open %s failed after %s: %v", id, remoteAddr, time.Since(start).Round(time.Millisecond), err)
				return
			}
			defer remoteConn.Close()
			log.Printf("tinglyssh: fwd#%d open %s ok in %s", id, remoteAddr, time.Since(start).Round(time.Millisecond))

			// Pipe data bidirectionally
			sent, received := pipeConnections(localConn, remoteConn)
			log.Printf("tinglyssh: fwd#%d closed after %s, sent %dB, received %dB",
				id, time.Since(start).Round(time.Millisecond), sent, received)
		}()
	}
}

// forwardSeq numbers forwarded connections in logs
var forwardSeq atomic.Int64

// CloseTunnel closes the tunnel but keeps the SSH connection
func (c *Client) CloseTunnel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeTunnelsLocked()

	if c.onTunnelClosed != nil {
		go c.onTunnelClosed()
	}
}

// closeTunnelsLocked closes all tunnel listeners (must hold lock)
func (c *Client) closeTunnelsLocked() {
	if c.tunnelListener != nil {
		c.tunnelListener.Close()
		c.tunnelListener = nil
	}
	if c.forwardingListener != nil {
		c.forwardingListener.Close()
		c.forwardingListener = nil
	}
	c.tunnelPort = 0
	c.forwardingPort = 0
	c.tunnelConfig = nil
}

// GetTunnelState returns the current tunnel state
func (c *Client) GetTunnelState() *TunnelState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return &TunnelState{
		IsConnected:    c.connected,
		TunnelPort:     c.tunnelPort,
		ForwardingPort: c.forwardingPort,
	}
}

// GetTunnelPort returns the assigned tunnel port
func (c *Client) GetTunnelPort() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tunnelPort
}

// GetForwardingPort returns the assigned forwarding port
func (c *Client) GetForwardingPort() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.forwardingPort
}

// SetOnDisconnected sets a callback for when connection is lost
func (c *Client) SetOnDisconnected(callback func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDisconnected = callback
}

// SetOnTunnelClosed sets a callback for when tunnel is closed
func (c *Client) SetOnTunnelClosed(callback func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onTunnelClosed = callback
}

// ExecuteCommand executes a command on the remote server
// Returns the output as a string
func (c *Client) ExecuteCommand(command string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.client == nil {
		return "", newError(ErrNotConnected, "not connected to SSH server")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", wrapError(ErrConnectionFailed, err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), wrapError(ErrConnectionFailed, err)
	}

	return string(output), nil
}

// ExecuteCommandWithContext executes a command with timeout context
func (c *Client) ExecuteCommandWithContext(ctx context.Context, command string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.client == nil {
		return "", newError(ErrNotConnected, "not connected to SSH server")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", wrapError(ErrConnectionFailed, err)
	}
	defer session.Close()

	// Create a channel to receive the result
	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)

	go func() {
		output, err := session.CombinedOutput(command)
		resultChan <- result{string(output), err}
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return "", newError(ErrTimeout, "command timed out")
	case r := <-resultChan:
		if r.err != nil {
			return r.output, wrapError(ErrConnectionFailed, r.err)
		}
		return r.output, nil
	}
}

// Dial creates a direct TCP connection through the SSH tunnel
// Useful for making arbitrary TCP connections through the SSH server
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.client == nil {
		return nil, newError(ErrNotConnected, "not connected to SSH server")
	}

	conn, err := c.client.Dial(network, addr)
	if err != nil {
		return nil, wrapError(ErrConnectionFailed, err)
	}

	return conn, nil
}

// parseKnownHosts parses known_hosts content and returns a host key callback
// Note: For now, this is not fully implemented. The default behavior is InsecureIgnoreHostKey
// similar to JSch's StrictHostKeyChecking=no
func parseKnownHosts(host, knownHosts string) (ssh.HostKeyCallback, error) {
	// TODO: Implement proper known_hosts parsing
	// For now, return insecure callback to match JSch behavior
	return ssh.InsecureIgnoreHostKey(), nil
}

// pipeConnections pipes data between two connections bidirectionally.
// Returns once both directions are done; when either side ends, both
// connections are closed to unblock the other direction.
// Returns bytes copied a->b and b->a.
func pipeConnections(a, b net.Conn) (aToB, bToA int64) {
	// Each direction sends exactly once; the channel is never closed,
	// so whichever side finishes last can't send on a closed channel.
	done := make(chan struct{}, 2)

	go func() {
		bToA = copyData(a, b)
		done <- struct{}{}
	}()

	go func() {
		aToB = copyData(b, a)
		done <- struct{}{}
	}()

	// Wait for one direction to complete
	<-done

	// Close both connections to unblock the other direction
	a.Close()
	b.Close()

	// Wait for the other direction
	<-done
	return aToB, bToA
}

// copyData copies data from src to dst, returning the number of bytes written
func copyData(dst, src net.Conn) (total int64) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w, err2 := dst.Write(buf[:n])
			total += int64(w)
			if err2 != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

// GetServerVersion returns the SSH server version string
func (c *Client) GetServerVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client != nil {
		return string(c.client.ServerVersion())
	}
	return ""
}

// GetRemoteAddr returns the remote address of the SSH connection
func (c *Client) GetRemoteAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client != nil && c.client.Conn != nil {
		return c.client.Conn.RemoteAddr().String()
	}
	return ""
}

// GetLocalAddr returns the local address of the SSH connection
func (c *Client) GetLocalAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client != nil && c.client.Conn != nil {
		return c.client.Conn.LocalAddr().String()
	}
	return ""
}

// SendKeepalive sends a keepalive message to keep the connection alive
func (c *Client) SendKeepalive() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.client == nil {
		return newError(ErrNotConnected, "not connected to SSH server")
	}

	// Send a global request as keepalive
	_, _, err := c.client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil && !strings.Contains(err.Error(), "unknown request") {
		// Some servers don't respond to keepalive, that's ok
		// But if connection is broken, we'll get a real error
		if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "broken") {
			c.connected = false
			return wrapError(ErrConnectionFailed, err)
		}
	}

	return nil
}
