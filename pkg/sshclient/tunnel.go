package sshclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// SocksServer provides a SOCKS5 proxy server that forwards through SSH
type SocksServer struct {
	client   *Client
	listener net.Listener
	port     int
	running  bool
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// NewSocksServer creates a new SOCKS5 proxy server
func NewSocksServer(client *Client) *SocksServer {
	return &SocksServer{
		client: client,
		stopCh: make(chan struct{}),
	}
}

// Start starts the SOCKS5 server on the specified port (0 for auto-assign)
func (s *SocksServer) Start(port int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return 0, newError(ErrTunnelFailed, "SOCKS server already running")
	}

	if !s.client.IsConnected() {
		return 0, newError(ErrNotConnected, "SSH client not connected")
	}

	addr := "127.0.0.1:0"
	if port > 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, newErrorf(ErrTunnelFailed, "failed to listen: %v", err)
	}

	s.listener = ln
	s.port = ln.Addr().(*net.TCPAddr).Port
	s.running = true
	s.stopCh = make(chan struct{})

	go s.acceptLoop()

	return s.port, nil
}

// Stop stops the SOCKS5 server
func (s *SocksServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.running = false
}

// IsRunning returns whether the server is running
func (s *SocksServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetPort returns the port the server is listening on
func (s *SocksServer) GetPort() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.port
}

// acceptLoop accepts incoming SOCKS5 connections
func (s *SocksServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SOCKS5 client connection
func (s *SocksServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set deadlines
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Check SOCKS version
	if n < 2 || buf[0] != 0x05 {
		return
	}

	// No authentication required
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 10 {
		return
	}

	// Verify SOCKS5 and CONNECT command
	if buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var targetAddr string
	var targetPort int

	// Parse address based on address type
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = int(buf[8])<<8 | int(buf[9])
	case 0x03: // Domain name
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			int(buf[4])<<8|int(buf[5]),
			int(buf[6])<<8|int(buf[7]),
			int(buf[8])<<8|int(buf[9]),
			int(buf[10])<<8|int(buf[11]),
			int(buf[12])<<8|int(buf[13]),
			int(buf[14])<<8|int(buf[15]),
			int(buf[16])<<8|int(buf[17]),
			int(buf[18])<<8|int(buf[19]),
		)
		targetPort = int(buf[20])<<8 | int(buf[21])
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	// Connect through SSH
	remoteAddr := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	remoteConn, err := s.client.Dial("tcp", remoteAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
		return
	}
	defer remoteConn.Close()

	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Clear deadline for data transfer
	conn.SetDeadline(time.Time{})

	// Pipe data bidirectionally
	pipeConnections(conn, remoteConn)
}

// DynamicTunnel manages dynamic port forwarding (SOCKS-like)
type DynamicTunnel struct {
	client   *Client
	listener net.Listener
	port     int
	running  bool
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewDynamicTunnel creates a new dynamic tunnel
func NewDynamicTunnel(client *Client) *DynamicTunnel {
	return &DynamicTunnel{
		client: client,
	}
}

// Start starts the dynamic tunnel on the specified port (0 for auto-assign)
func (t *DynamicTunnel) Start(port int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return 0, newError(ErrTunnelFailed, "tunnel already running")
	}

	if !t.client.IsConnected() {
		return 0, newError(ErrNotConnected, "SSH client not connected")
	}

	addr := "127.0.0.1:0"
	if port > 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, newErrorf(ErrTunnelFailed, "failed to listen: %v", err)
	}

	t.listener = ln
	t.port = ln.Addr().(*net.TCPAddr).Port
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.running = true

	go t.acceptLoop()

	return t.port, nil
}

// Stop stops the dynamic tunnel
func (t *DynamicTunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	t.cancel()
	if t.listener != nil {
		t.listener.Close()
	}
	t.running = false
}

// IsRunning returns whether the tunnel is running
func (t *DynamicTunnel) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}

// GetPort returns the port the tunnel is listening on
func (t *DynamicTunnel) GetPort() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.port
}

// acceptLoop accepts incoming connections
func (t *DynamicTunnel) acceptLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			conn, err := t.listener.Accept()
			if err != nil {
				if t.ctx.Err() != nil {
					return
				}
				continue
			}

			go t.handleConnection(conn)
		}
	}
}

// handleConnection handles a single connection
// Reads target address from first bytes and forwards through SSH
func (t *DynamicTunnel) handleConnection(conn net.Conn) {
	defer conn.Close()

	// This is a simple HTTP CONNECT-style handler
	// It expects the client to send the target address first

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Try to parse as HTTP CONNECT
	line := string(buf[:n])
	var targetHost string
	var targetPort int

	if len(line) > 7 && line[:7] == "CONNECT" {
		// HTTP CONNECT format: CONNECT host:port HTTP/1.x
		parts := strings.Split(line, " ")
		if len(parts) >= 2 {
			addrParts := strings.Split(parts[1], ":")
			targetHost = addrParts[0]
			if len(addrParts) > 1 {
				fmt.Sscanf(addrParts[1], "%d", &targetPort)
			} else {
				targetPort = 80
			}
		}

		// Send HTTP 200 response
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		// Assume it's a raw connection - need more sophisticated handling
		// For now, just forward to a default target or close
		return
	}

	// Connect through SSH
	remoteAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	remoteConn, err := t.client.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	// Clear deadline
	conn.SetDeadline(time.Time{})

	// Create pipe
	done := make(chan struct{}, 2)

	// Copy from client to remote
	go func() {
		io.Copy(remoteConn, conn)
		done <- struct{}{}
	}()

	// Copy from remote to client
	go func() {
		io.Copy(conn, remoteConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done

	// Close connections
	conn.Close()
	remoteConn.Close()

	// Wait for other direction
	<-done
}

// RemoteForwarding represents a remote port forwarding (reverse tunnel)
type RemoteForwarding struct {
	client     *Client
	remoteAddr string
	localAddr  string
	listener   net.Listener
	running    bool
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewRemoteForwarding creates a new remote forwarding
func NewRemoteForwarding(client *Client) *RemoteForwarding {
	return &RemoteForwarding{
		client: client,
	}
}

// Start starts remote port forwarding
// Requests the SSH server to listen on remoteAddr and forward to localAddr
func (r *RemoteForwarding) Start(remotePort int, localAddr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return newError(ErrTunnelFailed, "forwarding already running")
	}

	if !r.client.IsConnected() {
		return newError(ErrNotConnected, "SSH client not connected")
	}

	// Request remote port forwarding from SSH server
	r.remoteAddr = fmt.Sprintf("0.0.0.0:%d", remotePort)
	r.localAddr = localAddr

	ln, err := r.client.client.Listen("tcp", r.remoteAddr)
	if err != nil {
		return newErrorf(ErrTunnelFailed, "failed to request remote forwarding: %v", err)
	}

	r.listener = ln
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.running = true

	go r.acceptLoop()

	return nil
}

// Stop stops the remote forwarding
func (r *RemoteForwarding) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}

	r.cancel()
	if r.listener != nil {
		r.listener.Close()
	}
	r.running = false
}

// IsRunning returns whether the forwarding is running
func (r *RemoteForwarding) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

// GetRemoteAddr returns the remote address being forwarded
func (r *RemoteForwarding) GetRemoteAddr() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.remoteAddr
}

// acceptLoop accepts connections from the remote side
func (r *RemoteForwarding) acceptLoop() {
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
			conn, err := r.listener.Accept()
			if err != nil {
				if r.ctx.Err() != nil {
					return
				}
				continue
			}

			go r.handleConnection(conn)
		}
	}
}

// handleConnection handles a single remote forwarding connection
func (r *RemoteForwarding) handleConnection(remoteConn net.Conn) {
	defer remoteConn.Close()

	// Connect to local address
	localConn, err := net.Dial("tcp", r.localAddr)
	if err != nil {
		return
	}
	defer localConn.Close()

	// Pipe data bidirectionally
	pipeConnections(remoteConn, localConn)
}
