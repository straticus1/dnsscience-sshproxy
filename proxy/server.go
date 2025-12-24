package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hostscience/sshproxy/config"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	config      *config.Config
	sshConfig   *ssh.ServerConfig
	connCount   atomic.Int64
	totalConns  atomic.Int64
}

type connContext struct {
	user       *config.User
	targetHost string
	targetUser string
}

func NewServer(cfg *config.Config, hostKey ssh.Signer) *Server {
	s := &Server{config: cfg}

	s.sshConfig = &ssh.ServerConfig{
		PasswordCallback: s.passwordCallback,
		PublicKeyCallback: s.publicKeyCallback,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "SSH Proxy - Authorized access only\r\n"
		},
	}
	s.sshConfig.AddHostKey(hostKey)

	return s
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	loginID, targetHost, targetUser := parseUsername(conn.User())

	user := s.config.FindUser(loginID)
	if user == nil {
		log.Printf("[AUTH] Failed: unknown user %q from %s", loginID, conn.RemoteAddr())
		return nil, fmt.Errorf("unknown user")
	}

	if user.PasswordHash == "" {
		log.Printf("[AUTH] Failed: password auth disabled for %q", loginID)
		return nil, fmt.Errorf("password auth not enabled")
	}

	if !checkPassword(string(password), user.PasswordHash) {
		log.Printf("[AUTH] Failed: bad password for %q from %s", loginID, conn.RemoteAddr())
		return nil, fmt.Errorf("invalid password")
	}

	log.Printf("[AUTH] Success: %q via password from %s", loginID, conn.RemoteAddr())

	return &ssh.Permissions{
		Extensions: map[string]string{
			"login_id":    loginID,
			"target_host": targetHost,
			"target_user": targetUser,
		},
	}, nil
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	loginID, targetHost, targetUser := parseUsername(conn.User())

	user := s.config.FindUser(loginID)
	if user == nil {
		log.Printf("[AUTH] Failed: unknown user %q from %s", loginID, conn.RemoteAddr())
		return nil, fmt.Errorf("unknown user")
	}

	keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	for _, authorizedKey := range user.PublicKeys {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
		if err != nil {
			continue
		}
		if string(ssh.MarshalAuthorizedKey(parsed)) == string(ssh.MarshalAuthorizedKey(key)) {
			log.Printf("[AUTH] Success: %q via pubkey from %s", loginID, conn.RemoteAddr())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"login_id":    loginID,
					"target_host": targetHost,
					"target_user": targetUser,
					"pubkey":      keyStr,
				},
			}, nil
		}
	}

	log.Printf("[AUTH] Failed: no matching key for %q from %s", loginID, conn.RemoteAddr())
	return nil, fmt.Errorf("invalid key")
}

func parseUsername(username string) (loginID, targetHost, targetUser string) {
	// Formats supported:
	// 1. "targethost+user@proxy" -> target=targethost, login=user
	// 2. "user/targethost@proxy" -> target=targethost, login=user
	// 3. "user%targethost@proxy" -> target=targethost, login=user
	// 4. "user" -> login=user, target="" (will use default)

	if idx := strings.Index(username, "+"); idx > 0 {
		targetHost = username[:idx]
		loginID = username[idx+1:]
	} else if idx := strings.Index(username, "/"); idx > 0 {
		loginID = username[:idx]
		targetHost = username[idx+1:]
	} else if idx := strings.Index(username, "%"); idx > 0 {
		loginID = username[:idx]
		targetHost = username[idx+1:]
	} else {
		loginID = username
	}

	// Check if target has embedded user (user@host format in target)
	if idx := strings.LastIndex(targetHost, "@"); idx > 0 {
		targetUser = targetHost[:idx]
		targetHost = targetHost[idx+1:]
	}

	return loginID, targetHost, targetUser
}

func (s *Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	log.Printf("[SERVER] Listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[SERVER] Accept error: %v", err)
			continue
		}

		s.connCount.Add(1)
		s.totalConns.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(netConn net.Conn) {
	defer func() {
		s.connCount.Add(-1)
		netConn.Close()
	}()

	remoteAddr := netConn.RemoteAddr().String()
	log.Printf("[CONN] New connection from %s (active: %d, total: %d)",
		remoteAddr, s.connCount.Load(), s.totalConns.Load())

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		log.Printf("[CONN] SSH handshake failed from %s: %v", remoteAddr, err)
		return
	}
	defer sshConn.Close()

	loginID := sshConn.Permissions.Extensions["login_id"]
	targetHost := sshConn.Permissions.Extensions["target_host"]
	targetUser := sshConn.Permissions.Extensions["target_user"]

	user := s.config.FindUser(loginID)
	if user == nil {
		log.Printf("[CONN] User %q not found after auth?", loginID)
		return
	}

	// Resolve target host
	if targetHost == "" {
		targetHost = user.DefaultHost
	}
	if targetHost == "" {
		log.Printf("[CONN] No target host for %q", loginID)
		return
	}

	// ACL check
	if !user.CanAccessHost(targetHost) {
		log.Printf("[ACL] Denied: %q cannot access %q", loginID, targetHost)
		return
	}

	log.Printf("[PROXY] %q -> %s (user: %s)", loginID, targetHost, targetUser)

	// Handle global requests (keepalive, etc)
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChan := range chans {
		go s.handleChannel(newChan, targetHost, targetUser, loginID)
	}
}

func (s *Server) handleChannel(newChan ssh.NewChannel, targetHost, targetUser, loginID string) {
	if newChan.ChannelType() != "session" {
		newChan.Reject(ssh.UnknownChannelType, "only session channels supported")
		return
	}

	channel, requests, err := newChan.Accept()
	if err != nil {
		log.Printf("[CHAN] Accept failed: %v", err)
		return
	}
	defer channel.Close()

	// Connect to backend
	targetAddr := targetHost
	if !strings.Contains(targetAddr, ":") {
		targetAddr = targetAddr + ":22"
	}

	backendConn, err := net.DialTimeout("tcp", targetAddr, 10*1e9)
	if err != nil {
		log.Printf("[PROXY] Failed to connect to %s: %v", targetAddr, err)
		channel.Write([]byte(fmt.Sprintf("Failed to connect to backend: %v\r\n", err)))
		return
	}
	defer backendConn.Close()

	log.Printf("[PROXY] Connected %q to %s", loginID, targetAddr)

	// Handle session requests (pty-req, shell, exec, etc)
	go func() {
		for req := range requests {
			// For TCP tunnel mode, we just acknowledge requests
			// The actual terminal handling happens on the backend
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, channel)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(channel, backendConn)
		channel.CloseWrite()
	}()

	wg.Wait()
	log.Printf("[PROXY] Session ended for %q -> %s", loginID, targetHost)
}

func (s *Server) Stats() (active, total int64) {
	return s.connCount.Load(), s.totalConns.Load()
}
