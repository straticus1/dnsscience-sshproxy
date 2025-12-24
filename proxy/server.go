package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hostscience/sshproxy/config"
	"github.com/hostscience/sshproxy/store"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	config     *config.Config
	store      store.Store
	sshConfig  *ssh.ServerConfig
	connCount  atomic.Int64
	totalConns atomic.Int64

	// Session tracking for kill support
	sessions   map[string]*activeSession
	sessionsMu sync.RWMutex
}

type activeSession struct {
	id         string
	userID     string
	conn       ssh.Conn
	cancelFunc context.CancelFunc
}

type connContext struct {
	user       *config.User
	dbUser     *store.User
	targetHost string
	targetUser string
	keyID      string
}

func NewServer(cfg *config.Config, hostKey ssh.Signer, dataStore store.Store) *Server {
	s := &Server{
		config:   cfg,
		store:    dataStore,
		sessions: make(map[string]*activeSession),
	}

	s.sshConfig = &ssh.ServerConfig{
		PasswordCallback:  s.passwordCallback,
		PublicKeyCallback: s.publicKeyCallback,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "AfterDark SSH Proxy - Authorized access only\r\n"
		},
	}
	s.sshConfig.AddHostKey(hostKey)

	return s
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	loginID, targetHost, targetUser := parseUsername(conn.User())

	// Try database auth first
	if s.store != nil {
		dbUser, err := s.store.GetUser(context.Background(), loginID)
		if err == nil && dbUser.Enabled {
			// Database user exists but password auth not supported for DB users
			// They must use SSH keys
			log.Printf("[AUTH] DB user %q attempted password auth (not supported)", loginID)
			return nil, fmt.Errorf("password auth not supported, use SSH key")
		}
	}

	// Fall back to config file auth
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
			"auth_source": "config",
		},
	}, nil
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	loginID, targetHost, targetUser := parseUsername(conn.User())

	// Try database auth first
	if s.store != nil {
		dbUser, err := s.store.GetUser(context.Background(), loginID)
		if err == nil && dbUser.Enabled {
			// Check database keys
			keys, err := s.store.GetActiveKeys(context.Background(), loginID)
			if err == nil {
				for _, authorizedKey := range keys {
					parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
					if err != nil {
						continue
					}
					if keysEqual(parsed, key) {
						log.Printf("[AUTH] Success: %q via DB pubkey from %s", loginID, conn.RemoteAddr())

						// Get key ID for session tracking
						keyID := ""
						dbKeys, _ := s.store.ListKeys(context.Background(), loginID)
						for _, k := range dbKeys {
							if k.PublicKey == authorizedKey {
								keyID = k.ID
								break
							}
						}

						return &ssh.Permissions{
							Extensions: map[string]string{
								"login_id":    loginID,
								"target_host": targetHost,
								"target_user": targetUser,
								"auth_source": "database",
								"key_id":      keyID,
							},
						}, nil
					}
				}
			}
		}
	}

	// Fall back to config file auth
	user := s.config.FindUser(loginID)
	if user == nil {
		log.Printf("[AUTH] Failed: unknown user %q from %s", loginID, conn.RemoteAddr())
		return nil, fmt.Errorf("unknown user")
	}

	for _, authorizedKey := range user.PublicKeys {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
		if err != nil {
			continue
		}
		if keysEqual(parsed, key) {
			log.Printf("[AUTH] Success: %q via config pubkey from %s", loginID, conn.RemoteAddr())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"login_id":    loginID,
					"target_host": targetHost,
					"target_user": targetUser,
					"auth_source": "config",
				},
			}, nil
		}
	}

	log.Printf("[AUTH] Failed: no matching key for %q from %s", loginID, conn.RemoteAddr())
	return nil, fmt.Errorf("invalid key")
}

func keysEqual(a, b ssh.PublicKey) bool {
	return string(a.Marshal()) == string(b.Marshal())
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
	authSource := sshConn.Permissions.Extensions["auth_source"]
	keyID := sshConn.Permissions.Extensions["key_id"]

	var allowedHosts []string
	var defaultHost string

	if authSource == "database" && s.store != nil {
		dbUser, err := s.store.GetUser(context.Background(), loginID)
		if err != nil {
			log.Printf("[CONN] Failed to load DB user %q: %v", loginID, err)
			return
		}
		allowedHosts = dbUser.AllowedHosts
		defaultHost = dbUser.DefaultHost
	} else {
		user := s.config.FindUser(loginID)
		if user == nil {
			log.Printf("[CONN] User %q not found after auth?", loginID)
			return
		}
		allowedHosts = user.AllowedHosts
		defaultHost = user.DefaultHost
	}

	// Resolve target host
	if targetHost == "" {
		targetHost = defaultHost
	}
	if targetHost == "" {
		log.Printf("[CONN] No target host for %q", loginID)
		return
	}

	// ACL check
	if !canAccessHost(allowedHosts, targetHost) {
		log.Printf("[ACL] Denied: %q cannot access %q", loginID, targetHost)
		return
	}

	log.Printf("[PROXY] %q -> %s (user: %s, auth: %s)", loginID, targetHost, targetUser, authSource)

	// Track session in database
	var sessionID string
	if s.store != nil {
		sess := &store.Session{
			UserID:     loginID,
			RemoteAddr: remoteAddr,
			TargetHost: targetHost,
			KeyID:      keyID,
		}
		if err := s.store.CreateSession(context.Background(), sess); err != nil {
			log.Printf("[WARN] Failed to create session record: %v", err)
		} else {
			sessionID = sess.ID
		}
	}

	// Track active session for kill support
	ctx, cancel := context.WithCancel(context.Background())
	if sessionID != "" {
		s.sessionsMu.Lock()
		s.sessions[sessionID] = &activeSession{
			id:         sessionID,
			userID:     loginID,
			conn:       sshConn,
			cancelFunc: cancel,
		}
		s.sessionsMu.Unlock()
	}

	// Handle global requests (keepalive, etc)
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChan := range chans {
		go s.handleChannel(ctx, newChan, targetHost, targetUser, loginID)
	}

	// Cleanup
	if sessionID != "" {
		s.sessionsMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionsMu.Unlock()

		if s.store != nil {
			s.store.EndSession(context.Background(), sessionID)
		}
	}
	cancel()
}

func canAccessHost(allowedHosts []string, host string) bool {
	host = strings.ToLower(host)
	for _, allowed := range allowedHosts {
		if allowed == "*" {
			return true
		}
		if strings.ToLower(allowed) == host {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.ToLower(allowed[1:])
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleChannel(ctx context.Context, newChan ssh.NewChannel, targetHost, targetUser, loginID string) {
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

	backendConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
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
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()

	// Bidirectional copy with context cancellation support
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(backendConn, channel)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(channel, backendConn)
		channel.CloseWrite()
		done <- struct{}{}
	}()

	// Wait for either copy to finish or context cancellation
	select {
	case <-done:
	case <-ctx.Done():
		log.Printf("[PROXY] Session killed for %q", loginID)
	}

	log.Printf("[PROXY] Session ended for %q -> %s", loginID, targetHost)
}

func (s *Server) Stats() (active, total int64) {
	return s.connCount.Load(), s.totalConns.Load()
}

// KillSession terminates an active session by ID
func (s *Server) KillSession(sessionID string) bool {
	s.sessionsMu.RLock()
	sess, exists := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !exists {
		return false
	}

	sess.cancelFunc()
	sess.conn.Close()
	return true
}
