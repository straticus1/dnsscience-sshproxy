package store

import (
	"context"
	"time"
)

// Store defines the interface for user/key/session persistence
type Store interface {
	// User management
	GetUser(ctx context.Context, userID string) (*User, error)
	UpdateUser(ctx context.Context, userID string, update UserUpdate) (*User, error)
	SetUserAccess(ctx context.Context, userID string, enabled bool) error
	ListAllUsers(ctx context.Context) ([]User, error)
	EnsureUser(ctx context.Context, userID, email string) (*User, error)

	// SSH key management
	ListKeys(ctx context.Context, userID string) ([]SSHKey, error)
	AddKey(ctx context.Context, userID, name, publicKey string) (*SSHKey, error)
	RemoveKey(ctx context.Context, userID, keyID string) error
	SetKeyEnabled(ctx context.Context, userID, keyID string, enabled bool) error
	GetActiveKeys(ctx context.Context, userID string) ([]string, error)

	// Session management
	CreateSession(ctx context.Context, session *Session) error
	EndSession(ctx context.Context, sessionID string) error
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	ListAllSessions(ctx context.Context) ([]Session, error)
	KillSession(ctx context.Context, sessionID string) error
	KillUserSessions(ctx context.Context, userID string) (int, error)
	GetActiveSessionCount(ctx context.Context) (int, error)

	// Audit logging
	LogAudit(ctx context.Context, entry AuditEntry) error
	GetAuditLogs(ctx context.Context, userID string, limit int) ([]AuditEntry, error)

	// Stats
	GetStats(ctx context.Context) (*Stats, error)

	// Lifecycle
	Close() error
}

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Enabled      bool      `json:"enabled"`
	AllowedHosts []string  `json:"allowed_hosts"`
	DefaultHost  string    `json:"default_host"`
	KeyCount     int       `json:"key_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

type UserUpdate struct {
	AllowedHosts []string
	DefaultHost  string
}

type SSHKey struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	RemoteAddr string    `json:"remote_addr"`
	TargetHost string    `json:"target_host"`
	KeyID      string    `json:"key_id,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	Active     bool      `json:"active"`
}

type AuditEntry struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
}

type Stats struct {
	TotalUsers      int `json:"total_users"`
	ActiveUsers     int `json:"active_users"`
	TotalKeys       int `json:"total_keys"`
	ActiveSessions  int `json:"active_sessions"`
	TotalSessions   int `json:"total_sessions"`
	SessionsToday   int `json:"sessions_today"`
}
