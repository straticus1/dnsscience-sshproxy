package store

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(connString string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &PostgresStore{db: db}

	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

func (s *PostgresStore) migrate() error {
	migrations := []string{
		`CREATE SCHEMA IF NOT EXISTS sshproxy`,

		`CREATE TABLE IF NOT EXISTS sshproxy.users (
			id VARCHAR(255) PRIMARY KEY,
			email VARCHAR(255) NOT NULL UNIQUE,
			enabled BOOLEAN DEFAULT true,
			allowed_hosts TEXT[] DEFAULT ARRAY['*.afterdarksys.com'],
			default_host VARCHAR(255) DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			last_login TIMESTAMPTZ
		)`,

		`CREATE TABLE IF NOT EXISTS sshproxy.ssh_keys (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL REFERENCES sshproxy.users(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			public_key TEXT NOT NULL,
			fingerprint VARCHAR(255) NOT NULL,
			key_type VARCHAR(50) NOT NULL,
			enabled BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			last_used TIMESTAMPTZ,
			UNIQUE(user_id, fingerprint)
		)`,

		`CREATE INDEX IF NOT EXISTS idx_ssh_keys_user_id ON sshproxy.ssh_keys(user_id)`,

		`CREATE TABLE IF NOT EXISTS sshproxy.sessions (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL REFERENCES sshproxy.users(id) ON DELETE CASCADE,
			remote_addr VARCHAR(255) NOT NULL,
			target_host VARCHAR(255) NOT NULL,
			key_id VARCHAR(255),
			started_at TIMESTAMPTZ DEFAULT NOW(),
			ended_at TIMESTAMPTZ,
			active BOOLEAN DEFAULT true
		)`,

		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sshproxy.sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_active ON sshproxy.sessions(active) WHERE active = true`,

		`CREATE TABLE IF NOT EXISTS sshproxy.audit_log (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			action VARCHAR(100) NOT NULL,
			details TEXT,
			ip VARCHAR(255),
			timestamp TIMESTAMPTZ DEFAULT NOW()
		)`,

		`CREATE INDEX IF NOT EXISTS idx_audit_user_id ON sshproxy.audit_log(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON sshproxy.audit_log(timestamp)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %s: %w", m[:50], err)
		}
	}

	return nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// User management

func (s *PostgresStore) GetUser(ctx context.Context, userID string) (*User, error) {
	var user User
	var allowedHosts []byte

	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, enabled, allowed_hosts, default_host, created_at, updated_at, last_login,
		       (SELECT COUNT(*) FROM sshproxy.ssh_keys WHERE user_id = u.id) as key_count
		FROM sshproxy.users u
		WHERE id = $1
	`, userID).Scan(
		&user.ID, &user.Email, &user.Enabled, &allowedHosts, &user.DefaultHost,
		&user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.KeyCount,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	user.AllowedHosts = parsePostgresArray(string(allowedHosts))
	return &user, nil
}

func (s *PostgresStore) EnsureUser(ctx context.Context, userID, email string) (*User, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sshproxy.users (id, email)
		VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			updated_at = NOW()
	`, userID, email)

	if err != nil {
		return nil, err
	}

	return s.GetUser(ctx, userID)
}

func (s *PostgresStore) UpdateUser(ctx context.Context, userID string, update UserUpdate) (*User, error) {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sshproxy.users
		SET allowed_hosts = $2, default_host = $3, updated_at = NOW()
		WHERE id = $1
	`, userID, update.AllowedHosts, update.DefaultHost)

	if err != nil {
		return nil, err
	}

	return s.GetUser(ctx, userID)
}

func (s *PostgresStore) SetUserAccess(ctx context.Context, userID string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sshproxy.users SET enabled = $2, updated_at = NOW() WHERE id = $1
	`, userID, enabled)
	return err
}

func (s *PostgresStore) ListAllUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, email, enabled, allowed_hosts, default_host, created_at, updated_at, last_login,
		       (SELECT COUNT(*) FROM sshproxy.ssh_keys WHERE user_id = u.id) as key_count
		FROM sshproxy.users u
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var allowedHosts []byte

		if err := rows.Scan(
			&user.ID, &user.Email, &user.Enabled, &allowedHosts, &user.DefaultHost,
			&user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.KeyCount,
		); err != nil {
			return nil, err
		}

		user.AllowedHosts = parsePostgresArray(string(allowedHosts))
		users = append(users, user)
	}

	return users, nil
}

// SSH Key management

func (s *PostgresStore) ListKeys(ctx context.Context, userID string) ([]SSHKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, public_key, fingerprint, key_type, enabled, created_at, last_used
		FROM sshproxy.ssh_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SSHKey
	for rows.Next() {
		var key SSHKey
		if err := rows.Scan(
			&key.ID, &key.UserID, &key.Name, &key.PublicKey,
			&key.Fingerprint, &key.KeyType, &key.Enabled, &key.CreatedAt, &key.LastUsed,
		); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

func (s *PostgresStore) AddKey(ctx context.Context, userID, name, publicKey string) (*SSHKey, error) {
	// Parse and validate the public key
	parsed, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid SSH public key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(parsed)
	keyType := parsed.Type()

	if name == "" && comment != "" {
		name = comment
	}
	if name == "" {
		name = "Key " + fingerprint[:12]
	}

	id := uuid.New().String()

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sshproxy.ssh_keys (id, user_id, name, public_key, fingerprint, key_type)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, id, userID, name, publicKey, fingerprint, keyType)

	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return nil, fmt.Errorf("key already exists")
		}
		return nil, err
	}

	return &SSHKey{
		ID:          id,
		UserID:      userID,
		Name:        name,
		PublicKey:   publicKey,
		Fingerprint: fingerprint,
		KeyType:     keyType,
		Enabled:     true,
		CreatedAt:   time.Now(),
	}, nil
}

func (s *PostgresStore) RemoveKey(ctx context.Context, userID, keyID string) error {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM sshproxy.ssh_keys WHERE id = $1 AND user_id = $2
	`, keyID, userID)
	if err != nil {
		return err
	}

	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("key not found")
	}

	return nil
}

func (s *PostgresStore) SetKeyEnabled(ctx context.Context, userID, keyID string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sshproxy.ssh_keys SET enabled = $3 WHERE id = $1 AND user_id = $2
	`, keyID, userID, enabled)
	return err
}

func (s *PostgresStore) GetActiveKeys(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT public_key FROM sshproxy.ssh_keys
		WHERE user_id = $1 AND enabled = true
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// Session management

func (s *PostgresStore) CreateSession(ctx context.Context, session *Session) error {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}
	session.StartedAt = time.Now()
	session.Active = true

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sshproxy.sessions (id, user_id, remote_addr, target_host, key_id, started_at, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, session.ID, session.UserID, session.RemoteAddr, session.TargetHost, session.KeyID, session.StartedAt, session.Active)

	// Update last login
	s.db.ExecContext(ctx, `UPDATE sshproxy.users SET last_login = NOW() WHERE id = $1`, session.UserID)

	return err
}

func (s *PostgresStore) EndSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sshproxy.sessions SET ended_at = NOW(), active = false WHERE id = $1
	`, sessionID)
	return err
}

func (s *PostgresStore) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, remote_addr, target_host, key_id, started_at, ended_at, active
		FROM sshproxy.sessions
		WHERE user_id = $1
		ORDER BY started_at DESC
		LIMIT 100
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSessions(rows)
}

func (s *PostgresStore) ListAllSessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, remote_addr, target_host, key_id, started_at, ended_at, active
		FROM sshproxy.sessions
		WHERE active = true
		ORDER BY started_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]Session, error) {
	var sessions []Session
	for rows.Next() {
		var sess Session
		var keyID sql.NullString

		if err := rows.Scan(
			&sess.ID, &sess.UserID, &sess.RemoteAddr, &sess.TargetHost,
			&keyID, &sess.StartedAt, &sess.EndedAt, &sess.Active,
		); err != nil {
			return nil, err
		}

		if keyID.Valid {
			sess.KeyID = keyID.String
		}
		sessions = append(sessions, sess)
	}

	return sessions, nil
}

func (s *PostgresStore) KillSession(ctx context.Context, sessionID string) error {
	return s.EndSession(ctx, sessionID)
}

func (s *PostgresStore) KillUserSessions(ctx context.Context, userID string) (int, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE sshproxy.sessions SET ended_at = NOW(), active = false
		WHERE user_id = $1 AND active = true
	`, userID)
	if err != nil {
		return 0, err
	}

	n, _ := result.RowsAffected()
	return int(n), nil
}

func (s *PostgresStore) GetActiveSessionCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.sessions WHERE active = true`).Scan(&count)
	return count, err
}

// Audit logging

func (s *PostgresStore) LogAudit(ctx context.Context, entry AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sshproxy.audit_log (id, user_id, action, details, ip, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, entry.ID, entry.UserID, entry.Action, entry.Details, entry.IP, entry.Timestamp)

	return err
}

func (s *PostgresStore) GetAuditLogs(ctx context.Context, userID string, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, action, details, ip, timestamp
		FROM sshproxy.audit_log
		WHERE user_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.UserID, &entry.Action, &entry.Details, &entry.IP, &entry.Timestamp); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// Stats

func (s *PostgresStore) GetStats(ctx context.Context) (*Stats, error) {
	var stats Stats

	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.users`).Scan(&stats.TotalUsers)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.users WHERE enabled = true`).Scan(&stats.ActiveUsers)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.ssh_keys`).Scan(&stats.TotalKeys)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.sessions WHERE active = true`).Scan(&stats.ActiveSessions)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.sessions`).Scan(&stats.TotalSessions)
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sshproxy.sessions WHERE started_at > NOW() - INTERVAL '24 hours'`).Scan(&stats.SessionsToday)

	return &stats, nil
}

// Helpers

func parsePostgresArray(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func fingerprintMD5(key ssh.PublicKey) string {
	hash := md5.Sum(key.Marshal())
	out := make([]string, len(hash))
	for i, b := range hash {
		out[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(out, ":")
}

func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
