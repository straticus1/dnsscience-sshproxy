package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hostscience/sshproxy/store"
)

type Server struct {
	store      store.Store
	jwtSecret  []byte
	httpServer *http.Server
}

type Config struct {
	ListenAddr string
	JWTSecret  string
	Store      store.Store
}

func NewServer(cfg Config) *Server {
	s := &Server{
		store:     cfg.Store,
		jwtSecret: []byte(cfg.JWTSecret),
	}

	mux := http.NewServeMux()

	// Health check (no auth)
	mux.HandleFunc("GET /health", s.handleHealth)

	// User management (requires auth)
	mux.HandleFunc("GET /api/v1/users/{userID}", s.authMiddleware(s.handleGetUser))
	mux.HandleFunc("PUT /api/v1/users/{userID}", s.authMiddleware(s.handleUpdateUser))
	mux.HandleFunc("PUT /api/v1/users/{userID}/access", s.authMiddleware(s.handleToggleAccess))

	// SSH key management
	mux.HandleFunc("GET /api/v1/users/{userID}/keys", s.authMiddleware(s.handleListKeys))
	mux.HandleFunc("POST /api/v1/users/{userID}/keys", s.authMiddleware(s.handleAddKey))
	mux.HandleFunc("DELETE /api/v1/users/{userID}/keys/{keyID}", s.authMiddleware(s.handleRemoveKey))
	mux.HandleFunc("PATCH /api/v1/users/{userID}/keys/{keyID}", s.authMiddleware(s.handleToggleKey))

	// Session management
	mux.HandleFunc("GET /api/v1/users/{userID}/sessions", s.authMiddleware(s.handleListSessions))
	mux.HandleFunc("DELETE /api/v1/users/{userID}/sessions", s.authMiddleware(s.handleKillSessions))
	mux.HandleFunc("DELETE /api/v1/users/{userID}/sessions/{sessionID}", s.authMiddleware(s.handleKillSession))

	// Audit logs (admin only)
	mux.HandleFunc("GET /api/v1/audit", s.authMiddleware(s.handleAuditLogs))

	// Admin endpoints
	mux.HandleFunc("GET /api/v1/admin/users", s.adminMiddleware(s.handleListAllUsers))
	mux.HandleFunc("GET /api/v1/admin/sessions", s.adminMiddleware(s.handleListAllSessions))
	mux.HandleFunc("GET /api/v1/admin/stats", s.adminMiddleware(s.handleStats))

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.corsMiddleware(s.loggingMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

func (s *Server) ListenAndServe() error {
	log.Printf("[API] Management API listening on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Middleware

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://afterdarksys.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[API] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

type contextKey string

const (
	ctxUserID   contextKey = "userID"
	ctxUserRole contextKey = "userRole"
)

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			s.jsonError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		claims, err := s.validateJWT(token)
		if err != nil {
			s.jsonError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
			return
		}

		// Users can only access their own data (unless admin)
		requestedUserID := r.PathValue("userID")
		if requestedUserID != "" && requestedUserID != claims.UserID && claims.Role != "admin" {
			s.jsonError(w, http.StatusForbidden, "access denied")
			return
		}

		ctx := context.WithValue(r.Context(), ctxUserID, claims.UserID)
		ctx = context.WithValue(ctx, ctxUserRole, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value(ctxUserRole).(string)
		if role != "admin" {
			s.jsonError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) string {
	// Check Authorization header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check cookie
	cookie, err := r.Cookie("afterdark_token")
	if err == nil {
		return cookie.Value
	}

	return ""
}

// Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"status":  "healthy",
		"service": "sshproxy-api",
		"version": "1.0.0",
	})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	s.jsonResponse(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	var req struct {
		AllowedHosts []string `json:"allowed_hosts"`
		DefaultHost  string   `json:"default_host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := s.store.UpdateUser(r.Context(), userID, store.UserUpdate{
		AllowedHosts: req.AllowedHosts,
		DefaultHost:  req.DefaultHost,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, user)
}

func (s *Server) handleToggleAccess(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.store.SetUserAccess(r.Context(), userID, req.Enabled); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"user_id": userID,
		"enabled": req.Enabled,
	})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	keys, err := s.store.ListKeys(r.Context(), userID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"keys": keys,
	})
}

func (s *Server) handleAddKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.PublicKey == "" {
		s.jsonError(w, http.StatusBadRequest, "name and public_key required")
		return
	}

	key, err := s.store.AddKey(r.Context(), userID, req.Name, req.PublicKey)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Audit log
	s.store.LogAudit(r.Context(), store.AuditEntry{
		UserID:    userID,
		Action:    "key_added",
		Details:   fmt.Sprintf("Added key: %s", req.Name),
		IP:        r.RemoteAddr,
		Timestamp: time.Now(),
	})

	s.jsonResponse(w, http.StatusCreated, key)
}

func (s *Server) handleRemoveKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	keyID := r.PathValue("keyID")

	if err := s.store.RemoveKey(r.Context(), userID, keyID); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.store.LogAudit(r.Context(), store.AuditEntry{
		UserID:    userID,
		Action:    "key_removed",
		Details:   fmt.Sprintf("Removed key: %s", keyID),
		IP:        r.RemoteAddr,
		Timestamp: time.Now(),
	})

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"deleted": keyID,
	})
}

func (s *Server) handleToggleKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	keyID := r.PathValue("keyID")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.store.SetKeyEnabled(r.Context(), userID, keyID, req.Enabled); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	action := "key_disabled"
	if req.Enabled {
		action = "key_enabled"
	}
	s.store.LogAudit(r.Context(), store.AuditEntry{
		UserID:    userID,
		Action:    action,
		Details:   fmt.Sprintf("Key %s: %s", action, keyID),
		IP:        r.RemoteAddr,
		Timestamp: time.Now(),
	})

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"key_id":  keyID,
		"enabled": req.Enabled,
	})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	sessions, err := s.store.ListSessions(r.Context(), userID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"sessions": sessions,
	})
}

func (s *Server) handleKillSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")

	count, err := s.store.KillUserSessions(r.Context(), userID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.store.LogAudit(r.Context(), store.AuditEntry{
		UserID:    userID,
		Action:    "sessions_killed",
		Details:   fmt.Sprintf("Killed %d sessions", count),
		IP:        r.RemoteAddr,
		Timestamp: time.Now(),
	})

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"killed": count,
	})
}

func (s *Server) handleKillSession(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	sessionID := r.PathValue("sessionID")

	if err := s.store.KillSession(r.Context(), sessionID); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.store.LogAudit(r.Context(), store.AuditEntry{
		UserID:    userID,
		Action:    "session_killed",
		Details:   fmt.Sprintf("Killed session: %s", sessionID),
		IP:        r.RemoteAddr,
		Timestamp: time.Now(),
	})

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"killed": sessionID,
	})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	if userID == "" {
		userID = r.Context().Value(ctxUserID).(string)
	}

	logs, err := s.store.GetAuditLogs(r.Context(), userID, 100)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"logs": logs,
	})
}

func (s *Server) handleListAllUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListAllUsers(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"users": users,
	})
}

func (s *Server) handleListAllSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListAllSessions(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"sessions": sessions,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats(r.Context())
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, stats)
}

// Helpers

func (s *Server) jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, message string) {
	s.jsonResponse(w, status, map[string]string{"error": message})
}
