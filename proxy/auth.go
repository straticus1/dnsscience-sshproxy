package proxy

import (
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func checkPassword(password, hash string) bool {
	// Support multiple hash formats
	if strings.HasPrefix(hash, "$2") {
		// bcrypt
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}

	if strings.HasPrefix(hash, "plain:") {
		// Plain text (for testing only!)
		return subtle.ConstantTimeCompare([]byte(password), []byte(hash[6:])) == 1
	}

	if strings.HasPrefix(hash, "base64:") {
		// Base64 encoded plain (slightly better than plain)
		decoded, err := base64.StdEncoding.DecodeString(hash[7:])
		if err != nil {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(password), decoded) == 1
	}

	// Default: try bcrypt
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// HashPassword creates a bcrypt hash for use in config
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
