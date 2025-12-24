package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ListenAddr string  `json:"listen_addr"`
	HostKeyPath string `json:"host_key_path"`
	Users      []User  `json:"users"`
}

type User struct {
	LoginID       string   `json:"login_id"`
	AllowedHosts  []string `json:"allowed_hosts"`
	DefaultHost   string   `json:"default_host"`
	PublicKeys    []string `json:"public_keys,omitempty"`
	PasswordHash  string   `json:"password_hash,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":2222"
	}

	return &cfg, nil
}

func (c *Config) FindUser(loginID string) *User {
	loginID = strings.ToLower(loginID)
	for i := range c.Users {
		if strings.ToLower(c.Users[i].LoginID) == loginID {
			return &c.Users[i]
		}
	}
	return nil
}

func (u *User) CanAccessHost(host string) bool {
	host = strings.ToLower(host)
	for _, allowed := range u.AllowedHosts {
		// Wildcard: allow all hosts
		if allowed == "*" {
			return true
		}
		if strings.ToLower(allowed) == host {
			return true
		}
		// Suffix wildcard: *.example.com matches foo.example.com
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.ToLower(allowed[1:])
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}
