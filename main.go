package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hostscience/sshproxy/config"
	"github.com/hostscience/sshproxy/proxy"
	"golang.org/x/crypto/ssh"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	genKey := flag.Bool("genkey", false, "generate a new host key and exit")
	keyPath := flag.String("keyout", "host_key", "path for generated key")
	hashPw := flag.String("hashpw", "", "hash a password and exit")
	flag.Parse()

	if *hashPw != "" {
		hash, err := proxy.HashPassword(*hashPw)
		if err != nil {
			log.Fatalf("Failed to hash password: %v", err)
		}
		fmt.Println(hash)
		return
	}

	if *genKey {
		if err := generateHostKey(*keyPath); err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
		fmt.Printf("Generated host key: %s\n", *keyPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded config with %d users", len(cfg.Users))

	hostKey, err := loadHostKey(cfg.HostKeyPath)
	if err != nil {
		log.Fatalf("Failed to load host key: %v", err)
	}

	server := proxy.NewServer(cfg, hostKey)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		active, total := server.Stats()
		log.Printf("[SHUTDOWN] Stopping... (active: %d, total served: %d)", active, total)
		os.Exit(0)
	}()

	if err := server.ListenAndServe(cfg.ListenAddr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func loadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading host key: %w", err)
	}

	key, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing host key: %w", err)
	}

	return key, nil
}

func generateHostKey(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	return nil
}
