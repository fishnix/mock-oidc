package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"mock-oidc/internal/config"
	"mock-oidc/internal/handlers"
	"mock-oidc/internal/models"
	"mock-oidc/internal/pki"
)

func main() {
	// Parse command line flags
	usersDir := flag.String("users-dir", "./users", "Directory containing user JSON files")
	host := flag.String("host", "localhost", "Server host")
	port := flag.String("port", "8080", "Server port")
	issuer := flag.String("issuer", "", "OIDC issuer URL (defaults to http://{host}:{port})")
	flag.Parse()

	// Set environment variables from flags
	if *usersDir != "./users" {
		if err := os.Setenv("OIDC_USERS_DIR", *usersDir); err != nil {
			log.Fatalf("Failed to set OIDC_USERS_DIR: %v", err)
		}
	}
	if *host != "localhost" {
		if err := os.Setenv("OIDC_HOST", *host); err != nil {
			log.Fatalf("Failed to set OIDC_HOST: %v", err)
		}
	}
	if *port != "8080" {
		if err := os.Setenv("OIDC_PORT", *port); err != nil {
			log.Fatalf("Failed to set OIDC_PORT: %v", err)
		}
	}
	if *issuer != "" {
		if err := os.Setenv("OIDC_ISSUER", *issuer); err != nil {
			log.Fatalf("Failed to set OIDC_ISSUER: %v", err)
		}
	}

	// Load configuration
	cfg := config.New()
	if err := cfg.EnsureDirs(); err != nil {
		log.Fatalf("Failed to ensure directories: %v", err)
	}

	// Generate new keys
	keys, err := pki.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Load users
	users, err := models.LoadUsers(cfg.UsersDir)
	if err != nil {
		log.Fatalf("Failed to load users: %v", err)
	}

	// Create handler
	handler := handlers.New(cfg, users, keys)

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", handler.WellKnownConfiguration)
	mux.HandleFunc("/oauth2/authorize", handler.Authorize)
	mux.HandleFunc("/oauth2/login", handler.Login)
	mux.HandleFunc("/oauth2/token", handler.Token)
	mux.HandleFunc("/oauth2/userinfo", handler.UserInfo)
	mux.HandleFunc("/oauth2/jwks.json", handler.JWKS)

	// Start server
	server := &http.Server{
		Addr:    cfg.ServerAddr(),
		Handler: mux,
	}

	log.Printf("Loading users from: %s", cfg.UsersDir)

	log.Printf("Starting OIDC server on %s", cfg.ServerAddr())

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
