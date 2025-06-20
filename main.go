package main

import (
	"flag"
	"net/http"
	"os"

	"mock-oidc/internal/config"
	"mock-oidc/internal/handlers"
	"mock-oidc/internal/logger"
	"mock-oidc/internal/models"
	"mock-oidc/internal/pki"
)

func main() {
	// Parse command line flags
	usersDir := flag.String("users-dir", "./users", "Directory containing user JSON files")
	host := flag.String("host", "localhost", "Server host")
	port := flag.String("port", "8080", "Server port")
	issuer := flag.String("issuer", "", "OIDC issuer URL (defaults to http://{host}:{port})")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Initialize logger
	logLevel := logger.InfoLevel
	if *debug {
		logLevel = logger.DebugLevel
	}
	logger.Init(logLevel)
	log := logger.Get()

	log.Info("Starting OIDC server",
		"debug", *debug,
		"log_level", logLevel,
		"host", *host,
		"port", *port,
		"users_dir", *usersDir,
	)

	// Set environment variables from flags
	if *usersDir != "./users" {
		if err := os.Setenv("OIDC_USERS_DIR", *usersDir); err != nil {
			log.Error("Failed to set OIDC_USERS_DIR environment variable", "error", err)
			os.Exit(1)
		}
		log.Debug("Set OIDC_USERS_DIR environment variable", "value", *usersDir)
	}
	if *host != "localhost" {
		if err := os.Setenv("OIDC_HOST", *host); err != nil {
			log.Error("Failed to set OIDC_HOST environment variable", "error", err)
			os.Exit(1)
		}
		log.Debug("Set OIDC_HOST environment variable", "value", *host)
	}
	if *port != "8080" {
		if err := os.Setenv("OIDC_PORT", *port); err != nil {
			log.Error("Failed to set OIDC_PORT environment variable", "error", err)
			os.Exit(1)
		}
		log.Debug("Set OIDC_PORT environment variable", "value", *port)
	}
	if *issuer != "" {
		if err := os.Setenv("OIDC_ISSUER", *issuer); err != nil {
			log.Error("Failed to set OIDC_ISSUER environment variable", "error", err)
			os.Exit(1)
		}
		log.Debug("Set OIDC_ISSUER environment variable", "value", *issuer)
	}

	// Load configuration
	log.Info("Loading configuration")
	cfg := config.New()
	log.Debug("Configuration loaded",
		"users_dir", cfg.UsersDir,
		"host", cfg.Host,
		"port", cfg.Port,
		"issuer", cfg.Issuer,
	)

	if err := cfg.EnsureDirs(); err != nil {
		log.Error("Failed to ensure directories", "error", err, "users_dir", cfg.UsersDir)
		os.Exit(1)
	}
	log.Debug("Directories ensured", "users_dir", cfg.UsersDir)

	// Generate new keys
	log.Info("Generating key pair")
	keys, err := pki.GenerateKeyPair()
	if err != nil {
		log.Error("Failed to generate key pair", "error", err)
		os.Exit(1)
	}
	log.Info("Key pair generated successfully", "kid", keys.Kid)

	// Load users
	log.Info("Loading users", "users_dir", cfg.UsersDir)
	users, err := models.LoadUsers(cfg.UsersDir)
	if err != nil {
		log.Error("Failed to load users", "error", err, "users_dir", cfg.UsersDir)
		os.Exit(1)
	}
	log.Info("Users loaded successfully", "user_count", len(users))
	log.Debug("Loaded users", "usernames", getUserNames(users))

	// Create handler
	log.Info("Creating OIDC handler")
	handler := handlers.New(cfg, users, keys)
	log.Debug("OIDC handler created successfully")

	// Set up routes
	log.Info("Setting up routes")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", handler.WellKnownConfiguration)
	mux.HandleFunc("/oauth2/authorize", handler.Authorize)
	mux.HandleFunc("/oauth2/login", handler.Login)
	mux.HandleFunc("/oauth2/token", handler.Token)
	mux.HandleFunc("/oauth2/userinfo", handler.UserInfo)
	mux.HandleFunc("/oauth2/jwks.json", handler.JWKS)
	log.Debug("Routes configured",
		"endpoints", []string{
			"/.well-known/openid-configuration",
			"/oauth2/authorize",
			"/oauth2/login",
			"/oauth2/token",
			"/oauth2/userinfo",
			"/oauth2/jwks.json",
		},
	)

	// Start server
	server := &http.Server{
		Addr:    cfg.ServerAddr(),
		Handler: mux,
	}

	log.Info("Starting OIDC server",
		"address", cfg.ServerAddr(),
		"issuer", cfg.Issuer,
	)

	if err := server.ListenAndServe(); err != nil {
		log.Error("Failed to start server", "error", err, "address", cfg.ServerAddr())
		os.Exit(1)
	}
}

// getUserNames returns a slice of usernames from the users map
func getUserNames(users map[string]*models.User) []string {
	names := make([]string, 0, len(users))
	for username := range users {
		names = append(names, username)
	}
	return names
}
