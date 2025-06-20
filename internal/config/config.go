package config

import (
	"fmt"
	"os"

	"mock-oidc/internal/logger"
)

// Config holds the server configuration
type Config struct {
	UsersDir string
	Host     string
	Port     string
	Issuer   string
}

// New creates a new Config with values from environment variables or defaults
func New() *Config {
	log := logger.Get()
	log.Debug("Creating new configuration")

	host := getEnv("OIDC_HOST", "localhost")
	port := getEnv("OIDC_PORT", "8080")
	issuer := getEnv("OIDC_ISSUER", fmt.Sprintf("http://%s:%s", host, port))
	usersDir := getEnv("OIDC_USERS_DIR", "./users")

	config := &Config{
		UsersDir: usersDir,
		Host:     host,
		Port:     port,
		Issuer:   issuer,
	}

	log.Debug("Configuration created",
		"host", host,
		"port", port,
		"issuer", issuer,
		"users_dir", usersDir,
	)

	return config
}

// ServerAddr returns the server address in the format "host:port"
func (c *Config) ServerAddr() string {
	addr := fmt.Sprintf("%s:%s", c.Host, c.Port)
	log := logger.Get()
	log.Debug("Server address generated", "address", addr)
	return addr
}

// EnsureDirs ensures that the required directories exist
func (c *Config) EnsureDirs() error {
	log := logger.Get()
	log.Debug("Ensuring directories exist", "users_dir", c.UsersDir)

	if err := os.MkdirAll(c.UsersDir, 0755); err != nil {
		log.Error("Failed to create directory", "error", err, "directory", c.UsersDir)
		return fmt.Errorf("failed to create directory %s: %w", c.UsersDir, err)
	}

	log.Debug("Directory ensured successfully", "directory", c.UsersDir)
	return nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		log := logger.Get()
		log.Debug("Environment variable found", "key", key, "value", value)
		return value
	}

	log := logger.Get()
	log.Debug("Environment variable not found, using default", "key", key, "default_value", defaultValue)
	return defaultValue
}
