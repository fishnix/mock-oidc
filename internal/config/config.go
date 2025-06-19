package config

import (
	"fmt"
	"os"
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
	host := getEnv("OIDC_HOST", "localhost")
	port := getEnv("OIDC_PORT", "8080")
	issuer := getEnv("OIDC_ISSUER", fmt.Sprintf("http://%s:%s", host, port))
	usersDir := getEnv("OIDC_USERS_DIR", "./users")

	return &Config{
		UsersDir: usersDir,
		Host:     host,
		Port:     port,
		Issuer:   issuer,
	}
}

// ServerAddr returns the server address in the format "host:port"
func (c *Config) ServerAddr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

// EnsureDirs ensures that the required directories exist
func (c *Config) EnsureDirs() error {
	if err := os.MkdirAll(c.UsersDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", c.UsersDir, err)
	}
	return nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
