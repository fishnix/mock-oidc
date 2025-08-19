package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"mock-oidc/internal/logger"
)

// App represents an OIDC client application with its credentials and claims
type App struct {
	ClientID     string                 `json:"client_id"`
	ClientSecret string                 `json:"client_secret"`
	Claims       map[string]interface{} `json:"claims"`
}

// LoadApps loads all client application JSON files from the specified directory
func LoadApps(dir string) (map[string]*App, error) {
	log := logger.Get()
	log.Debug("Starting to load client applications", "directory", dir)

	apps := make(map[string]*App)

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Error("Failed to read apps directory", "error", err, "directory", dir)
		return nil, err
	}

	log.Debug("Found directory entries", "entry_count", len(entries), "directory", dir)

	loadedCount := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			log.Debug("Skipping non-JSON file", "filename", entry.Name())
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		log.Debug("Loading app file", "filename", entry.Name(), "filepath", filePath)

		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Error("Failed to read app file", "error", err, "filename", entry.Name(), "filepath", filePath)
			return nil, err
		}

		var app App
		if err := json.Unmarshal(data, &app); err != nil {
			log.Error("Failed to unmarshal app JSON", "error", err, "filename", entry.Name(), "filepath", filePath)
			return nil, err
		}

		// Validate required fields
		if app.ClientID == "" {
			log.Error("App missing client_id", "filename", entry.Name())
			return nil, fmt.Errorf("app in %s missing client_id", entry.Name())
		}

		if app.ClientSecret == "" {
			log.Error("App missing client_secret", "filename", entry.Name())
			return nil, fmt.Errorf("app in %s missing client_secret", entry.Name())
		}

		apps[app.ClientID] = &app
		loadedCount++

		log.Debug("Successfully loaded app",
			"client_id", app.ClientID,
			"filename", entry.Name(),
			"claim_count", len(app.Claims),
		)
	}

	log.Info("App loading completed", "loaded_count", loadedCount, "total_apps", len(apps), "directory", dir)
	return apps, nil
}

// ValidateClientSecret checks if the provided client secret matches the app's client secret
func (a *App) ValidateClientSecret(clientSecret string) bool {
	log := logger.Get()

	isValid := a.ClientSecret == clientSecret

	log.Debug("Client secret validation attempt",
		"client_id", a.ClientID,
		"is_valid", isValid,
		"secret_provided", clientSecret != "",
	)

	return isValid
}
