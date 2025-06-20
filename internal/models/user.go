package models

import (
	"encoding/json"
	"os"
	"path/filepath"

	"mock-oidc/internal/logger"
)

// User represents an OIDC user with their claims
type User struct {
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	Claims   map[string]interface{} `json:"claims"`
}

// LoadUsers loads all user JSON files from the specified directory
func LoadUsers(dir string) (map[string]*User, error) {
	log := logger.Get()
	log.Debug("Starting to load users", "directory", dir)

	users := make(map[string]*User)

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Error("Failed to read users directory", "error", err, "directory", dir)
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
		log.Debug("Loading user file", "filename", entry.Name(), "filepath", filePath)

		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Error("Failed to read user file", "error", err, "filename", entry.Name(), "filepath", filePath)
			return nil, err
		}

		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			log.Error("Failed to unmarshal user JSON", "error", err, "filename", entry.Name(), "filepath", filePath)
			return nil, err
		}

		users[user.Username] = &user
		loadedCount++

		log.Debug("Successfully loaded user",
			"username", user.Username,
			"filename", entry.Name(),
			"claim_count", len(user.Claims),
		)
	}

	log.Info("User loading completed", "loaded_count", loadedCount, "total_users", len(users), "directory", dir)
	return users, nil
}

// ValidatePassword checks if the provided password matches the user's password
func (u *User) ValidatePassword(password string) bool {
	log := logger.Get()

	isValid := u.Password == password

	log.Debug("Password validation attempt",
		"username", u.Username,
		"is_valid", isValid,
		"password_provided", password != "",
	)

	return isValid
}
