package models

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// User represents an OIDC user with their claims
type User struct {
	Username string                 `json:"username"`
	Password string                 `json:"password"`
	Claims   map[string]interface{} `json:"claims"`
}

// LoadUsers loads all user JSON files from the specified directory
func LoadUsers(dir string) (map[string]*User, error) {
	users := make(map[string]*User)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}

		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			return nil, err
		}

		users[user.Username] = &user
	}

	return users, nil
}

// ValidatePassword checks if the provided password matches the user's password
func (u *User) ValidatePassword(password string) bool {
	return u.Password == password
}
