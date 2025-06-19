package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ClientID    string
	RedirectURI string
	State       string
	Scope       string
	Username    string
	ExpiresAt   time.Time
}

// Manager handles session and authorization code management
type Manager struct {
	mu                sync.RWMutex
	authCodes         map[string]*AuthorizationRequest
	codeExpiryMinutes int
}

// New creates a new session manager
func New(codeExpiryMinutes int) *Manager {
	return &Manager{
		authCodes:         make(map[string]*AuthorizationRequest),
		codeExpiryMinutes: codeExpiryMinutes,
	}
}

// GenerateAuthorizationCode generates a new authorization code
func (m *Manager) GenerateAuthorizationCode(req *AuthorizationRequest) string {
	code := generateRandomString(32)
	req.ExpiresAt = time.Now().Add(time.Duration(m.codeExpiryMinutes) * time.Minute)

	m.mu.Lock()
	m.authCodes[code] = req
	m.mu.Unlock()

	return code
}

// ValidateAuthorizationCode validates and returns the authorization request for a code
func (m *Manager) ValidateAuthorizationCode(code string) (*AuthorizationRequest, error) {
	m.mu.RLock()
	req, exists := m.authCodes[code]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid authorization code")
	}

	if time.Now().After(req.ExpiresAt) {
		m.mu.Lock()
		delete(m.authCodes, code)
		m.mu.Unlock()
		return nil, fmt.Errorf("authorization code expired")
	}

	return req, nil
}

// ConsumeAuthorizationCode consumes an authorization code
func (m *Manager) ConsumeAuthorizationCode(code string) {
	m.mu.Lock()
	delete(m.authCodes, code)
	m.mu.Unlock()
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random string: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
