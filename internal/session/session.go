package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"mock-oidc/internal/logger"
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
	logger            *logger.Logger
}

// New creates a new session manager
func New(codeExpiryMinutes int) *Manager {
	log := logger.Get()
	log.Info("Creating session manager", "code_expiry_minutes", codeExpiryMinutes)

	return &Manager{
		authCodes:         make(map[string]*AuthorizationRequest),
		codeExpiryMinutes: codeExpiryMinutes,
		logger:            log,
	}
}

// GenerateAuthorizationCode generates a new authorization code
func (m *Manager) GenerateAuthorizationCode(req *AuthorizationRequest) string {
	code := generateRandomString(32)
	req.ExpiresAt = time.Now().Add(time.Duration(m.codeExpiryMinutes) * time.Minute)

	m.mu.Lock()
	m.authCodes[code] = req
	activeCodes := len(m.authCodes)
	m.mu.Unlock()

	m.logger.Info("Authorization code generated",
		"code", code,
		"username", req.Username,
		"client_id", req.ClientID,
		"expires_at", req.ExpiresAt,
		"active_codes", activeCodes,
	)

	return code
}

// ValidateAuthorizationCode validates and returns the authorization request for a code
func (m *Manager) ValidateAuthorizationCode(code string) (*AuthorizationRequest, error) {
	m.mu.RLock()
	req, exists := m.authCodes[code]
	m.mu.RUnlock()

	if !exists {
		m.logger.Warn("Authorization code not found", "code", code)
		return nil, fmt.Errorf("invalid authorization code")
	}

	if time.Now().After(req.ExpiresAt) {
		m.logger.Warn("Authorization code expired",
			"code", code,
			"expires_at", req.ExpiresAt,
			"username", req.Username,
		)

		m.mu.Lock()
		delete(m.authCodes, code)
		activeCodes := len(m.authCodes)
		m.mu.Unlock()

		m.logger.Debug("Expired authorization code removed", "code", code, "active_codes", activeCodes)
		return nil, fmt.Errorf("authorization code expired")
	}

	m.logger.Debug("Authorization code validated successfully",
		"code", code,
		"username", req.Username,
		"client_id", req.ClientID,
		"expires_at", req.ExpiresAt,
	)

	return req, nil
}

// ConsumeAuthorizationCode consumes an authorization code
func (m *Manager) ConsumeAuthorizationCode(code string) {
	m.mu.Lock()
	req, exists := m.authCodes[code]
	delete(m.authCodes, code)
	activeCodes := len(m.authCodes)
	m.mu.Unlock()

	if exists {
		m.logger.Info("Authorization code consumed",
			"code", code,
			"username", req.Username,
			"client_id", req.ClientID,
			"active_codes", activeCodes,
		)
	} else {
		m.logger.Warn("Attempted to consume non-existent authorization code", "code", code)
	}
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log := logger.Get()
		log.Error("Failed to generate random string", "error", err, "length", length)
		panic("failed to generate random string: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
