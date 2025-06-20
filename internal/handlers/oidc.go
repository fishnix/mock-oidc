package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"mock-oidc/internal/config"
	"mock-oidc/internal/logger"
	"mock-oidc/internal/models"
	"mock-oidc/internal/pki"
	"mock-oidc/internal/session"

	"github.com/golang-jwt/jwt/v5"
)

// Handler handles OIDC endpoints
type Handler struct {
	config  *config.Config
	users   map[string]*models.User
	keys    *pki.KeyPair
	session *session.Manager
	logger  *logger.Logger
}

// New creates a new Handler
func New(cfg *config.Config, users map[string]*models.User, keys *pki.KeyPair) *Handler {
	return &Handler{
		config:  cfg,
		users:   users,
		keys:    keys,
		session: session.New(10), // 10 minutes expiry for auth codes
		logger:  logger.Get(),
	}
}

// generateRequestID generates a unique request ID for tracking
func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// WellKnownConfiguration handles the /.well-known/openid-configuration endpoint
func (h *Handler) WellKnownConfiguration(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	log := h.logger.WithRequestID(requestID).WithEndpoint("well-known-configuration")

	log.Info("Handling well-known configuration request",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	config := map[string]interface{}{
		"issuer":                 h.config.Issuer,
		"authorization_endpoint": fmt.Sprintf("%s/oauth2/authorize", h.config.Issuer),
		"token_endpoint":         fmt.Sprintf("%s/oauth2/token", h.config.Issuer),
		"userinfo_endpoint":      fmt.Sprintf("%s/oauth2/userinfo", h.config.Issuer),
		"jwks_uri":               fmt.Sprintf("%s/oauth2/jwks.json", h.config.Issuer),
		"response_types_supported": []string{
			"code",
			"id_token",
			"token",
			"id_token token",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"ES256",
		},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
		"claims_supported": []string{
			"sub",
			"iss",
			"name",
			"email",
		},
	}

	log.Debug("Generated configuration", "issuer", h.config.Issuer)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		log.Error("Failed to encode configuration response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Info("Well-known configuration request completed successfully")
}

// JWKS handles the /oauth2/jwks.json endpoint
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	log := h.logger.WithRequestID(requestID).WithEndpoint("jwks")

	log.Info("Handling JWKS request",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	jwks := h.keys.GetJWKS()
	log.Debug("Generated JWKS", "kid", h.keys.Kid, "key_count", len(jwks.Keys))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Error("Failed to encode JWKS response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Info("JWKS request completed successfully")
}

// Authorize handles the /oauth2/authorize endpoint
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	log := h.logger.WithRequestID(requestID).WithEndpoint("authorize")

	log.Info("Handling authorization request",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"url", r.URL.String(),
	)

	if r.Method != http.MethodGet {
		log.Warn("Invalid method for authorization endpoint", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")

	log.Debug("Authorization request parameters",
		"client_id", clientID,
		"redirect_uri", redirectURI,
		"state", state,
		"scope", scope,
		"response_type", responseType,
	)

	// Validate required parameters
	if clientID == "" || redirectURI == "" || state == "" || responseType == "" {
		log.Warn("Missing required parameters in authorization request",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"state", state,
			"response_type", responseType,
		)
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Validate response type
	if responseType != "code" {
		log.Warn("Unsupported response type", "response_type", responseType)
		http.Error(w, "Unsupported response type", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	if _, err := url.Parse(redirectURI); err != nil {
		log.Warn("Invalid redirect URI", "redirect_uri", redirectURI, "error", err)
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	log.Debug("Authorization request validation passed")

	// Load login template
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Error("Failed to parse login template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Render login page
	data := struct {
		ClientID     string
		RedirectURI  string
		State        string
		Scope        string
		ResponseType string
		Error        string
	}{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		State:        state,
		Scope:        scope,
		ResponseType: responseType,
	}

	log.Debug("Rendering login page", "client_id", clientID)

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Error("Failed to execute login template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Info("Authorization request completed successfully - login page rendered")
}

// Login handles the /oauth2/login endpoint
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	log := h.logger.WithRequestID(requestID).WithEndpoint("login")

	log.Info("Handling login request",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	if r.Method != http.MethodPost {
		log.Warn("Invalid method for login endpoint", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		log.Error("Failed to parse form data", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get form data
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	state := r.Form.Get("state")
	scope := r.Form.Get("scope")
	responseType := r.Form.Get("response_type")

	log.Debug("Login form data",
		"username", username,
		"client_id", clientID,
		"redirect_uri", redirectURI,
		"state", state,
		"scope", scope,
		"response_type", responseType,
		"password_provided", password != "",
	)

	// Validate user
	user, exists := h.users[username]
	if !exists {
		log.Warn("Login attempt with non-existent user", "username", username)
	} else if !user.ValidatePassword(password) {
		log.Warn("Login attempt with invalid password", "username", username)
	}

	if !exists || !user.ValidatePassword(password) {
		// Reload login page with error
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			log.Error("Failed to parse login template for error page", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		data := struct {
			ClientID     string
			RedirectURI  string
			State        string
			Scope        string
			ResponseType string
			Error        string
		}{
			ClientID:     clientID,
			RedirectURI:  redirectURI,
			State:        state,
			Scope:        scope,
			ResponseType: responseType,
			Error:        "Invalid username or password",
		}

		log.Debug("Rendering login page with error", "client_id", clientID)

		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			log.Error("Failed to execute login template with error", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		log.Info("Login failed - error page rendered", "username", username)
		return
	}

	log.Info("User authentication successful", "username", username)

	// Generate authorization code
	authReq := &session.AuthorizationRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       scope,
		Username:    username,
	}
	code := h.session.GenerateAuthorizationCode(authReq)

	log.Debug("Authorization code generated",
		"code", code,
		"username", username,
		"client_id", clientID,
	)

	// Redirect to client with authorization code
	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	log.Info("Redirecting to client with authorization code",
		"username", username,
		"client_id", clientID,
		"redirect_uri", redirectURL.String(),
	)

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// Token handles the /oauth2/token endpoint
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	log := h.logger.WithRequestID(requestID).WithEndpoint("token")

	log.Info("Handling token request",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	if r.Method != http.MethodPost {
		log.Warn("Invalid method for token endpoint", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		log.Error("Failed to parse form data", "error", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get grant type
	grantType := r.Form.Get("grant_type")
	if grantType == "" {
		log.Warn("Missing grant_type in token request")
		http.Error(w, "Missing grant_type", http.StatusBadRequest)
		return
	}

	log.Debug("Token request parameters", "grant_type", grantType)

	var user *models.User

	switch grantType {
	case "authorization_code":
		// Get authorization code
		code := r.Form.Get("code")
		if code == "" {
			log.Warn("Missing authorization code", "grant_type", grantType)
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		log.Debug("Processing authorization code grant", "code", code)

		// Validate authorization code
		authReq, err := h.session.ValidateAuthorizationCode(code)
		if err != nil {
			log.Warn("Invalid authorization code", "code", code, "error", err)
			http.Error(w, "Invalid authorization code", http.StatusBadRequest)
			return
		}

		log.Debug("Authorization code validated",
			"code", code,
			"username", authReq.Username,
			"client_id", authReq.ClientID,
		)

		// Consume the code
		h.session.ConsumeAuthorizationCode(code)
		log.Debug("Authorization code consumed", "code", code)

		// Get user
		var exists bool
		user, exists = h.users[authReq.Username]
		if !exists {
			log.Error("User not found for validated authorization code",
				"username", authReq.Username,
				"code", code,
			)
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		log.Info("Authorization code grant successful", "username", user.Username)

	case "password":
		// Get username and password
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if username == "" || password == "" {
			log.Warn("Missing username or password in password grant", "username", username)
			http.Error(w, "Missing username or password", http.StatusBadRequest)
			return
		}

		log.Debug("Processing password grant", "username", username)

		// Validate user
		var exists bool
		user, exists = h.users[username]
		if !exists {
			log.Warn("Password grant attempt with non-existent user", "username", username)
		} else if !user.ValidatePassword(password) {
			log.Warn("Password grant attempt with invalid password", "username", username)
		}

		if !exists || !user.ValidatePassword(password) {
			log.Warn("Password grant failed", "username", username)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		log.Info("Password grant successful", "username", user.Username)

	default:
		log.Warn("Unsupported grant type", "grant_type", grantType)
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	// Create ID token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": h.config.Issuer,
		"sub": user.Username,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	// Add user claims
	for k, v := range user.Claims {
		claims[k] = v
	}

	log.Debug("Creating JWT token",
		"username", user.Username,
		"issuer", h.config.Issuer,
		"expires_at", now.Add(time.Hour),
		"claim_count", len(claims),
	)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = h.keys.Kid

	// Sign token
	tokenString, err := token.SignedString(h.keys.PrivateKey)
	if err != nil {
		log.Error("Failed to sign JWT token", "error", err, "username", user.Username)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return token response
	response := map[string]interface{}{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     tokenString,
	}

	log.Debug("Token response prepared", "username", user.Username)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("Failed to encode token response", "error", err, "username", user.Username)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Info("Token request completed successfully", "username", user.Username, "grant_type", grantType)
}

// UserInfo handles the /oauth2/userinfo endpoint
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	log := h.logger.WithRequestID(requestID).WithEndpoint("userinfo")

	log.Info("Handling userinfo request",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	// Get token from Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		log.Warn("Missing Authorization header")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if len(auth) < 7 || auth[:7] != "Bearer " {
		log.Warn("Invalid Authorization header format", "auth_header", auth)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := auth[7:]
	log.Debug("Processing userinfo request", "token_length", len(tokenString))

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.keys.PublicKey, nil
	})

	if err != nil {
		log.Warn("Failed to parse JWT token", "error", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		log.Warn("Invalid JWT token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Get claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Error("Invalid token claims format")
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	username, _ := claims["sub"].(string)
	log.Debug("Token validated successfully", "username", username)

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		log.Error("Failed to encode userinfo response", "error", err, "username", username)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Info("Userinfo request completed successfully", "username", username)
}
