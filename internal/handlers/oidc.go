package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"mock-oidc/internal/config"
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
}

// New creates a new Handler
func New(cfg *config.Config, users map[string]*models.User, keys *pki.KeyPair) *Handler {
	return &Handler{
		config:  cfg,
		users:   users,
		keys:    keys,
		session: session.New(10), // 10 minutes expiry for auth codes
	}
}

// WellKnownConfiguration handles the /.well-known/openid-configuration endpoint
func (h *Handler) WellKnownConfiguration(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// JWKS handles the /oauth2/jwks.json endpoint
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.keys.GetJWKS()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Authorize handles the /oauth2/authorize endpoint
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	responseType := r.URL.Query().Get("response_type")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || state == "" || responseType == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Validate response type
	if responseType != "code" {
		http.Error(w, "Unsupported response type", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	if _, err := url.Parse(redirectURI); err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	// Load login template
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
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

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Login handles the /oauth2/login endpoint
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
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

	// Validate user
	user, exists := h.users[username]
	if !exists || !user.ValidatePassword(password) {
		// Reload login page with error
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
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

		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Generate authorization code
	authReq := &session.AuthorizationRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       scope,
		Username:    username,
	}
	code := h.session.GenerateAuthorizationCode(authReq)

	// Redirect to client with authorization code
	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// Token handles the /oauth2/token endpoint
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get grant type
	grantType := r.Form.Get("grant_type")
	if grantType == "" {
		http.Error(w, "Missing grant_type", http.StatusBadRequest)
		return
	}

	var user *models.User

	switch grantType {
	case "authorization_code":
		// Get authorization code
		code := r.Form.Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		// Validate authorization code
		authReq, err := h.session.ValidateAuthorizationCode(code)
		if err != nil {
			http.Error(w, "Invalid authorization code", http.StatusBadRequest)
			return
		}

		// Consume the code
		h.session.ConsumeAuthorizationCode(code)

		// Get user
		var exists bool
		user, exists = h.users[authReq.Username]
		if !exists {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

	case "password":
		// Get username and password
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if username == "" || password == "" {
			http.Error(w, "Missing username or password", http.StatusBadRequest)
			return
		}

		// Validate user
		var exists bool
		user, exists = h.users[username]
		if !exists || !user.ValidatePassword(password) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

	default:
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

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = h.keys.Kid

	// Sign token
	tokenString, err := token.SignedString(h.keys.PrivateKey)
	if err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// UserInfo handles the /oauth2/userinfo endpoint
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	// Get token from Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse token
	token, err := jwt.Parse(auth[7:], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.keys.PublicKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Get claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
