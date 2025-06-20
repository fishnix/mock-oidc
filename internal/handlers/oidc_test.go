package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mock-oidc/internal/config"
	"mock-oidc/internal/models"
	"mock-oidc/internal/pki"
)

func setupTestHandler(t *testing.T) *Handler {
	// Create a test user
	user := &models.User{
		Username: "testuser",
		Password: "password123",
		Claims: map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
			"sub":   "testuser",
		},
	}
	users := map[string]*models.User{"testuser": user}

	// Create test config
	cfg := &config.Config{
		UsersDir: "./users",
		Host:     "localhost",
		Port:     "8080",
		Issuer:   "http://localhost:8080",
	}

	// Generate test keys
	keys, err := pki.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate test key pair: %v", err)
	}

	return New(cfg, users, keys)
}

func TestWellKnownConfiguration(t *testing.T) {
	h := setupTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rw := httptest.NewRecorder()

	h.WellKnownConfiguration(rw, req)

	resp := rw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if data["issuer"] != "http://localhost:8080" {
		t.Errorf("expected issuer to be http://localhost:8080, got %v", data["issuer"])
	}
	if data["authorization_endpoint"] == nil {
		t.Error("expected authorization_endpoint in response")
	}
}

func TestJWKS(t *testing.T) {
	h := setupTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/jwks.json", nil)
	rw := httptest.NewRecorder()

	h.JWKS(rw, req)

	resp := rw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if data["keys"] == nil {
		t.Error("expected keys in JWKS response")
	}
}

func TestAuthorizeLoginPage(t *testing.T) {
	h := setupTestHandler(t)
	url := "/oauth2/authorize?client_id=client&redirect_uri=http://client/callback&response_type=code&state=xyz&scope=openid"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rw := httptest.NewRecorder()

	h.Authorize(rw, req)

	resp := rw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	body := rw.Body.String()
	if !contains(body, "Sign in to your account") {
		t.Error("login page should contain heading")
	}
	if !contains(body, "name=\"username\"") {
		t.Error("login page should contain username field")
	}
	if !contains(body, "name=\"password\"") {
		t.Error("login page should contain password field")
	}
}

func TestLoginSuccess(t *testing.T) {
	h := setupTestHandler(t)
	form := "username=testuser&password=password123&client_id=client&redirect_uri=http://client/callback&state=xyz&scope=openid&response_type=code"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	h.Login(rw, req)

	resp := rw.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !contains(loc, "code=") {
		t.Errorf("redirect location should contain code, got %s", loc)
	}
}

func TestLoginFailure(t *testing.T) {
	h := setupTestHandler(t)
	form := "username=testuser&password=wrongpass&client_id=client&redirect_uri=http://client/callback&state=xyz&scope=openid&response_type=code"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	h.Login(rw, req)

	resp := rw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on login failure, got %d", resp.StatusCode)
	}
	body := rw.Body.String()
	if !contains(body, "Invalid username or password") {
		t.Error("login failure page should show error message")
	}
}

func TestTokenPasswordGrant(t *testing.T) {
	h := setupTestHandler(t)
	form := "grant_type=password&username=testuser&password=password123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	h.Token(rw, req)

	resp := rw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if data["access_token"] == nil || data["id_token"] == nil {
		t.Error("expected access_token and id_token in response")
	}
}

func TestTokenCodeGrant(t *testing.T) {
	h := setupTestHandler(t)
	// Simulate login to get code
	form := "username=testuser&password=password123&client_id=client&redirect_uri=http://client/callback&state=xyz&scope=openid&response_type=code"
	loginReq := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRw := httptest.NewRecorder()
	h.Login(loginRw, loginReq)
	loc := loginRw.Result().Header.Get("Location")
	code := extractQueryParam(loc, "code")
	if code == "" {
		t.Fatal("expected code in redirect location")
	}
	// Exchange code for token
	tokenForm := "grant_type=authorization_code&code=" + code
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tokenForm))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRw := httptest.NewRecorder()
	h.Token(tokenRw, tokenReq)
	resp := tokenRw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if data["access_token"] == nil || data["id_token"] == nil {
		t.Error("expected access_token and id_token in response")
	}
}

func TestUserInfo(t *testing.T) {
	h := setupTestHandler(t)
	// Get token
	form := "grant_type=password&username=testuser&password=password123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	h.Token(rw, req)
	var data map[string]interface{}
	if err := json.NewDecoder(rw.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	token := data["access_token"].(string)
	// Call userinfo
	userinfoReq := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	userinfoReq.Header.Set("Authorization", "Bearer "+token)
	userinfoRw := httptest.NewRecorder()
	h.UserInfo(userinfoRw, userinfoReq)
	resp := userinfoRw.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}
	if claims["sub"] != "testuser" {
		t.Errorf("expected sub to be testuser, got %v", claims["sub"])
	}
}

// Helper functions
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func extractQueryParam(urlStr, key string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

func TestMain(m *testing.M) {
	// Change working directory to project root
	dir, _ := os.Getwd()
	for !fileExists(filepath.Join(dir, "go.mod")) && dir != "/" {
		dir = filepath.Dir(dir)
	}
	_ = os.Chdir(dir)
	os.Exit(m.Run())
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
