package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
)

func TestNewOidcProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		wantName      string
		wantScopesLen int
		wantPkce      bool
	}{
		{
			name:          "Default provider creation",
			wantName:      "OpenID Connect",
			wantScopesLen: 3,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewOidcProvider()
			oidcProvider, ok := provider.(*oidcProvider)

			if !ok {
				t.Error("NewOidcProvider should return *oidcProvider type")
			}

			if oidcProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", oidcProvider.DisplayName, tt.wantName)
			}

			if len(oidcProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(oidcProvider.Scopes), tt.wantScopesLen)
			}

			if oidcProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", oidcProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"openid", "profile", "email"}
			for i, scope := range oidcProvider.Scopes {
				if scope != expectedScopes[i] {
					t.Errorf("Scope[%d] = %v, want %v", i, scope, expectedScopes[i])
				}
			}
		})
	}
}

func TestValidateConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		redirectURL  string
		authURL      string
		tokenURL     string
		userAPIURL   string
		wantErr      bool
		expectedErr  string
	}{
		{
			name:         "Empty client ID",
			clientID:     "",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			authURL:      "https://example.com/oauth2/auth",
			tokenURL:     "https://example.com/oauth2/token",
			userAPIURL:   "https://example.com/oauth2/userinfo",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty client secret",
			clientID:     "test-id",
			clientSecret: "",
			redirectURL:  "http://localhost:8080/callback",
			authURL:      "https://example.com/oauth2/auth",
			tokenURL:     "https://example.com/oauth2/token",
			userAPIURL:   "https://example.com/oauth2/userinfo",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "",
			authURL:      "https://example.com/oauth2/auth",
			tokenURL:     "https://example.com/oauth2/token",
			userAPIURL:   "https://example.com/oauth2/userinfo",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty auth URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			authURL:      "",
			tokenURL:     "https://example.com/oauth2/token",
			userAPIURL:   "https://example.com/oauth2/userinfo",
			wantErr:      true,
			expectedErr:  "auth url, token url and user api url are required",
		},
		{
			name:         "Empty token URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			authURL:      "https://example.com/oauth2/auth",
			tokenURL:     "",
			userAPIURL:   "https://example.com/oauth2/userinfo",
			wantErr:      true,
			expectedErr:  "auth url, token url and user api url are required",
		},
		{
			name:         "Empty user API URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			authURL:      "https://example.com/oauth2/auth",
			tokenURL:     "https://example.com/oauth2/token",
			userAPIURL:   "",
			wantErr:      true,
			expectedErr:  "auth url, token url and user api url are required",
		},
		{
			name:         "Valid configuration",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			authURL:      "https://example.com/oauth2/auth",
			tokenURL:     "https://example.com/oauth2/token",
			userAPIURL:   "https://example.com/oauth2/userinfo",
			wantErr:      false,
			expectedErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewOidcProvider()
			oidcProvider := provider.(*oidcProvider)
			oidcProvider.clientId = tt.clientID
			oidcProvider.clientSecret = tt.clientSecret
			oidcProvider.redirectUrl = tt.redirectURL
			oidcProvider.AuthUrl = tt.authURL
			oidcProvider.TokenUrl = tt.tokenURL
			oidcProvider.UserApiUrl = tt.userAPIURL

			err := oidcProvider.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.expectedErr {
				t.Errorf("ValidateConfig() error = %v, want %v", err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestFetchUser_WithMockServer(t *testing.T) {
	// Mock OIDC user data
	mockUserData := map[string]interface{}{
		"sub":                "123456789",
		"name":               "Test User",
		"preferred_username": "testuser",
		"email":              "test@example.com",
		"picture":            "https://example.com/avatar/123.jpg",
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
		expectedUser   *goauth.Credential
	}{
		{
			name: "Valid user data",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse:   mockUserData,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &goauth.Credential{
				Id:        "123456789",
				Name:      "Test User",
				Username:  "testuser",
				Email:     "test@example.com",
				AvatarUrl: "https://example.com/avatar/123.jpg",
			},
		},
		{
			name: "Invalid response format",
			token: &oauth2.Token{
				AccessToken: "invalid-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(time.Hour),
			},
			mockResponse:   "invalid json",
			mockStatusCode: http.StatusOK,
			wantErr:        true,
			expectedUser:   nil,
		},
		{
			name: "API error response",
			token: &oauth2.Token{
				AccessToken: "error-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(time.Hour),
			},
			mockResponse: map[string]interface{}{
				"error":             "invalid_token",
				"error_description": "The access token is invalid",
			},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// OIDC API gereksinimlerini kontrol et
				if r.Header.Get("Authorization") == "" {
					t.Error("Authorization header is required")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewOidcProvider()
			oidcProvider := provider.(*oidcProvider)
			oidcProvider.UserApiUrl = server.URL

			user, err := oidcProvider.FetchUser(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.expectedUser != nil {
				if user.Id != tt.expectedUser.Id {
					t.Errorf("User.Id = %v, want %v", user.Id, tt.expectedUser.Id)
				}
				if user.Name != tt.expectedUser.Name {
					t.Errorf("User.Name = %v, want %v", user.Name, tt.expectedUser.Name)
				}
				if user.Username != tt.expectedUser.Username {
					t.Errorf("User.Username = %v, want %v", user.Username, tt.expectedUser.Username)
				}
				if user.Email != tt.expectedUser.Email {
					t.Errorf("User.Email = %v, want %v", user.Email, tt.expectedUser.Email)
				}
				if user.AvatarUrl != tt.expectedUser.AvatarUrl {
					t.Errorf("User.AvatarUrl = %v, want %v", user.AvatarUrl, tt.expectedUser.AvatarUrl)
				}
			}
		})
	}
}

func TestRefreshToken_WithMockServer(t *testing.T) {
	mockTokenResponse := map[string]interface{}{
		"access_token": "new-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	mockErrorResponse := map[string]interface{}{
		"error":             "invalid_grant",
		"error_description": "The refresh token is invalid",
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		clientID       string
		clientSecret   string
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
	}{
		{
			name: "Valid refresh token",
			token: &oauth2.Token{
				AccessToken:  "old-access-token",
				TokenType:    "Bearer",
				RefreshToken: "old-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			clientID:       "test-client-id",
			clientSecret:   "test-client-secret",
			mockResponse:   mockTokenResponse,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "Empty refresh token",
			token: &oauth2.Token{
				AccessToken: "old-access-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(-time.Hour),
			},
			clientID:       "test-client-id",
			clientSecret:   "test-client-secret",
			mockResponse:   nil,
			mockStatusCode: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name: "Invalid refresh token",
			token: &oauth2.Token{
				AccessToken:  "old-access-token",
				TokenType:    "Bearer",
				RefreshToken: "invalid-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			clientID:       "test-client-id",
			clientSecret:   "test-client-secret",
			mockResponse:   mockErrorResponse,
			mockStatusCode: http.StatusBadRequest,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// OIDC API gereksinimlerini kontrol et
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("Content-Type header should be application/x-www-form-urlencoded")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			provider := NewOidcProvider()
			oidcProvider := provider.(*oidcProvider)
			oidcProvider.tokenUrl = server.URL
			oidcProvider.clientId = tt.clientID
			oidcProvider.clientSecret = tt.clientSecret

			newToken, err := oidcProvider.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && newToken != nil {
				if newToken.AccessToken != mockTokenResponse["access_token"] {
					t.Errorf("AccessToken = %v, want %v", newToken.AccessToken, mockTokenResponse["access_token"])
				}
				if newToken.TokenType != mockTokenResponse["token_type"] {
					t.Errorf("TokenType = %v, want %v", newToken.TokenType, mockTokenResponse["token_type"])
				}
			}
		})
	}
}
