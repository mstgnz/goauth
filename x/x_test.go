package x

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

func TestNewXProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		wantName      string
		wantAuthUrl   string
		wantTokenUrl  string
		wantUserApi   string
		wantScopesLen int
		wantPkce      bool
	}{
		{
			name:          "Default provider creation",
			wantName:      "X (Twitter)",
			wantAuthUrl:   "https://x.com/i/oauth2/authorize",
			wantTokenUrl:  "https://api.x.com/2/oauth2/token",
			wantUserApi:   "https://api.x.com/2/users/me",
			wantScopesLen: 2,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewXProvider()
			xProvider, ok := provider.(*xProvider)

			if !ok {
				t.Error("NewXProvider should return *xProvider type")
			}

			if xProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", xProvider.DisplayName, tt.wantName)
			}

			if xProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", xProvider.AuthUrl, tt.wantAuthUrl)
			}

			if xProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", xProvider.TokenUrl, tt.wantTokenUrl)
			}

			if xProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", xProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(xProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(xProvider.Scopes), tt.wantScopesLen)
			}

			if xProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", xProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"users.read", "tweet.read"}
			for i, scope := range xProvider.Scopes {
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
		wantErr      bool
		expectedErr  string
	}{
		{
			name:         "Empty client ID",
			clientID:     "",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty client secret",
			clientID:     "test-id",
			clientSecret: "",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Valid configuration",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      false,
			expectedErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewXProvider()
			xProvider := provider.(*xProvider)
			xProvider.clientId = tt.clientID
			xProvider.clientSecret = tt.clientSecret
			xProvider.redirectUrl = tt.redirectURL

			err := xProvider.ValidateConfig()
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
	// Mock X user data
	mockUserData := map[string]interface{}{
		"data": map[string]interface{}{
			"id":       "123456789",
			"name":     "Test User",
			"username": "testuser",
		},
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
		expectedUser   *config.Credential
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
			expectedUser: &config.Credential{
				Id:       "123456789",
				Name:     "Test User",
				Username: "testuser",
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
				"errors": []interface{}{
					map[string]interface{}{
						"message": "Invalid token",
						"code":    401,
					},
				},
			},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewXProvider()
			xProvider := provider.(*xProvider)
			xProvider.UserApiUrl = server.URL

			user, err := xProvider.FetchUser(tt.token)
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
		"error_description": "Invalid refresh token",
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
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			provider := NewXProvider()
			xProvider := provider.(*xProvider)
			xProvider.tokenUrl = server.URL
			xProvider.clientId = tt.clientID
			xProvider.clientSecret = tt.clientSecret

			newToken, err := xProvider.RefreshToken(tt.token)
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
