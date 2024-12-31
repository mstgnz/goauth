package twitch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
)

func TestNewTwitchProvider_TableDriven(t *testing.T) {
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
			wantName:      "Twitch",
			wantAuthUrl:   "https://id.twitch.tv/oauth2/authorize",
			wantTokenUrl:  "https://id.twitch.tv/oauth2/token",
			wantUserApi:   "https://api.twitch.tv/helix/users",
			wantScopesLen: 1,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewTwitchProvider()
			twitchProvider, ok := provider.(*twitchProvider)

			if !ok {
				t.Error("NewTwitchProvider should return *twitchProvider type")
			}

			if twitchProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", twitchProvider.DisplayName, tt.wantName)
			}

			if twitchProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", twitchProvider.AuthUrl, tt.wantAuthUrl)
			}

			if twitchProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", twitchProvider.TokenUrl, tt.wantTokenUrl)
			}

			if twitchProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", twitchProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(twitchProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(twitchProvider.Scopes), tt.wantScopesLen)
			}

			if twitchProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", twitchProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"user:read:email"}
			for i, scope := range twitchProvider.Scopes {
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
			expectedErr:  "client ID is required",
		},
		{
			name:         "Empty client secret",
			clientID:     "test-id",
			clientSecret: "",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
			expectedErr:  "client secret is required",
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "",
			wantErr:      true,
			expectedErr:  "redirect URL is required",
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
			provider := NewTwitchProvider()
			twitchProvider := provider.(*twitchProvider)
			twitchProvider.ClientId = tt.clientID
			twitchProvider.ClientSecret = tt.clientSecret
			twitchProvider.RedirectUrl = tt.redirectURL

			err := twitchProvider.ValidateConfig()
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
	// Mock Twitch user data
	mockUserData := map[string]interface{}{
		"data": []interface{}{
			map[string]interface{}{
				"id":                "123456789",
				"login":             "testuser",
				"display_name":      "Test User",
				"email":             "test@twitch.tv",
				"profile_image_url": "https://static-cdn.jtvnw.net/user-default-pictures-uv/123.jpg",
			},
		},
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
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "test@twitch.tv",
				AvatarUrl:    "https://static-cdn.jtvnw.net/user-default-pictures-uv/123.jpg",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
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
				"error":   "Unauthorized",
				"status":  401,
				"message": "Invalid OAuth token",
			},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Twitch API gereksinimlerini kontrol et
				if r.Header.Get("Client-ID") == "" {
					t.Error("Client-ID header is required")
				}
				if r.Header.Get("Authorization") == "" {
					t.Error("Authorization header is required")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewTwitchProvider()
			twitchProvider := provider.(*twitchProvider)
			twitchProvider.UserApiUrl = server.URL
			twitchProvider.ClientId = "test-client-id"

			user, err := twitchProvider.FetchUser(tt.token)
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
				if user.AccessToken != tt.expectedUser.AccessToken {
					t.Errorf("User.AccessToken = %v, want %v", user.AccessToken, tt.expectedUser.AccessToken)
				}
				if user.RefreshToken != tt.expectedUser.RefreshToken {
					t.Errorf("User.RefreshToken = %v, want %v", user.RefreshToken, tt.expectedUser.RefreshToken)
				}
			}
		})
	}
}

func TestRefreshToken_WithMockServer(t *testing.T) {
	mockTokenResponse := map[string]interface{}{
		"access_token":  "new-access-token",
		"refresh_token": "new-refresh-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
	}

	mockErrorResponse := map[string]interface{}{
		"error":   "invalid_grant",
		"message": "Invalid refresh token",
		"status":  400,
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
				// Twitch API gereksinimlerini kontrol et
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

			provider := NewTwitchProvider()
			twitchProvider := provider.(*twitchProvider)
			twitchProvider.TokenUrl = server.URL
			twitchProvider.ClientId = tt.clientID
			twitchProvider.ClientSecret = tt.clientSecret

			newToken, err := twitchProvider.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && newToken != nil {
				if newToken.AccessToken != mockTokenResponse["access_token"] {
					t.Errorf("AccessToken = %v, want %v", newToken.AccessToken, mockTokenResponse["access_token"])
				}
				if newToken.RefreshToken != mockTokenResponse["refresh_token"] {
					t.Errorf("RefreshToken = %v, want %v", newToken.RefreshToken, mockTokenResponse["refresh_token"])
				}
				if newToken.TokenType != mockTokenResponse["token_type"] {
					t.Errorf("TokenType = %v, want %v", newToken.TokenType, mockTokenResponse["token_type"])
				}
			}
		})
	}
}
