package spotify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

func TestNewSpotifyProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		wantName      string
		wantAuthURL   string
		wantTokenURL  string
		wantUserURL   string
		wantScopesLen int
		wantPkce      bool
	}{
		{
			name:          "Default provider creation",
			wantName:      "Spotify",
			wantAuthURL:   "https://accounts.spotify.com/authorize",
			wantTokenURL:  "https://accounts.spotify.com/api/token",
			wantUserURL:   "https://api.spotify.com/v1/me",
			wantScopesLen: 2,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewSpotifyProvider()
			spotifyProvider, ok := provider.(*spotifyProvider)

			if !ok {
				t.Error("NewSpotifyProvider should return *spotifyProvider type")
			}

			if spotifyProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", spotifyProvider.DisplayName, tt.wantName)
			}

			if spotifyProvider.AuthUrl != tt.wantAuthURL {
				t.Errorf("AuthUrl = %v, want %v", spotifyProvider.AuthUrl, tt.wantAuthURL)
			}

			if spotifyProvider.TokenUrl != tt.wantTokenURL {
				t.Errorf("TokenUrl = %v, want %v", spotifyProvider.TokenUrl, tt.wantTokenURL)
			}

			if spotifyProvider.UserApiUrl != tt.wantUserURL {
				t.Errorf("UserApiUrl = %v, want %v", spotifyProvider.UserApiUrl, tt.wantUserURL)
			}

			if len(spotifyProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(spotifyProvider.Scopes), tt.wantScopesLen)
			}

			if spotifyProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", spotifyProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"user-read-email", "user-read-private"}
			for i, scope := range spotifyProvider.Scopes {
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
			provider := NewSpotifyProvider()
			spotifyProvider := provider.(*spotifyProvider)
			spotifyProvider.ClientId = tt.clientID
			spotifyProvider.ClientSecret = tt.clientSecret
			spotifyProvider.RedirectUrl = tt.redirectURL

			err := spotifyProvider.ValidateConfig()
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
	mockUserData := map[string]interface{}{
		"id":           "123456789",
		"display_name": "Test User",
		"images": []map[string]interface{}{
			{
				"url": "https://example.com/avatar.jpg",
			},
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
				Id:           "123456789",
				Name:         "Test User",
				AvatarUrl:    "https://example.com/avatar.jpg",
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
				"error": map[string]interface{}{
					"status":  401,
					"message": "Invalid access token",
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
				// Spotify API gereksinimlerini kontrol et
				if r.Header.Get("Authorization") == "" {
					t.Error("Authorization header is required")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewSpotifyProvider()
			spotifyProvider := provider.(*spotifyProvider)
			spotifyProvider.UserApiUrl = server.URL

			user, err := spotifyProvider.FetchUser(tt.token)
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
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "new-refresh-token",
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
				// Spotify OAuth2 token endpoint gereksinimlerini kontrol et
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

			provider := NewSpotifyProvider()
			spotifyProvider := provider.(*spotifyProvider)
			spotifyProvider.TokenUrl = server.URL
			spotifyProvider.ClientId = tt.clientID
			spotifyProvider.ClientSecret = tt.clientSecret

			newToken, err := spotifyProvider.RefreshToken(tt.token)
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
			}
		})
	}
}
