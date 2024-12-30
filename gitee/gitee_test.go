package gitee

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

func TestNewGiteeProvider_TableDriven(t *testing.T) {
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
			wantName:      "Gitee",
			wantAuthURL:   "https://gitee.com/oauth/authorize",
			wantTokenURL:  "https://gitee.com/oauth/token",
			wantUserURL:   "https://gitee.com/api/v5/user",
			wantScopesLen: 1,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewGiteeProvider()
			giteeProvider, ok := provider.(*giteeProvider)

			if !ok {
				t.Error("NewGiteeProvider should return *giteeProvider type")
			}

			if giteeProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", giteeProvider.DisplayName, tt.wantName)
			}

			if giteeProvider.AuthUrl != tt.wantAuthURL {
				t.Errorf("AuthUrl = %v, want %v", giteeProvider.AuthUrl, tt.wantAuthURL)
			}

			if giteeProvider.TokenUrl != tt.wantTokenURL {
				t.Errorf("TokenUrl = %v, want %v", giteeProvider.TokenUrl, tt.wantTokenURL)
			}

			if giteeProvider.UserApiUrl != tt.wantUserURL {
				t.Errorf("UserApiUrl = %v, want %v", giteeProvider.UserApiUrl, tt.wantUserURL)
			}

			if len(giteeProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(giteeProvider.Scopes), tt.wantScopesLen)
			}

			if giteeProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", giteeProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"user_info"}
			for i, scope := range giteeProvider.Scopes {
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
			provider := NewGiteeProvider()
			giteeProvider := provider.(*giteeProvider)
			giteeProvider.ClientId = tt.clientID
			giteeProvider.ClientSecret = tt.clientSecret
			giteeProvider.RedirectUrl = tt.redirectURL

			err := giteeProvider.ValidateConfig()
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
		"id":         123456789,
		"login":      "testuser",
		"name":       "Test User",
		"email":      "test@example.com",
		"avatar_url": "https://example.com/avatar.jpg",
	}

	mockEmailsData := []map[string]interface{}{
		{
			"email": "primary@example.com",
			"state": "confirmed",
			"scope": []string{"primary"},
		},
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		mockEmails     interface{}
		mockStatusCode int
		wantErr        bool
		expectedUser   *config.Credential
	}{
		{
			name: "Valid user data with public email",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse:   mockUserData,
			mockEmails:     mockEmailsData,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "test@example.com",
				AvatarUrl:    "https://example.com/avatar.jpg",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "Valid user data with private email",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse: map[string]interface{}{
				"id":         123456789,
				"login":      "testuser",
				"name":       "Test User",
				"avatar_url": "https://example.com/avatar.jpg",
			},
			mockEmails:     mockEmailsData,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "primary@example.com",
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
			mockEmails:     nil,
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
				"message": "Invalid access token",
			},
			mockEmails:     nil,
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock user info endpoint
			userServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Gitee API gereksinimlerini kontrol et
				if r.Header.Get("Authorization") == "" {
					t.Error("Authorization header is required")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer userServer.Close()

			// Mock emails endpoint
			emailServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tt.mockEmails != nil {
					json.NewEncoder(w).Encode(tt.mockEmails)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			defer emailServer.Close()

			provider := NewGiteeProvider()
			giteeProvider := provider.(*giteeProvider)
			giteeProvider.UserApiUrl = userServer.URL
			giteeProvider.EmailApiUrl = emailServer.URL

			user, err := giteeProvider.FetchUser(tt.token)
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
				// Gitee OAuth2 token endpoint gereksinimlerini kontrol et
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

			provider := NewGiteeProvider()
			giteeProvider := provider.(*giteeProvider)
			giteeProvider.TokenUrl = server.URL
			giteeProvider.ClientId = tt.clientID
			giteeProvider.ClientSecret = tt.clientSecret

			newToken, err := giteeProvider.RefreshToken(tt.token)
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
