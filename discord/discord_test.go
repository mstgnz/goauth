package discord

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
)

func TestNewDiscordProvider_TableDriven(t *testing.T) {
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
			wantName:      "Discord",
			wantAuthUrl:   "https://discord.com/api/oauth2/authorize",
			wantTokenUrl:  "https://discord.com/api/oauth2/token",
			wantUserApi:   "https://discord.com/api/users/@me",
			wantScopesLen: 2,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewDiscordProvider()
			discordProvider, ok := provider.(*discordProvider)

			if !ok {
				t.Error("NewDiscordProvider should return *discordProvider type")
			}

			if discordProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", discordProvider.DisplayName, tt.wantName)
			}

			if discordProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", discordProvider.AuthUrl, tt.wantAuthUrl)
			}

			if discordProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", discordProvider.TokenUrl, tt.wantTokenUrl)
			}

			if discordProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", discordProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(discordProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(discordProvider.Scopes), tt.wantScopesLen)
			}

			if discordProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", discordProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"identify", "email"}
			for i, scope := range discordProvider.Scopes {
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
	}{
		{
			name:         "Empty client ID",
			clientID:     "",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
		},
		{
			name:         "Empty client secret",
			clientID:     "test-id",
			clientSecret: "",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "",
			wantErr:      true,
		},
		{
			name:         "Valid configuration",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewDiscordProvider()
			discordProvider := provider.(*discordProvider)
			discordProvider.OAuth2Config.ClientId = tt.clientID
			discordProvider.OAuth2Config.ClientSecret = tt.clientSecret
			discordProvider.OAuth2Config.RedirectUrl = tt.redirectURL

			err := discordProvider.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFetchUser_WithMockServer(t *testing.T) {
	// Mock Discord user data
	mockUserData := map[string]interface{}{
		"id":            "123456789",
		"username":      "TestUser",
		"discriminator": "1234",
		"avatar":        "abc123",
		"email":         "test@discord.com",
		"verified":      true,
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		wantErr        bool
		expectedUser   *goauth.Credential
		mockStatusCode int
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
				Name:         "TestUser#1234",
				Username:     "TestUser",
				Email:        "test@discord.com",
				AvatarUrl:    "https://cdn.discordapp.com/avatars/123456789/abc123.png",
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
			mockResponse:   map[string]interface{}{"error": "Invalid token"},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
		{
			name: "Unverified user",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse: map[string]interface{}{
				"id":            "123456789",
				"username":      "TestUser",
				"discriminator": "1234",
				"avatar":        "abc123",
				"email":         "test@discord.com",
				"verified":      false,
			},
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &goauth.Credential{
				Id:           "123456789",
				Name:         "TestUser#1234",
				Username:     "TestUser",
				Email:        "",
				AvatarUrl:    "https://cdn.discordapp.com/avatars/123456789/abc123.png",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
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

			provider := NewDiscordProvider()
			discordProvider := provider.(*discordProvider)
			discordProvider.UserApiUrl = server.URL

			user, err := discordProvider.FetchUser(tt.token)
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

func TestRefreshToken_TableDriven(t *testing.T) {
	// Mock token yanıtı
	mockTokenResponse := map[string]interface{}{
		"access_token":  "new-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "new-refresh-token",
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
	}{
		{
			name: "Missing refresh token",
			token: &oauth2.Token{
				AccessToken: "test-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(-time.Hour),
			},
			mockResponse:   nil,
			mockStatusCode: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name: "Valid refresh token",
			token: &oauth2.Token{
				AccessToken:  "test-token",
				TokenType:    "Bearer",
				RefreshToken: "test-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			mockResponse:   mockTokenResponse,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "API error response",
			token: &oauth2.Token{
				AccessToken:  "test-token",
				TokenType:    "Bearer",
				RefreshToken: "invalid-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			mockResponse: map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid refresh token",
			},
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

			provider := NewDiscordProvider()
			discordProvider := provider.(*discordProvider)
			discordProvider.OAuth2Config.ClientId = "test-client-id"
			discordProvider.OAuth2Config.ClientSecret = "test-client-secret"
			discordProvider.TokenUrl = server.URL

			newToken, err := discordProvider.RefreshToken(tt.token)
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
