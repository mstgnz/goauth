package discord

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewDiscordProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
		wantAuth string
		wantLen  int
	}{
		{
			name:     "Default provider creation",
			wantName: "Discord",
			wantAuth: "https://discord.com/api/oauth2/authorize",
			wantLen:  2,
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

			if discordProvider.AuthUrl != tt.wantAuth {
				t.Errorf("AuthUrl = %v, want %v", discordProvider.AuthUrl, tt.wantAuth)
			}

			if len(discordProvider.Scopes) != tt.wantLen {
				t.Errorf("Scopes length = %v, want %v", len(discordProvider.Scopes), tt.wantLen)
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
			clientSecret: "",
			redirectURL:  "",
			wantErr:      true,
		},
		{
			name:         "Empty client secret",
			clientID:     "test-client-id",
			clientSecret: "",
			redirectURL:  "",
			wantErr:      true,
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			redirectURL:  "",
			wantErr:      true,
		},
		{
			name:         "Valid configuration",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
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

	// Mock sunucu oluştur
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockUserData)
	}))
	defer server.Close()

	tests := []struct {
		name    string
		token   *oauth2.Token
		wantErr bool
	}{
		{
			name: "Valid token",
			token: &oauth2.Token{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				RefreshToken: "test-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			},
			wantErr: false,
		},
		{
			name: "Expired token",
			token: &oauth2.Token{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				RefreshToken: "test-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewDiscordProvider()
			discordProvider := provider.(*discordProvider)
			discordProvider.UserApiUrl = server.URL

			user, err := discordProvider.FetchUser(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && user != nil {
				if user.Id != mockUserData["id"] {
					t.Errorf("User ID = %v, want %v", user.Id, mockUserData["id"])
				}
				if user.Username != mockUserData["username"] {
					t.Errorf("Username = %v, want %v", user.Username, mockUserData["username"])
				}
				if user.Email != mockUserData["email"] {
					t.Errorf("Email = %v, want %v", user.Email, mockUserData["email"])
				}
				expectedAvatarUrl := "https://cdn.discordapp.com/avatars/123456789/abc123.png"
				if user.AvatarUrl != expectedAvatarUrl {
					t.Errorf("AvatarUrl = %v, want %v", user.AvatarUrl, expectedAvatarUrl)
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockTokenResponse)
	}))
	defer server.Close()

	tests := []struct {
		name    string
		token   *oauth2.Token
		wantErr bool
	}{
		{
			name: "Valid refresh token",
			token: &oauth2.Token{
				AccessToken:  "old-access-token",
				TokenType:    "Bearer",
				RefreshToken: "old-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			wantErr: false,
		},
		{
			name: "Empty refresh token",
			token: &oauth2.Token{
				AccessToken: "old-access-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(-time.Hour),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewDiscordProvider()
			discordProvider := provider.(*discordProvider)
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
