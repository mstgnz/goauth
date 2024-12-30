package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func TestNewGithubProvider_TableDriven(t *testing.T) {
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
			wantName:      "GitHub",
			wantAuthUrl:   github.Endpoint.AuthURL,
			wantTokenUrl:  github.Endpoint.TokenURL,
			wantUserApi:   "https://api.github.com/user",
			wantScopesLen: 2,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewGithubProvider()
			ghProvider, ok := provider.(*gitHubProvider)

			if !ok {
				t.Error("NewGithubProvider should return *gitHubProvider type")
			}

			if ghProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", ghProvider.DisplayName, tt.wantName)
			}

			if ghProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", ghProvider.AuthUrl, tt.wantAuthUrl)
			}

			if ghProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", ghProvider.TokenUrl, tt.wantTokenUrl)
			}

			if ghProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", ghProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(ghProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(ghProvider.Scopes), tt.wantScopesLen)
			}

			if ghProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", ghProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"read:user", "user:email"}
			for i, scope := range ghProvider.Scopes {
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
			provider := NewGithubProvider()
			ghProvider := provider.(*gitHubProvider)
			ghProvider.OAuth2Config.ClientId = tt.clientID
			ghProvider.OAuth2Config.ClientSecret = tt.clientSecret
			ghProvider.OAuth2Config.RedirectUrl = tt.redirectURL

			err := ghProvider.ValidateConfig()
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
	// Mock GitHub user data
	mockUserData := map[string]interface{}{
		"login":      "testuser",
		"id":         123456789,
		"name":       "Test User",
		"email":      "test@github.com",
		"avatar_url": "https://github.com/images/test.png",
	}

	// Mock email data
	mockEmailData := []map[string]interface{}{
		{
			"email":    "primary@github.com",
			"verified": true,
			"primary":  true,
		},
		{
			"email":    "secondary@github.com",
			"verified": true,
			"primary":  false,
		},
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockUserData   interface{}
		mockEmailData  interface{}
		userStatus     int
		emailStatus    int
		wantErr        bool
		expectedUser   *config.Credential
		checkEmailCall bool
	}{
		{
			name: "Valid user data with email",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockUserData:   mockUserData,
			mockEmailData:  nil,
			userStatus:     http.StatusOK,
			emailStatus:    http.StatusOK,
			wantErr:        false,
			checkEmailCall: false,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "test@github.com",
				AvatarUrl:    "https://github.com/images/test.png",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "User with private email",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockUserData: map[string]interface{}{
				"login":      "testuser",
				"id":         123456789,
				"name":       "Test User",
				"email":      "",
				"avatar_url": "https://github.com/images/test.png",
			},
			mockEmailData:  mockEmailData,
			userStatus:     http.StatusOK,
			emailStatus:    http.StatusOK,
			wantErr:        false,
			checkEmailCall: true,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "primary@github.com",
				AvatarUrl:    "https://github.com/images/test.png",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "Email API unauthorized",
			token: &oauth2.Token{
				AccessToken: "valid-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(time.Hour),
			},
			mockUserData: map[string]interface{}{
				"login":      "testuser",
				"id":         123456789,
				"name":       "Test User",
				"email":      "",
				"avatar_url": "https://github.com/images/test.png",
			},
			mockEmailData:  nil,
			userStatus:     http.StatusOK,
			emailStatus:    http.StatusUnauthorized,
			wantErr:        false,
			checkEmailCall: true,
			expectedUser: &config.Credential{
				Id:        "123456789",
				Name:      "Test User",
				Username:  "testuser",
				Email:     "",
				AvatarUrl: "https://github.com/images/test.png",
			},
		},
		{
			name: "Invalid user response",
			token: &oauth2.Token{
				AccessToken: "invalid-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(time.Hour),
			},
			mockUserData:   "invalid json",
			mockEmailData:  nil,
			userStatus:     http.StatusOK,
			emailStatus:    http.StatusOK,
			wantErr:        true,
			checkEmailCall: false,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emailCallCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.URL.Path == "/user/emails" {
					emailCallCount++
					w.WriteHeader(tt.emailStatus)
					if tt.mockEmailData != nil {
						json.NewEncoder(w).Encode(tt.mockEmailData)
					}
					return
				}

				w.WriteHeader(tt.userStatus)
				json.NewEncoder(w).Encode(tt.mockUserData)
			}))
			defer server.Close()

			provider := NewGithubProvider()
			ghProvider := provider.(*gitHubProvider)
			ghProvider.UserApiUrl = server.URL + "/user"

			user, err := ghProvider.FetchUser(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkEmailCall && emailCallCount == 0 {
				t.Error("Expected email API call, but none was made")
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

func TestRefreshToken_NotSupported(t *testing.T) {
	provider := NewGithubProvider()
	token := &oauth2.Token{
		AccessToken:  "test-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(-time.Hour),
	}

	_, err := provider.RefreshToken(token)
	if err == nil {
		t.Error("RefreshToken() should return error for GitHub provider")
	}

	expectedError := "GitHub does not support refresh tokens"
	if err.Error() != expectedError {
		t.Errorf("RefreshToken() error = %v, want %v", err.Error(), expectedError)
	}
}
