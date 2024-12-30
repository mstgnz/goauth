package facebook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

func TestNewFacebookProvider_TableDriven(t *testing.T) {
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
			wantName:      "Facebook",
			wantAuthUrl:   facebook.Endpoint.AuthURL,
			wantTokenUrl:  facebook.Endpoint.TokenURL,
			wantUserApi:   "https://graph.facebook.com/v18.0/me",
			wantScopesLen: 2,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewFacebookProvider()
			fbProvider, ok := provider.(*facebookProvider)

			if !ok {
				t.Error("NewFacebookProvider should return *facebookProvider type")
			}

			if fbProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", fbProvider.DisplayName, tt.wantName)
			}

			if fbProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", fbProvider.AuthUrl, tt.wantAuthUrl)
			}

			if fbProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", fbProvider.TokenUrl, tt.wantTokenUrl)
			}

			if fbProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", fbProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(fbProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(fbProvider.Scopes), tt.wantScopesLen)
			}

			if fbProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", fbProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"email", "public_profile"}
			for i, scope := range fbProvider.Scopes {
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
			provider := NewFacebookProvider()
			fbProvider := provider.(*facebookProvider)
			fbProvider.OAuth2Config.ClientId = tt.clientID
			fbProvider.OAuth2Config.ClientSecret = tt.clientSecret
			fbProvider.OAuth2Config.RedirectUrl = tt.redirectURL

			err := fbProvider.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFetchUser_WithMockServer(t *testing.T) {
	// Mock Facebook user data
	mockUserData := map[string]interface{}{
		"id":    "123456789",
		"name":  "Test User",
		"email": "test@facebook.com",
		"picture": map[string]interface{}{
			"data": map[string]interface{}{
				"url": "https://graph.facebook.com/123456789/picture",
			},
		},
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		wantErr        bool
		expectedUser   *config.Credential
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
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Email:        "test@facebook.com",
				AvatarUrl:    "https://graph.facebook.com/123456789/picture",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewFacebookProvider()
			fbProvider := provider.(*facebookProvider)
			fbProvider.UserApiUrl = server.URL

			user, err := fbProvider.FetchUser(tt.token)
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

func TestRefreshToken_NotSupported(t *testing.T) {
	provider := NewFacebookProvider()
	token := &oauth2.Token{
		AccessToken:  "test-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(-time.Hour),
	}

	_, err := provider.RefreshToken(token)
	if err == nil {
		t.Error("RefreshToken() should return error for Facebook provider")
	}

	expectedError := "refresh token is not supported by this provider"
	if err.Error() != expectedError {
		t.Errorf("RefreshToken() error = %v, want %v", err.Error(), expectedError)
	}
}
