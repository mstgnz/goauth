package apple

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Test için gerçek bir private key oluştur
var (
	testPrivateKey    string
	testPrivateKeyRSA *rsa.PrivateKey
	testKID           = "test-kid-123"
	testTeamID        = "test-team-id"
)

func init() {
	var err error
	// RSA private key oluştur
	testPrivateKeyRSA, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("private key oluşturulamadı: %v", err))
	}

	// Private key'i PEM formatına dönüştür
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(testPrivateKeyRSA)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	testPrivateKey = string(privateKeyPEM)
}

// Mock JWK yanıtı oluştur
func createMockJWK(kid string) map[string]interface{} {
	// Public key parametrelerini base64 formatına dönüştür
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(testPrivateKeyRSA.PublicKey.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(testPrivateKeyRSA.PublicKey.N.Bytes())

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}
}

// Test JWT token oluştur
func createTestJWT(kid string) string {
	claims := jwt.MapClaims{
		"sub":            "test-user-id",
		"email":          "test@example.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"iss":            "https://appleid.apple.com",
		"aud":            "test-client-id",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedToken, err := token.SignedString(testPrivateKeyRSA)
	if err != nil {
		panic(fmt.Sprintf("JWT token oluşturulamadı: %v", err))
	}

	return signedToken
}

func TestNewAppleProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
		wantAuth string
		wantLen  int
	}{
		{
			name:     "Default provider creation",
			wantName: "Apple",
			wantAuth: "https://appleid.apple.com/auth/authorize",
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewAppleProvider()
			appleProvider, ok := provider.(*appleProvider)

			if !ok {
				t.Error("NewAppleProvider should return *appleProvider type")
			}

			if appleProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", appleProvider.DisplayName, tt.wantName)
			}

			if appleProvider.AuthUrl != tt.wantAuth {
				t.Errorf("AuthUrl = %v, want %v", appleProvider.AuthUrl, tt.wantAuth)
			}

			if len(appleProvider.Scopes) != tt.wantLen {
				t.Errorf("Scopes length = %v, want %v", len(appleProvider.Scopes), tt.wantLen)
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
			name:         "Invalid private key format",
			clientID:     "test-client-id",
			clientSecret: "invalid-private-key",
			redirectURL:  "",
			wantErr:      true,
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-client-id",
			clientSecret: testPrivateKey,
			redirectURL:  "",
			wantErr:      true,
		},
		{
			name:         "Valid configuration",
			clientID:     "test-client-id",
			clientSecret: testPrivateKey,
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewAppleProvider()
			appleProvider := provider.(*appleProvider)
			appleProvider.OAuth2Config.ClientId = tt.clientID
			appleProvider.OAuth2Config.ClientSecret = tt.clientSecret
			appleProvider.OAuth2Config.RedirectUrl = tt.redirectURL

			err := appleProvider.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFetchUser_WithMockServer(t *testing.T) {
	// Mock sunucu oluştur
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/keys":
			// JWK yanıtını simüle et
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createMockJWK(testKID))
		case "/auth/token":
			// Token endpoint yanıtını simüle et
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "test-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "test-refresh-token",
				"id_token":      createTestJWT(testKID),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tests := []struct {
		name    string
		token   *oauth2.Token
		wantErr bool
	}{
		{
			name: "Invalid token without id_token",
			token: &oauth2.Token{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				RefreshToken: "test-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			},
			wantErr: true,
		},
		{
			name: "Valid token with id_token",
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
			provider := NewAppleProvider()
			appleProvider := provider.(*appleProvider)
			appleProvider.jwkUrl = server.URL + "/auth/keys"
			appleProvider.TokenUrl = server.URL + "/auth/token"

			// Valid token case için id_token ekle
			if tt.name == "Valid token with id_token" {
				tt.token = tt.token.WithExtra(map[string]interface{}{
					"id_token": createTestJWT(testKID),
				})
			}

			user, err := appleProvider.FetchUser(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && user != nil {
				// Başarılı durumda kullanıcı bilgilerini kontrol et
				if user.Email != "test@example.com" {
					t.Errorf("FetchUser() email = %v, want %v", user.Email, "test@example.com")
				}
				if user.Id != "test-user-id" {
					t.Errorf("FetchUser() id = %v, want %v", user.Id, "test-user-id")
				}
			}
		})
	}
}

func TestRefreshToken_TableDriven(t *testing.T) {
	// Mock sunucu oluştur
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.URL.Path != "/auth/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Form verilerini kontrol et
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("refresh_token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Başarılı yanıt
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh-token",
		})
	}))
	defer server.Close()

	tests := []struct {
		name         string
		token        *oauth2.Token
		clientSecret string
		wantErr      bool
	}{
		{
			name: "Empty refresh token",
			token: &oauth2.Token{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				RefreshToken: "",
				Expiry:       time.Now().Add(time.Hour),
			},
			clientSecret: testPrivateKey,
			wantErr:      true,
		},
		{
			name: "Invalid client secret",
			token: &oauth2.Token{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				RefreshToken: "test-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			},
			clientSecret: "invalid-key",
			wantErr:      true,
		},
		{
			name: "Valid refresh token",
			token: &oauth2.Token{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				RefreshToken: "test-refresh-token",
				Expiry:       time.Now().Add(-time.Hour), // Süresi dolmuş token
			},
			clientSecret: testPrivateKey,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewAppleProvider()
			appleProvider := provider.(*appleProvider)
			appleProvider.OAuth2Config.ClientSecret = tt.clientSecret
			appleProvider.TokenUrl = server.URL + "/auth/token"

			newToken, err := appleProvider.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && newToken != nil {
				// Yeni token'ı kontrol et
				if newToken.AccessToken != "new-access-token" {
					t.Errorf("RefreshToken() access token = %v, want %v", newToken.AccessToken, "new-access-token")
				}
				if newToken.RefreshToken != "new-refresh-token" {
					t.Errorf("RefreshToken() refresh token = %v, want %v", newToken.RefreshToken, "new-refresh-token")
				}
			}
		})
	}
}

func TestGenerateClientSecret_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		teamID       string
		keyID        string
		clientSecret string
		wantErr      bool
	}{
		{
			name:         "Invalid private key",
			clientID:     "test-client-id",
			teamID:       testTeamID,
			keyID:        "test-key-id",
			clientSecret: "invalid-key",
			wantErr:      true,
		},
		{
			name:         "Valid private key format but invalid content",
			clientID:     "test-client-id",
			teamID:       testTeamID,
			keyID:        "test-key-id",
			clientSecret: "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			wantErr:      true,
		},
		{
			name:         "Valid configuration",
			clientID:     "test-client-id",
			teamID:       testTeamID,
			keyID:        "test-key-id",
			clientSecret: testPrivateKey,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewAppleProvider()
			appleProvider := provider.(*appleProvider)
			appleProvider.OAuth2Config.ClientId = tt.clientID
			appleProvider.OAuth2Config.ClientSecret = tt.clientSecret
			appleProvider.OAuth2Config.TeamID = tt.teamID

			secret, err := appleProvider.generateClientSecret()
			if (err != nil) != tt.wantErr {
				t.Errorf("generateClientSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && secret != "" {
				// JWT formatını kontrol et
				token, err := jwt.Parse(secret, func(token *jwt.Token) (interface{}, error) {
					return testPrivateKeyRSA.Public(), nil
				})

				if err != nil {
					t.Errorf("generateClientSecret() generated invalid JWT: %v", err)
					return
				}

				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					// JWT içeriğini kontrol et
					if claims["iss"] != tt.teamID {
						t.Errorf("generateClientSecret() iss = %v, want %v", claims["iss"], tt.teamID)
					}
					if claims["sub"] != tt.clientID {
						t.Errorf("generateClientSecret() sub = %v, want %v", claims["sub"], tt.clientID)
					}
				}
			}
		})
	}
}

func TestParseAndVerifyIdToken_TableDriven(t *testing.T) {
	// Mock JWK sunucusu
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(createMockJWK(testKID))
	}))
	defer server.Close()

	tests := []struct {
		name    string
		idToken string
		wantErr bool
	}{
		{
			name:    "Empty token",
			idToken: "",
			wantErr: true,
		},
		{
			name:    "Invalid token format",
			idToken: "invalid-token",
			wantErr: true,
		},
		{
			name:    "Malformed JWT",
			idToken: "header.payload.signature",
			wantErr: true,
		},
		{
			name:    "Valid JWT token",
			idToken: createTestJWT(testKID),
			wantErr: false,
		},
		{
			name:    "JWT with wrong kid",
			idToken: createTestJWT("wrong-kid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewAppleProvider()
			appleProvider := provider.(*appleProvider)
			appleProvider.jwkUrl = server.URL

			claims, err := appleProvider.parseAndVerifyIdToken(tt.idToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAndVerifyIdToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && claims != nil {
				// Token içeriğini kontrol et
				if claims["email"] != "test@example.com" {
					t.Errorf("parseAndVerifyIdToken() email = %v, want %v", claims["email"], "test@example.com")
				}
				if claims["sub"] != "test-user-id" {
					t.Errorf("parseAndVerifyIdToken() sub = %v, want %v", claims["sub"], "test-user-id")
				}
			}
		})
	}
}
