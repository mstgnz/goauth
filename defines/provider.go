package goauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// Provider defines a common interface for OAuth2 client implementations.
// It abstracts the necessary methods and properties required for OAuth2 authentication.
type Provider interface {
	// GetContext retrieves the context associated with the provider (if any).
	GetContext() context.Context

	// SetContext assigns the specified context to the current provider.
	SetContext(ctx context.Context)

	// GetDisplayName usually returns the official name of the provider as written by the service.
	// It can be used directly in user interfaces.
	GetDisplayName() string

	// SetDisplayName sets the display name of the OAuth2 provider.
	SetDisplayName(displayName string)

	// GetClientId retrieves the client ID associated with the provider.
	GetClientId() string

	// SetClientId sets the client ID of the OAuth2 provider.
	SetClientId(clientId string)

	// GetClientSecret retrieves the client secret associated with the provider.
	GetClientSecret() string

	// SetClientSecret sets the client secret of the OAuth2 provider.
	SetClientSecret(secret string)

	// GetRedirectUrl retrieves the URL where the user is redirected after OAuth2 authentication.
	GetRedirectUrl() string

	// SetRedirectUrl sets the redirect URL of the OAuth2 provider.
	SetRedirectUrl(url string)

	// GetAuthUrl retrieves the authorization service URL of the OAuth2 provider.
	GetAuthUrl() string

	// SetAuthUrl sets the authorization service URL of the OAuth2 provider.
	SetAuthUrl(url string)

	// GetTokenUrl retrieves the token exchange service URL of the OAuth2 provider.
	GetTokenUrl() string

	// SetTokenUrl sets the token exchange service URL of the OAuth2 provider.
	SetTokenUrl(url string)

	// GetUserApiUrl retrieves the user information API URL of the OAuth2 provider.
	GetUserApiUrl() string

	// SetUserApiUrl sets the user information API URL of the OAuth2 provider.
	SetUserApiUrl(url string)

	// GetScopes retrieves the access permissions that will be requested during the OAuth2 flow.
	GetScopes() []string

	// SetScopes sets the access permissions that will be requested during the OAuth2 flow.
	SetScopes(scopes []string)

	// GetPKCE retrieves whether the provider can use the PKCE (Proof Key for Code Exchange) flow.
	GetPKCE() bool

	// SetPKCE toggles the state of PKCE flow for the OAuth2 provider.
	SetPKCE(enable bool)

	// Client returns an HTTP client configured with the provided OAuth2 token.
	Client(token *oauth2.Token) *http.Client

	// BuildAuthUrl returns the URL to the OAuth2 provider's consent page, asking for explicit permissions.
	BuildAuthUrl(state string, opts ...oauth2.AuthCodeOption) string

	// FetchToken converts an authorization code to an OAuth2 token.
	FetchToken(code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)

	// FetchRawData requests and marshals the raw OAuth user API response.
	FetchRawData(token *oauth2.Token) ([]byte, error)

	// FetchUser is similar to FetchRawData but normalizes and marshals the user API response into a standardized Credential struct.
	FetchUser(token *oauth2.Token) (user *Credential, err error)
}
