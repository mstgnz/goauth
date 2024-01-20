package goauth

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// OAuth2Config encapsulates common attributes and behaviors shared among OAuth2 providers.
// It serves as a foundation for creating specific provider implementations.
type OAuth2Config struct {
	Ctx          context.Context // Context for the provider operations.
	DisplayName  string          // Human-readable name of the OAuth2 provider.
	ClientId     string          // Client ID associated with the OAuth2 provider.
	ClientSecret string          // Client secret associated with the OAuth2 provider.
	RedirectUrl  string          // Redirect URL to complete the OAuth2 flow.
	AuthUrl      string          // URL for the OAuth2 authorization service.
	TokenUrl     string          // URL for the OAuth2 token exchange service.
	UserApiUrl   string          // URL for fetching user information from the provider.
	Scopes       []string        // Requested access permissions from the provider.
	Pkce         bool            // Indicates whether the provider supports the PKCE flow.
}

// GetContext retrieves the context associated with the OAuth2 provider.
// It implements the GetContext() method of the Provider interface.
// The context is used to perform operations within the scope of the provider.
func (oc *OAuth2Config) GetContext() context.Context {
	return oc.Ctx
}

// SetContext assigns the specified context to the OAuth2 provider.
// It implements the SetContext() method of the Provider interface.
// The context is crucial for performing operations within the scope of the provider.
func (oc *OAuth2Config) SetContext(ctx context.Context) {
	oc.Ctx = ctx
}

// GetDisplayName retrieves the human-readable name of the OAuth2 provider.
// It implements the GetDisplayName() method of the Provider interface.
// The display name is typically used for UI or identification purposes.
func (oc *OAuth2Config) GetDisplayName() string {
	return oc.DisplayName
}

// SetDisplayName sets the human-readable name of the OAuth2 provider.
// It implements the SetDisplayName() method of the Provider interface.
// The display name is typically used for UI or identification purposes.
func (oc *OAuth2Config) SetDisplayName(displayName string) {
	oc.DisplayName = displayName
}

// GetClientId retrieves the client ID associated with the OAuth2 provider.
// It implements the GetClientId() method of the Provider interface.
// The client ID is used to uniquely identify the application associated with the provider.
func (oc *OAuth2Config) GetClientId() string {
	return oc.ClientId
}

// SetClientId assigns the specified client ID to the OAuth2 provider.
// It implements the SetClientId() method of the Provider interface.
// The client ID is used to uniquely identify the application associated with the provider.
func (oc *OAuth2Config) SetClientId(clientId string) {
	oc.ClientId = clientId
}

// GetClientSecret retrieves the client secret associated with the OAuth2 provider.
// It implements the GetClientSecret() method of the Provider interface.
// The client secret is used for secure communication between the application and the provider.
func (oc *OAuth2Config) GetClientSecret() string {
	return oc.ClientSecret
}

// SetClientSecret assigns the specified client secret to the OAuth2 provider.
// It implements the SetClientSecret() method of the Provider interface.
// The client secret is used for secure communication between the application and the provider.
func (oc *OAuth2Config) SetClientSecret(secret string) {
	oc.ClientSecret = secret
}

// GetRedirectUrl retrieves the redirect URL associated with the OAuth2 provider.
// It implements the GetRedirectUrl() method of the Provider interface.
// The redirect URL is where the user is redirected after completing the OAuth2 flow.
func (oc *OAuth2Config) GetRedirectUrl() string {
	return oc.RedirectUrl
}

// SetRedirectUrl assigns the specified redirect URL to the OAuth2 provider.
// It implements the SetRedirectUrl() method of the Provider interface.
// The redirect URL is where the user is redirected after completing the OAuth2 flow.
func (oc *OAuth2Config) SetRedirectUrl(url string) {
	oc.RedirectUrl = url
}

// GetAuthUrl retrieves the OAuth2 authorization service URL associated with the provider.
// It implements the GetAuthUrl() method of the Provider interface.
// The authorization service URL is where the user grants permission for the OAuth2 flow.
func (oc *OAuth2Config) GetAuthUrl() string {
	return oc.AuthUrl
}

// SetAuthUrl assigns the specified OAuth2 authorization service URL to the OAuth2 provider.
// It implements the SetAuthUrl() method of the Provider interface.
// The authorization service URL is where the user grants permission for the OAuth2 flow.
func (oc *OAuth2Config) SetAuthUrl(url string) {
	oc.AuthUrl = url
}

// GetTokenUrl retrieves the OAuth2 token exchange service URL associated with the provider.
// It implements the GetTokenUrl() method of the Provider interface.
// The token exchange service URL is where the OAuth2 authorization code is exchanged for an access token.
func (oc *OAuth2Config) GetTokenUrl() string {
	return oc.TokenUrl
}

// SetTokenUrl assigns the specified OAuth2 token exchange service URL to the OAuth2 provider.
// It implements the SetTokenUrl() method of the Provider interface.
// The token exchange service URL is where the OAuth2 authorization code is exchanged for an access token.
func (oc *OAuth2Config) SetTokenUrl(url string) {
	oc.TokenUrl = url
}

// GetUserApiUrl retrieves the user information API URL associated with the OAuth2 provider.
// It implements the GetUserApiUrl() method of the Provider interface.
// The user information API URL is used to fetch details about the authenticated user.
func (oc *OAuth2Config) GetUserApiUrl() string {
	return oc.UserApiUrl
}

// SetUserApiUrl assigns the specified user information API URL to the OAuth2 provider.
// It implements the SetUserApiUrl() method of the Provider interface.
// The user information API URL is used to fetch details about the authenticated user.
func (oc *OAuth2Config) SetUserApiUrl(url string) {
	oc.UserApiUrl = url
}

// GetScopes retrieves the access permissions that will be requested from the OAuth2 provider.
// It implements the GetScopes() method of the Provider interface.
// Scopes define the level of access the application is requesting from the user.
func (oc *OAuth2Config) GetScopes() []string {
	return oc.Scopes
}

// SetScopes sets the access permissions that will be requested later during the OAuth2 flow.
// It implements the SetScopes() method of the Provider interface.
// Scopes define the level of access the application is requesting from the user.
func (oc *OAuth2Config) SetScopes(scopes []string) {
	oc.Scopes = scopes
}

// GetPKCE retrieves whether the OAuth2 provider can use the PKCE (Proof Key for Code Exchange) flow.
// It implements the GetPKCE() method of the Provider interface.
// PKCE enhances the security of OAuth2 authorization code grants.
func (oc *OAuth2Config) GetPKCE() bool {
	return oc.Pkce
}

// SetPKCE toggles the state whether the OAuth2 provider can use the PKCE flow or not.
// It implements the SetPKCE() method of the Provider interface.
// PKCE enhances the security of OAuth2 authorization code grants.
func (oc *OAuth2Config) SetPKCE(enable bool) {
	oc.Pkce = enable
}

// Client returns an HTTP client using the provided OAuth2 token.
// It implements the Client() method of the Provider interface.
// The client is configured to include the OAuth2 token in its requests.
func (oc *OAuth2Config) Client(token *oauth2.Token) *http.Client {
	return oc.oauth2Config().Client(oc.Ctx, token)
}

// BuildAuthUrl returns a URL to the OAuth2 provider's consent page that asks for permissions explicitly.
// It implements the BuildAuthUrl() method of the Provider interface.
// The state parameter is a unique value to prevent CSRF attacks during the OAuth2 flow.
func (oc *OAuth2Config) BuildAuthUrl(state string, opts ...oauth2.AuthCodeOption) string {
	return oc.oauth2Config().AuthCodeURL(state, opts...)
}

// FetchToken converts an authorization code to an OAuth2 token.
// It implements the FetchToken() method of the Provider interface.
// This step is performed after the user grants permission in the OAuth2 flow.
func (oc *OAuth2Config) FetchToken(code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return oc.oauth2Config().Exchange(oc.Ctx, code, opts...)
}

// FetchRawData requests and marshals the OAuth user API response.
// It implements the FetchRawData() method of the Provider interface.
// The user API response contains detailed information about the authenticated user.
func (oc *OAuth2Config) FetchRawData(token *oauth2.Token) ([]byte, error) {
	req, err := http.NewRequestWithContext(oc.Ctx, "GET", oc.UserApiUrl, nil)
	if err != nil {
		return nil, err
	}
	return oc.SendRawUserDataRequest(req, token)
}

// SendRawUserDataRequest sends the specified user data request and returns its raw response body.
// It is a helper method used internally to fetch user data.
func (oc *OAuth2Config) SendRawUserDataRequest(req *http.Request, token *oauth2.Token) ([]byte, error) {
	client := oc.Client(token)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)

	result, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	// http.Client.Get doesn't treat non 2xx responses as error
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf(
			"failed to fetch user via %s (%d):\n%s",
			oc.UserApiUrl,
			res.StatusCode,
			string(result),
		)
	}
	return result, nil
}

// oauth2Config constructs an oauth2.Config instance based on the OAuth2 provider settings.
// It is used internally to create the OAuth2 configuration.
func (oc *OAuth2Config) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  oc.RedirectUrl,
		ClientID:     oc.ClientId,
		ClientSecret: oc.ClientSecret,
		Scopes:       oc.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oc.AuthUrl,
			TokenURL: oc.TokenUrl,
		},
	}
}
