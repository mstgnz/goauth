# goauth

The `goauth` package provides a common interface and implementations for OAuth2 authorization flows in Go. This package can be used to integrate with various OAuth2 providers (such as Apple, Discord, Facebook, etc.).


## Installation
To add the package to your project, run the following command in the terminal:

```bash
go get -u github.com/mstgnz/goauth
```


## Supported OAuth2 Providers

- Apple - [Apple Developer](https://developer.apple.com/)
- Discord - [Discord Developer](https://discord.com/developers/docs)
- Facebook - [Facebook for Developers](https://developers.facebook.com/)
- Gitea - [Gitea Developer](https://gitea.io/en-us/docs/)
- Gitee - [Gitee Developer](https://gitee.com/help)
- GitHub - [GitHub Developer](https://developer.github.com/)
- GitLab - [GitLab Developer](https://docs.gitlab.com/ee/api/)
- Google - [Google Identity Platform](https://developers.google.com/identity)
- Instagram - [Instagram Graph API](https://developers.facebook.com/docs/instagram-api)
- Kakao - [Kakao Developers](https://developers.kakao.com/)
- LiveChat - [LiveChat API](https://developers.livechat.com/docs/rest-api/)
- Mailcow - [Mailcow API](https://mailcow.github.io/mailcow-dockerized-docs/)
- Microsoft - [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- OIDC - [OpenID Connect](https://openid.net/connect/)
- Patreon - [Patreon API](https://docs.patreon.com/#introduction)
- Spotify - [Spotify for Developers](https://developer.spotify.com/documentation/general/)
- Strava - [Strava API](https://developers.strava.com/)
- Twitch - [Twitch Developers](https://dev.twitch.tv/docs)
- X - [X Developer](https://developer.x.com/)
- VK - [VK API](https://vk.com/dev)
- Yandex - [Yandex Passport API](https://yandex.com/dev/passport/)


## Usage
To use the package in your project, you can create an example as follows:

```go
package main

import (
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

var err error
var provider config.Provider

func main() {

	provider, err = goauth.NewProviderByName("github")
	if err != nil {
		log.Fatal(err.Error())
	}
	provider.SetRedirectUrl("http://localhost:8585/callback")

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Fatal(http.ListenAndServe(":8585", nil))

}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := provider.BuildAuthUrl("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	token, err := provider.FetchToken(r.URL.Query().Get("code"))
	if err != nil {
		log.Println(err)
	}
	if user, err := provider.FetchUser(token); err != nil {
		log.Println(err)
	} else {
		log.Println(user)
	}
}

## Provider Examples

### GitHub
```go
provider, _ := goauth.NewProviderByName("github")
provider.SetClientId("your-client-id")
provider.SetClientSecret("your-client-secret")
provider.SetRedirectUrl("http://localhost:8585/callback")
// Default scopes: read:user, user:email
provider.SetScopes([]string{"read:user", "user:email", "repo"})
```

### Google
```go
provider, _ := goauth.NewProviderByName("google")
provider.SetClientId("your-client-id")
provider.SetClientSecret("your-client-secret")
provider.SetRedirectUrl("http://localhost:8585/callback")
// Default scopes: profile, email
provider.SetScopes([]string{"profile", "email", "https://www.googleapis.com/auth/calendar.readonly"})
```

### Facebook
```go
provider, _ := goauth.NewProviderByName("facebook")
provider.SetClientId("your-client-id")
provider.SetClientSecret("your-client-secret")
provider.SetRedirectUrl("http://localhost:8585/callback")
// Default scopes: email, public_profile
provider.SetScopes([]string{"email", "public_profile", "user_friends"})
```

### Discord
```go
provider, _ := goauth.NewProviderByName("discord")
provider.SetClientId("your-client-id")
provider.SetClientSecret("your-client-secret")
provider.SetRedirectUrl("http://localhost:8585/callback")
// Default scopes: identify, email
provider.SetScopes([]string{"identify", "email", "guilds"})
```

### Apple
```go
provider, _ := goauth.NewProviderByName("apple")
provider.SetClientId("your-client-id")
provider.SetClientSecret("your-client-secret") // Must be a JWT token
provider.SetRedirectUrl("http://localhost:8585/callback")
// Default scopes: name, email
provider.SetScopes([]string{"name", "email"})
```

## Troubleshooting Guide

### Common Issues and Solutions

1. **Invalid Client ID/Secret**
   - Error: "invalid_client" or "unauthorized_client"
   - Solution: 
     - Verify that the Client ID and Secret are correct
     - Check if the RedirectURL is properly configured in the provider's developer console
     - Ensure HTTPS is used for providers that require SSL

2. **Invalid Redirect URI**
   - Error: "redirect_uri_mismatch"
   - Solution:
     - Verify that the RedirectURL in your code matches exactly with the one configured in the provider's developer console
     - Ensure exact match including http/https, www/non-www, and trailing slash

3. **Invalid Scope**
   - Error: "invalid_scope"
   - Solution:
     - Verify that the requested scopes are supported by the provider
     - Check if the scopes are formatted correctly
     - Ensure the scopes are enabled in the provider's developer console

4. **Unable to Get Token**
   - Error: "invalid_grant" or "invalid_request"
   - Solution:
     - Ensure the authorization code is used only once
     - Verify that the token request includes correct parameters
     - If using PKCE, verify the code verifier is correct

5. **Unable to Fetch User Information**
   - Error: API call fails
   - Solution:
     - Verify the token is valid
     - Ensure you have requested sufficient scopes for the information
     - Check if the API endpoint is correct

### Provider-Specific Issues

1. **Apple Sign In**
   - Client Secret must be in JWT format
   - Verify the private key format is correct
   - Check Team ID and Bundle ID configuration

2. **Facebook**
   - App Review might be required
   - SSL certificate is mandatory
   - Verify Graph API version compatibility

3. **Google**
   - Check consent screen configuration
   - Ensure required APIs are enabled for the project
   - Verify required scopes are added to OAuth consent screen

4. **GitHub**
   - Monitor rate limiting
   - Additional permissions needed for organization access
   - Verify appropriate scopes for private repo access

### Debugging Tips

1. **Debug Logs**
```go
// Enable debug mode
provider.SetDebug(true)
```

2. **Monitor HTTP Requests**
```go
// Customize HTTP client
client := &http.Client{
    Transport: &loggingTransport{http.DefaultTransport},
}
provider.SetHttpClient(client)
```

3. **Inspect Token Information**
```go
token, _ := provider.FetchToken(code)
log.Printf("Access Token: %s", token.AccessToken)
log.Printf("Token Type: %s", token.TokenType)
log.Printf("Refresh Token: %s", token.RefreshToken)
log.Printf("Expiry: %s", token.Expiry)
```


## Providers
The `goauth` package supports various popular OAuth2 providers. For each provider, you will need to provide the following information:

- `DisplayName`: The official name of the provider.
- `ClientId`: The application ID for the provider's client.
- `ClientSecret`: The application secret for the provider's client.
- `RedirectUrl`: The URL to redirect to after completing the OAuth flow.
- `AuthUrl`: The URL of the OAuth2 authorization service.
- `TokenUrl`: The URL of the token exchange service.
- `UserApiUrl`: The API URL used to fetch user information.
- `Scopes`: The access permissions you want to request.
- `Pkce`: Whether the provider supports the PKCE flow.


## Contribution
If you want to contribute to improving `goauth` or adding new providers, please open an issue or submit a pull request.


## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.