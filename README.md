# goauth

[![Go Reference](https://pkg.go.dev/badge/github.com/mstgnz/goauth.svg)](https://pkg.go.dev/github.com/mstgnz/goauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/mstgnz/goauth)](https://goreportcard.com/report/github.com/mstgnz/goauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Go package that provides a unified interface for OAuth2 authentication across multiple providers. This package simplifies the integration of OAuth2 authentication in your Go applications by offering a consistent API for various OAuth2 providers.

## Features

- Unified interface for all OAuth2 providers
- Easy-to-use API
- Type-safe implementation
- Extensive provider support
- Built-in token management
- Standardized user information
- Customizable scopes
- Error handling
- Token refresh support

## Installation

```bash
go get -u github.com/mstgnz/goauth
```

## Quick Start

Here's a simple example using GitHub OAuth2:

```go
package main

import (
    "log"
    "net/http"
    "github.com/mstgnz/goauth/initialize"
    "golang.org/x/oauth2"
)

func main() {
    // Initialize the provider
    provider, err := initialize.NewProviderByName("github")
    if err != nil {
        log.Fatal(err)
    }

    // Configure the provider
    provider.SetClientId("your-client-id")
    provider.SetClientSecret("your-client-secret")
    provider.SetRedirectUrl("http://localhost:8080/callback")
    provider.SetScopes([]string{"read:user", "user:email"})

    // Setup login handler
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        url := provider.BuildAuthUrl("state", oauth2.AccessTypeOffline)
        http.Redirect(w, r, url, http.StatusTemporaryRedirect)
    })

    // Setup callback handler
    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        // Exchange code for token
        token, err := provider.FetchToken(r.URL.Query().Get("code"))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Get user information
        user, err := provider.FetchUser(token)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        log.Printf("Logged in user: %+v", user)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Supported Providers

The package currently supports the following OAuth2 providers:

| Provider | Documentation |
|----------|--------------|
| Apple | [Apple Developer](https://developer.apple.com/) |
| Discord | [Discord Developer](https://discord.com/developers/docs) |
| Facebook | [Facebook for Developers](https://developers.facebook.com/) |
| Gitea | [Gitea Developer](https://gitea.io/en-us/docs/) |
| Gitee | [Gitee Developer](https://gitee.com/help) |
| GitHub | [GitHub Developer](https://developer.github.com/) |
| GitLab | [GitLab Developer](https://docs.gitlab.com/ee/api/) |
| Google | [Google Identity Platform](https://developers.google.com/identity) |
| Instagram | [Instagram Graph API](https://developers.facebook.com/docs/instagram-api) |
| Kakao | [Kakao Developers](https://developers.kakao.com/) |
| LiveChat | [LiveChat API](https://developers.livechat.com/docs/rest-api/) |
| Mailcow | [Mailcow API](https://mailcow.github.io/mailcow-dockerized-docs/) |
| Microsoft | [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/) |
| OIDC | [OpenID Connect](https://openid.net/connect/) |
| Patreon | [Patreon API](https://docs.patreon.com/#introduction) |
| Spotify | [Spotify for Developers](https://developer.spotify.com/documentation/general/) |
| Strava | [Strava API](https://developers.strava.com/) |
| Twitch | [Twitch Developers](https://dev.twitch.tv/docs) |
| X (Twitter) | [X Developer](https://developer.x.com/) |
| VK | [VK API](https://vk.com/dev) |
| Yandex | [Yandex Passport API](https://yandex.com/dev/passport/) |

## Advanced Usage

### Custom Scopes

```go
provider.SetScopes([]string{
    "read:user",
    "user:email",
    "custom:scope",
})
```

### Token Refresh

```go
newToken, err := provider.RefreshToken(oldToken)
if err != nil {
    log.Fatal(err)
}
```

### Custom HTTP Client

```go
client := provider.Client(token)
resp, err := client.Get("https://api.provider.com/endpoint")
```

## Best Practices

1. **Environment Variables**: Store sensitive credentials in environment variables
   ```go
   provider.SetClientId(os.Getenv("OAUTH_CLIENT_ID"))
   provider.SetClientSecret(os.Getenv("OAUTH_CLIENT_SECRET"))
   ```

2. **State Parameter**: Always validate the state parameter
   ```go
   if r.URL.Query().Get("state") != expectedState {
       http.Error(w, "Invalid state parameter", http.StatusBadRequest)
       return
   }
   ```

3. **Error Handling**: Implement proper error handling
   ```go
   if err := provider.ValidateConfig(); err != nil {
       log.Fatal("Configuration error:", err)
   }
   ```

## Security Considerations

- Always use HTTPS in production
- Implement CSRF protection using the state parameter
- Store tokens securely
- Use environment variables for credentials
- Implement PKCE when available
- Keep scopes to minimum required
- Properly handle token expiration and refresh

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please file an issue on the [GitHub repository](https://github.com/mstgnz/goauth/issues).