# goauth

The `goauth` package provides a common interface and implementations for OAuth2 authorization flows in Go. This package can be used to integrate with various OAuth2 providers (such as Apple, Discord, Facebook, etc.).

## Installation
To add the package to your project, run the following command in the terminal:

```bash
go get -u github.com/mstgnz/goauth
```

## Documentation

### Package Structure
The package is organized as follows:

```
goauth/
├── provider/         # Base provider interface and common functionality
├── apple/           # Apple OAuth2 provider implementation
├── discord/         # Discord OAuth2 provider implementation
├── facebook/        # Facebook OAuth2 provider implementation
├── github/          # GitHub OAuth2 provider implementation
├── google/          # Google OAuth2 provider implementation
└── example/         # Example implementations for each provider
```

### Provider Interface
All OAuth2 providers implement the following interface:

```go
type Provider interface {
    SetClientId(string)
    SetClientSecret(string)
    SetRedirectUrl(string)
    SetScopes([]string)
    BuildAuthUrl(string, ...oauth2.AuthCodeOption) string
    FetchToken(string) (*oauth2.Token, error)
    FetchUser(*oauth2.Token) (*User, error)
    RefreshToken(*oauth2.Token) (*oauth2.Token, error)
    ValidateConfig() error
    Client(*oauth2.Token) *http.Client
}
```

### User Type
User information is returned in a standardized format:

```go
type User struct {
    ID       string
    Username string
    Name     string
    Email    string
    Avatar   string
}
```

## Example Usage

### GitHub OAuth2

```go
package main

import (
    "log"
    "net/http"
    "github.com/mstgnz/goauth"
    "golang.org/x/oauth2"
)

func main() {
    provider, err := goauth.NewProviderByName("github")
    if err != nil {
        log.Fatal(err)
    }

    provider.SetClientId("your-client-id")
    provider.SetClientSecret("your-client-secret")
    provider.SetRedirectUrl("http://localhost:8080/callback")
    provider.SetScopes([]string{"read:user", "user:email"})

    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        url := provider.BuildAuthUrl("state", oauth2.AccessTypeOffline)
        http.Redirect(w, r, url, http.StatusTemporaryRedirect)
    })

    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        token, err := provider.FetchToken(r.URL.Query().Get("code"))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

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

### Google OAuth2

```go
package main

import (
    "log"
    "net/http"
    "github.com/mstgnz/goauth"
    "golang.org/x/oauth2"
)

func main() {
    provider, err := goauth.NewProviderByName("google")
    if err != nil {
        log.Fatal(err)
    }

    provider.SetClientId("your-client-id")
    provider.SetClientSecret("your-client-secret")
    provider.SetRedirectUrl("http://localhost:8080/callback")
    provider.SetScopes([]string{
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
    })

    // ... HTTP handlers similar to GitHub example ...
}
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

## Security Considerations

1. Always use HTTPS in production
2. Validate state parameter to prevent CSRF attacks
3. Store tokens securely
4. Use environment variables for client credentials
5. Implement PKCE when supported by the provider
6. Keep scopes to the minimum required
7. Handle token expiration and refresh properly

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.