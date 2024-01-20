# goauth

The `goauth` package provides a common interface and implementations for OAuth2 authorization flows in Go. This package can be used to integrate with various OAuth2 providers (such as Apple, Discord, Facebook, etc.).

## Installation
To add the package to your project, run the following command in the terminal:
```bash
go get -u github.com/mstgnz/goauth
```

## Usage
To use the package in your project, you can create an example as follows:

```go
package main

import (
	"log"
	"net/http"

	config "github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/providers"
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


