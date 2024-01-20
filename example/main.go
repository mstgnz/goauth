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
