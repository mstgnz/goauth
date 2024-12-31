package main

import (
	"log"
	"net/http"

	provider "github.com/mstgnz/goauth"
	"github.com/mstgnz/goauth/initialize"
	"golang.org/x/oauth2"
)

var err error
var provide provider.Provider

func main() {

	provide, err := initialize.NewProviderByName("github")
	if err != nil {
		log.Fatal(err.Error())
	}
	provide.SetRedirectUrl("http://localhost:8585/callback")

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Fatal(http.ListenAndServe(":8585", nil))

}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := provide.BuildAuthUrl("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	token, err := provide.FetchToken(r.URL.Query().Get("code"))
	if err != nil {
		log.Println(err)
	}
	if user, err := provide.FetchUser(token); err != nil {
		log.Println(err)
	} else {
		log.Println(user)
	}
}
