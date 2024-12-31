package main

import (
	"log"
	"net/http"
	"time"

	"github.com/mstgnz/goauth"
	"github.com/mstgnz/goauth/initialize"
	"github.com/mstgnz/goauth/middleware"
	"golang.org/x/oauth2"
)

var provide goauth.Provider

func main() {
	provide, err := initialize.NewProviderByName("github")
	if err != nil {
		log.Fatal(err.Error())
	}
	provide.SetRedirectUrl("http://localhost:8585/callback")

	// Rate limiter oluştur: 60 saniyede maksimum 100 istek
	rateLimiter := middleware.NewRateLimiter(100, 60*time.Second)

	// HTTP handler'ları oluştur
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)

	// Rate limiter middleware'ini ekle
	handler := rateLimiter.Middleware(mux)

	// Periyodik temizlik için goroutine başlat
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			rateLimiter.CleanupOldEntries()
		}
	}()

	log.Fatal(http.ListenAndServe(":8585", handler))
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
