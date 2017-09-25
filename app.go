/*
Oidc-auth-proxy
*/
package main

import (
	"fmt"
	oidc "github.com/coreos/go-oidc"
	jwt "github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	clientID      = os.Getenv("CLIENT_ID")
	clientSecret  = os.Getenv("CLIENT_SECRET")
	cookieSignKey = []byte(os.Getenv("SECRET"))
)

// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string
	// Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}

func validate(rawToken string) (*jwt.Token, error) {
	return jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return cookieSignKey, nil
	})

}

func createToken(exp time.Time, v string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = exp.Unix()
	claims["v"] = v
	tokenString, _ := token.SignedString(cookieSignKey)
	return tokenString
}

func createConfig(provider *oidc.Provider, r *http.Request) oauth2.Config {
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "https://" + r.Host + "/sso/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return config
}

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, os.Getenv("REALM"))
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/sso/auth", func(w http.ResponseWriter, r *http.Request) {
		// Implement nginx auth check
		cookie, err := r.Cookie("oidc-proxy-auth-session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		sessionToken, err := validate(cookie.Value)

		// 403 if not
		if err != nil {
			log.Printf("Not valid session")
			log.Printf(err.Error())
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		// 200 if ok
		if sessionToken.Valid {
			w.Write([]byte("OK"))
		}

	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		expiration := time.Now().Add(15 * time.Minute)
		token := createToken(expiration, r.Referer())
		config := createConfig(provider, r)
		log.Printf(formatRequest(r))
		http.Redirect(w, r, config.AuthCodeURL(token), http.StatusFound)
	})

	http.HandleFunc("/sso/login", func(w http.ResponseWriter, r *http.Request) {
		expiration := time.Now().Add(15 * time.Minute)
		token := createToken(expiration, r.Referer())
		config := createConfig(provider, r)
		log.Printf(formatRequest(r))
		http.Redirect(w, r, config.AuthCodeURL(token), http.StatusFound)
	})

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "", http.StatusNotFound)
	})

	http.HandleFunc("/sso/callback", func(w http.ResponseWriter, r *http.Request) {

		config := createConfig(provider, r)

		stateToken, err := validate(r.URL.Query().Get("state"))

		if err != nil {
			log.Printf("State token error")
			log.Printf(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if stateToken.Valid {
			log.Printf("State OK")
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusUnauthorized)
			return
		}
		expiration := time.Now().Add(24 * time.Hour)

		token := createToken(expiration, userInfo.Subject)

		cookie := http.Cookie{Name: "oidc-proxy-auth-session",
			Value:    token,
			HttpOnly: true,
			Path:     "/",
			Expires:  expiration}
		http.SetCookie(w, &cookie)

		http.Redirect(w, r, "https://"+r.Host, http.StatusFound)
	})

	log.Printf("listening on http://%s/", "0.0.0.0:5556")
	log.Fatal(http.ListenAndServe("0.0.0.0:5556", nil))
}
