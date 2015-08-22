package main

import (
	"code.google.com/p/go-uuid/uuid"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/golang/groupcache/lru"
	"github.com/namsral/flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var nonceCache = lru.New(20)

func main() {

	listenUriPtr := flag.String("listen-url", "", "uri to listen on eg: localhost:2001. leave blank to set equal to proxy-url")
	proxyUriPtr := flag.String("proxy-url", "", "outer url of this host eg: http://secrets.example.com")
	originUriPtr := flag.String("origin-url", "", "origin to proxy eg: http://localhost:2002")
	ssoSecretPtr := flag.String("sso-secret", "", "SSO secret for origin")
	ssoUriPtr := flag.String("sso-url", "", "SSO endpoint eg: http://discourse.forum.com")

	flag.Parse()

	originUrl, err := url.Parse(*originUriPtr)

	if err != nil {
		flag.Usage()
		log.Fatal("invalid origin url")
	}

	_, err = url.Parse(*ssoUriPtr)

	if err != nil {
		flag.Usage()
		log.Fatal("invalid sso url, should point at Discourse site with enable sso")
	}

	proxyUrl, err2 := url.Parse(*proxyUriPtr)

	if err2 != nil {
		flag.Usage()
		log.Fatal("invalid proxy uri")
	}

	if *listenUriPtr == "" {
		log.Info("Defaulting to listening on the proxy url")
		*listenUriPtr = proxyUrl.Host
	}

	if *proxyUriPtr == "" || *originUriPtr == "" || *ssoSecretPtr == "" || *ssoUriPtr == "" || *listenUriPtr == "" {
		flag.Usage()
		os.Exit(1)
		return
	}

	cookieSecret := uuid.New()

	proxy := httputil.NewSingleHostReverseProxy(originUrl)

	handler := redirectIfCookieMissing(proxy, *ssoSecretPtr, cookieSecret, *ssoUriPtr, *proxyUriPtr)

	server := &http.Server{
		Addr:           *listenUriPtr,
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Fatal(server.ListenAndServe())
}

func envOrFlag(name, help string) string {
	flag.String(name, "", help)

	return ""
}

func redirectIfCookieMissing(handler http.Handler, ssoSecret, cookieSecret, ssoUri, proxyHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("__discourse_proxy")

		var username string

		if err == nil && cookie != nil {
			username, err = parseCookie(cookie.Value, cookieSecret)
		}

		if err == nil {
			r.Header.Set("Discourse-User-Name", username)
			handler.ServeHTTP(w, r)
			return
		}

		query := r.URL.Query()
		sso := query.Get("sso")
		sig := query.Get("sig")

		if len(sso) == 0 {
			url := ssoUri + "/session/sso_provider?" + sso_payload(ssoSecret, proxyHost, r.URL.String())
			http.Redirect(w, r, url, 302)
		} else {
			decoded, _ := base64.StdEncoding.DecodeString(sso)
			decodedString := string(decoded)
			parsedQuery, _ := url.ParseQuery(decodedString)

			username := parsedQuery["username"]
			admin := parsedQuery["admin"]
			nonce := parsedQuery["nonce"]

			if len(nonce) > 0 && len(admin) > 0 && len(username) > 0 && admin[0] == "true" {
				returnUrl, err := getReturnUrl(ssoSecret, sso, sig, nonce[0])

				if err != nil {
					fmt.Fprintf(w, "Invalid request")
					return
				}

				// we have a valid auth
				expiration := time.Now().Add(365 * 24 * time.Hour)

				cookie := http.Cookie{Name: "__discourse_proxy", Value: signCookie(username[0], cookieSecret), Expires: expiration, HttpOnly: true}
				http.SetCookie(w, &cookie)
				// works around weird safari stuff
				fmt.Fprintf(w, "<html><head></head><body><script>window.location = '%v'</script></body>", returnUrl)
			}
		}

	})
}

func getReturnUrl(secret string, payload string, sig string, nonce string) (returnUrl string, err error) {
	value, gotNonce := nonceCache.Get(nonce)
	returnUrl = value.(string)
	nonceCache.Remove(nonce)
	valid := ComputeHmac256(payload, secret) == sig && gotNonce
	if !valid {
		err = fmt.Errorf("Signature is invalid")
	}
	return
}

func sameHost(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = r.URL.Host
		handler.ServeHTTP(w, r)
	})
}

func signCookie(data, secret string) string {
	return data + "," + ComputeHmac256(data, secret)
}

func parseCookie(data, secret string) (parsed string, err error) {
	err = nil
	parsed = ""

	split := strings.Split(data, ",")

	if len(split) < 2 {
		err = fmt.Errorf("Expecting a semi column in cookie")
		return
	}

	signature := split[len(split)-1]
	parsed = strings.Join(split[:len(split)-1], ",")
	expected := ComputeHmac256(parsed, secret)

	if expected != signature {
		parsed = ""
		err = fmt.Errorf("Expecting signature to match")
		return
	}

	return
}

func sso_payload(secret string, return_sso_url string, returnUrl string) string {
	result := "return_sso_url=" + return_sso_url + "&nonce=" + addNonce(returnUrl)
	payload := base64.StdEncoding.EncodeToString([]byte(result))

	return "sso=" + payload + "&sig=" + ComputeHmac256(payload, secret)
}

func addNonce(returnUrl string) string {
	guid := uuid.New()
	nonceCache.Add(guid, returnUrl)
	return guid
}

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
