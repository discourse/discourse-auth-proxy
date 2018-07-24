package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/golang/groupcache/lru"
	"github.com/namsral/flag"
	"github.com/pborman/uuid"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var nonceCache = lru.New(20)
var nonceMutex = &sync.Mutex{}

type Config struct {
	ListenUriPtr      *string
	ProxyUriPtr       *string
	OriginUriPtr      *string
	SsoSecretPtr      *string
	SsoUriPtr         *string
	BasicAuthPtr      *string
	UsernameHeaderPtr *string
	GroupsHeaderPtr   *string
	TimeoutPtr        *int
	CookieSecret      string
	AllowAllPtr       *bool
}

func main() {
	config := new(Config)

	config.ListenUriPtr = flag.String("listen-url", "", "uri to listen on eg: localhost:2001. leave blank to set equal to proxy-url")
	config.ProxyUriPtr = flag.String("proxy-url", "", "outer url of this host eg: http://secrets.example.com")
	config.OriginUriPtr = flag.String("origin-url", "", "origin to proxy eg: http://localhost:2002")
	config.SsoSecretPtr = flag.String("sso-secret", "", "SSO secret for origin")
	config.SsoUriPtr = flag.String("sso-url", "", "SSO endpoint eg: http://discourse.forum.com")
	config.AllowAllPtr = flag.Bool("allow-all", false, "allow all discourse users (default: admin users only)")
	config.BasicAuthPtr = flag.String("basic-auth", "", "HTTP Basic authentication credentials to let through directly")
	config.UsernameHeaderPtr = flag.String("username-header", "Discourse-User-Name", "Request header to pass authenticated username into")
	config.GroupsHeaderPtr = flag.String("groups-header", "Discourse-User-Groups", "Request header to pass authenticated groups into")
	config.TimeoutPtr = flag.Int("timeout", 10, "Read/write timeout")

	flag.Parse()

	originUrl, err := url.Parse(*config.OriginUriPtr)

	if err != nil {
		flag.Usage()
		log.Fatal("invalid origin url")
	}

	_, err = url.Parse(*config.SsoUriPtr)

	if err != nil {
		flag.Usage()
		log.Fatal("invalid sso url, should point at Discourse site with enable sso")
	}

	proxyUrl, err2 := url.Parse(*config.ProxyUriPtr)

	if err2 != nil {
		flag.Usage()
		log.Fatal("invalid proxy uri")
	}

	if *config.ListenUriPtr == "" {
		log.Println("Defaulting to listening on the proxy url")
		*config.ListenUriPtr = proxyUrl.Host
	}

	if *config.ProxyUriPtr == "" || *config.OriginUriPtr == "" || *config.SsoSecretPtr == "" || *config.SsoUriPtr == "" || *config.ListenUriPtr == "" {
		flag.Usage()
		os.Exit(1)
		return
	}

	if *config.BasicAuthPtr != "" {
		log.Println("Enabling basic auth support")
	}

	config.CookieSecret = uuid.New()

	proxy := httputil.NewSingleHostReverseProxy(originUrl)

	handler := authProxyHandler(proxy, config)

	server := &http.Server{
		Addr:           *config.ListenUriPtr,
		Handler:        handler,
		ReadTimeout:    time.Duration(*config.TimeoutPtr) * time.Second,
		WriteTimeout:   time.Duration(*config.TimeoutPtr) * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Fatal(server.ListenAndServe())
}

func authProxyHandler(handler http.Handler, config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkAuthorizationHeader(handler, r, w, config) {
			return
		}
		redirectIfNoCookie(handler, r, w, config)
	})
}

func checkAuthorizationHeader(handler http.Handler, r *http.Request, w http.ResponseWriter, config *Config) bool {
	if *config.BasicAuthPtr == "" {
		// Can't auth if we don't have anything to auth against
		return false
	}

	auth_header := r.Header.Get("Authorization")
	if len(auth_header) < 6 {
		return false
	}

	if auth_header[0:6] == "Basic " {
		log.Println("Received request with basic auth creds")
		b_creds, _ := base64.StdEncoding.DecodeString(auth_header[6:])
		creds := string(b_creds)
		if creds == *config.BasicAuthPtr {
			colon_idx := strings.Index(creds, ":")
			if colon_idx == -1 {
				return false
			}
			username := creds[0:colon_idx]
			r.Header.Set(*config.UsernameHeaderPtr, username)
			r.Header.Del("Authorization")
			log.Printf("Accepted basic auth creds for %s\n", username)
			handler.ServeHTTP(w, r)
			return true
		} else {
			log.Printf("Rejected basic auth creds.  Authorization header was %s", auth_header)
		}
	}

	return false
}

func redirectIfNoCookie(handler http.Handler, r *http.Request, w http.ResponseWriter, config *Config) {
	cookie, err := r.Cookie("__discourse_proxy")
	var username, groups string

	if err == nil && cookie != nil {
		username, groups, err = parseCookie(cookie.Value, config.CookieSecret)
	}

	if err == nil {
		r.Header.Set(*config.UsernameHeaderPtr, username)
		r.Header.Set(*config.GroupsHeaderPtr, groups)
		handler.ServeHTTP(w, r)
		return
	}

	query := r.URL.Query()
	sso := query.Get("sso")
	sig := query.Get("sig")

	if len(sso) == 0 {
		url := *config.SsoUriPtr + "/session/sso_provider?" + sso_payload(*config.SsoSecretPtr, *config.ProxyUriPtr, r.URL.String())
		http.Redirect(w, r, url, 302)
	} else {
		decoded, _ := base64.StdEncoding.DecodeString(sso)
		decodedString := string(decoded)
		parsedQuery, _ := url.ParseQuery(decodedString)

		username := parsedQuery["username"]
		groups := parsedQuery["groups"]
		admin := parsedQuery["admin"]
		nonce := parsedQuery["nonce"]

		groupsArray := strings.Split(groups[0], ",")

		if len(nonce) > 0 && len(admin) > 0 && len(username) > 0 && (admin[0] == "true" || *config.AllowAllPtr) {
			returnUrl, err := getReturnUrl(*config.SsoSecretPtr, sso, sig, nonce[0])

			if err != nil {
				fmt.Fprintf(w, "Invalid request")
				return
			}

			// we have a valid auth
			expiration := time.Now().Add(365 * 24 * time.Hour)

			cookieData := strings.Join([]string{username[0], strings.Join(groupsArray, "|")}, ",")
			cookie := http.Cookie{Name: "__discourse_proxy", Value: signCookie(cookieData, config.CookieSecret), Expires: expiration, HttpOnly: true}
			http.SetCookie(w, &cookie)

			// works around weird safari stuff
			fmt.Fprintf(w, "<html><head></head><body><script>window.location = '%v'</script></body>", returnUrl)
		}
	}
}

func getReturnUrl(secret string, payload string, sig string, nonce string) (returnUrl string, err error) {
	nonceMutex.Lock()
	value, gotNonce := nonceCache.Get(nonce)
	nonceMutex.Unlock()
	if !gotNonce {
		err = fmt.Errorf("Nonce %s not found", nonce)
		return
	}
	returnUrl = value.(string)
	nonceMutex.Lock()
	nonceCache.Remove(nonce)
	nonceMutex.Unlock()
	if ComputeHmac256(payload, secret) != sig {
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

func parseCookie(data, secret string) (username string, groups string, err error) {
	err = nil
	username = ""
	groups = ""

	split := strings.Split(data, ",")

	if len(split) < 2 {
		err = fmt.Errorf("Expecting a semi column in cookie")
		return
	}

	signature := split[len(split)-1]
	parsed := strings.Join(split[:len(split)-1], ",")
	expected := ComputeHmac256(parsed, secret)

	if expected != signature {
		parsed = ""
		err = fmt.Errorf("Expecting signature to match")
		return
	} else {
		username = strings.Split(parsed, ",")[0]
		groups = strings.Split(parsed, ",")[1]
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
	nonceMutex.Lock()
	nonceCache.Add(guid, returnUrl)
	nonceMutex.Unlock()
	return guid
}

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
