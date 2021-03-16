package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang/groupcache/lru"
	"github.com/pborman/uuid"

	"github.com/discourse/discourse-auth-proxy/internal/httpproxy"
)

var (
	logger = newRateLimitedLogger(os.Stderr, "", 0)

	config *Config

	storageInstance CacheStore
)

const (
	cookieName          = "__discourse_proxy"
	reauthorizeInterval = 365 * 24 * time.Hour
)

func main() {
	{
		var err error
		config, err = ParseConfig()
		if err != nil {
			usage(err)
		}
	}

	setupStorage(config)
	GetSetNXCookieSecretIfRedis(config)

	dnssrv := httpproxy.NewDNSSRVBackend(config.OriginURL)
	go dnssrv.Lookup(context.Background(), 50*time.Second, 10*time.Second, config.SRVAbandonAfter)
	proxy := &httputil.ReverseProxy{Director: dnssrv.Director}

	handler := authProxyHandler(proxy)

	if config.LogRequests {
		handler = logHandler(handler)
	}

	var listener net.Listener
	var err error

	if strings.Index(config.ListenAddr, "unix:") == 0 {
		file := strings.Replace(config.ListenAddr, "unix:", "", 1)
		if _, err = os.Stat(file); err == nil {
			os.Remove(file)
		}
		listener, err = net.Listen("unix", strings.Replace(config.ListenAddr, "unix:", "", 1))
	} else {
		listener, err = net.Listen("tcp", config.ListenAddr)
	}

	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Handler:        handler,
		ReadTimeout:    config.Timeout,
		WriteTimeout:   config.Timeout,
		MaxHeaderBytes: 1 << 20,
	}

	log.Fatal(server.Serve(listener))
}

func authProxyHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkWhitelist(handler, r, w) {
			return
		}
		if checkAuthorizationHeader(handler, r, w) {
			return
		}
		redirectIfNoCookie(handler, r, w)
	})
}

func checkAuthorizationHeader(handler http.Handler, r *http.Request, w http.ResponseWriter) bool {
	if config.BasicAuth == "" {
		return false
	}

	auth_header := r.Header.Get("Authorization")
	if len(auth_header) < 6 {
		return false
	}

	if auth_header[0:6] == "Basic " {
		b_creds, _ := base64.StdEncoding.DecodeString(auth_header[6:])
		creds := string(b_creds)
		if creds == config.BasicAuth {
			colon_idx := strings.Index(creds, ":")
			if colon_idx == -1 {
				return false
			}
			username := creds[0:colon_idx]
			r.Header.Set(config.UsernameHeader, username)
			r.Header.Del("Authorization")
			handler.ServeHTTP(w, r)
			return true
		} else {
			logger.Printf("rejected basic auth creds: authorization header: %s", auth_header)
		}
	}

	return false
}

func checkWhitelist(handler http.Handler, r *http.Request, w http.ResponseWriter) bool {
	if config.Whitelist == "" {
		return false
	}

	if r.URL.Path == config.Whitelist {
		handler.ServeHTTP(w, r)
		return true
	}

	return false
}

func redirectIfNoCookie(handler http.Handler, r *http.Request, w http.ResponseWriter) {
	writeHttpError := func(code int) {
		http.Error(w, http.StatusText(code), code)
	}
	fail := func(format string, v ...interface{}) {
		logger.Printf(format, v...)
		writeHttpError(http.StatusBadRequest)
	}

	cookie, err := r.Cookie(cookieName)
	var username, groups string

	if err == nil && cookie != nil {
		username, groups, err = parseCookie(cookie.Value, config.CookieSecret)
	}

	if err == nil {
		r.Header.Set(config.UsernameHeader, username)
		r.Header.Set(config.GroupsHeader, groups)
		handler.ServeHTTP(w, r)
		return
	}

	query := r.URL.Query()
	sso := query.Get("sso")
	sig := query.Get("sig")

	if len(sso) == 0 {
		payload, err := ssoPayload(config.SSOSecret, config.ProxyURLString, r.URL.String())
		if err != nil {
			fail("An error occurred when generating SSO payload: %s", err)
			return
		}
		url := config.SSOURLString + "/session/sso_provider?" + payload.Encode()
		http.Redirect(w, r, url, 302)
	} else {
		decoded, err := base64.StdEncoding.DecodeString(sso)
		if err != nil {
			fail("invalid sso query parameter: %s", err)
			return
		}

		parsedQuery, err := url.ParseQuery(string(decoded))
		if err != nil {
			fail("invalid sso query parameter: %s", err)
			return
		}

		var (
			username = parsedQuery.Get("username")
			admin    = parsedQuery.Get("admin")
			nonce    = parsedQuery.Get("nonce")
			groups   = NewStringSet(parsedQuery.Get("groups"))
		)

		if len(nonce) == 0 {
			fail("incomplete payload from sso provider: missing nonce")
			return
		}
		if len(username) == 0 {
			fail("incomplete payload from sso provider: missing username")
			return
		}
		if len(admin) == 0 {
			fail("incomplete payload from sso provider: missing admin")
			return
		}
		if !(config.AllowAll || admin == "true") {
			allowed := config.AllowGroups.ContainsAny(groups)

			if !allowed {
				writeHttpError(http.StatusForbidden)
				return
			}
		}

		returnUrl, err := getReturnUrl(config.SSOSecret, sso, sig, nonce)
		if err != nil {
			fail("failed to build return URL: %s", err)
			return
		}

		// we have a valid auth
		expiration := time.Now().Add(reauthorizeInterval)

		cookieData := strings.Join([]string{username, strings.Join(groups, "|")}, ",")
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    signCookie(cookieData, config.CookieSecret),
			Expires:  expiration,
			HttpOnly: true,
			Path:     "/",
		})

		// works around weird safari stuff
		fmt.Fprintf(w, "<html><head></head><body><script>window.location = '%v'</script></body>", template.JSEscapeString(returnUrl))
	}
}

func getReturnUrl(secret string, payload string, sig string, nonce string) (returnUrl string, err error) {
	returnUrl, err = storageInstance.GetAndDeleteNonce(nonce)
	if err != nil {
		return "", err
	}
	if computeHMAC(payload, secret) != sig {
		err = errors.New("signature is invalid")
	}
	return returnUrl, err
}

func signCookie(data, secret string) string {
	return data + "," + computeHMAC(data, secret)
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
	expected := computeHMAC(parsed, secret)

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

// ssoPayload takes the SSO secret and the two redirection URLs, stores the
// returnUrl in the nonce cache, and returns a partial URL querystring.
func ssoPayload(secret string, return_sso_url string, returnUrl string) (url.Values, error) {
	guid, err := addNonce(returnUrl)
	if err != nil {
		return url.Values{}, err
	}
	result := "return_sso_url=" + url.QueryEscape(return_sso_url) + url.QueryEscape(returnUrl) + "&nonce=" + url.QueryEscape(guid)
	payload := base64.StdEncoding.EncodeToString([]byte(result))

	return url.Values{
		"sso": []string{payload},
		"sig": []string{computeHMAC(payload, secret)},
	}, nil
}

// addNonce takes a return URL and returns a nonce associated to that URL.
func addNonce(returnUrl string) (string, error) {
	guid := uuid.New()
	err := storageInstance.AddNonce(guid, returnUrl)
	if err != nil {
		return "", err
	}
	return guid, nil
}

// computeHMAC implements the Discourse SSO protocol, returning a hex string.
func computeHMAC(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func setupStorage(config *Config) {
	if config.RedisAddress != "" {
		client := redis.NewClient(&redis.Options{
			Addr:     config.RedisAddress,
			Password: config.RedisPassword,
		})
		storageInstance = &RedisStore{
			Redis:     client,
			Namespace: "_discourse-auth-proxy_",
		}
	} else {
		storageInstance = &MemoryStore{
			Mutex: &sync.Mutex{},
			Cache: lru.New(20),
		}
	}
}

func GetSetNXCookieSecretIfRedis(config *Config) {
	redisStore, ok := storageInstance.(*RedisStore)
	if ok {
		secret, err := redisStore.GetSetNXCookieSecret()
		if err != nil {
			fmt.Printf("Failed to get cookie secret from redis. Error: %s\n", err)
		} else {
			config.CookieSecret = secret
		}
	}
}
