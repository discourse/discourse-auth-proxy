package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/golang/groupcache/lru"
	"github.com/stretchr/testify/assert"
)

type SSOOptions struct {
	URL    string
	Secret string
	Nonce  string
	Groups string
	Admin  bool
}

type SSOOverrideFunc func(*SSOOptions)
type ConfigOverrideFunc func(*Config)

func NewRedisStore() *RedisStore {
	return &RedisStore{
		Redis: redis.NewClient(&redis.Options{
			Addr: "127.0.0.1:6379",
		}),
		Namespace: "_discourse-auth-proxy-test_",
	}
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Mutex: &sync.Mutex{},
		Cache: lru.New(20),
	}
}

var redisStore = NewRedisStore()
var memoryStore = NewMemoryStore()
var stores = [2]CacheStore{memoryStore, redisStore}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func NewTestConfig() Config {
	return Config{
		OriginURL:       mustParseURL("http://origin.url"),
		ProxyURL:        mustParseURL("http://proxy.url"),
		SSOURL:          mustParseURL("http://sso.url"),
		SSOSecret:       "secret",
		AllowAll:        false,
		AllowGroups:     NewStringSet(""),
		BasicAuth:       "",
		Whitelist:       "",
		UsernameHeader:  "username-header",
		GroupsHeader:    "groups-header",
		Timeout:         10,
		SRVAbandonAfter: 600,
		LogRequests:     false,
		RedisAddress:    "",
		RedisPassword:   "",
	}
}

func NewSSOOptions(url string, secret string) SSOOptions {
	return SSOOptions{
		URL:    url,
		Secret: secret,
		Admin:  false,
	}
}

func RegisterTestNonce(t *testing.T, options SSOOptions) SSOOptions {
	if options.Nonce != "" {
		return options
	}
	nonce, err := addNonce("http://some.url/")
	assert.NoError(t, err)
	options.Nonce = nonce
	t.Cleanup(func() {
		storageInstance.Clear()
	})
	return options
}

func BuildTestSSOURL(options SSOOptions) string {
	innerqs := url.Values{
		"username": []string{"sam"},
		"groups":   []string{options.Groups},
		"admin":    []string{strconv.FormatBool(options.Admin)},
		"nonce":    []string{options.Nonce},
	}
	inner := base64.StdEncoding.EncodeToString([]byte(innerqs.Encode()))

	u := mustParseURL(options.URL)
	outerqs := u.Query()
	outerqs.Set("sso", inner)
	outerqs.Set("sig", computeHMAC(inner, options.Secret))
	u.RawQuery = outerqs.Encode()
	return u.String()
}

func GetTestResult(t *testing.T, configOverride ConfigOverrideFunc, ssoOverride SSOOverrideFunc) *http.Response {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "")
	})

	newConfig := NewTestConfig()

	configOverride(&newConfig)
	config = &newConfig
	setupStorage(config)

	proxy := authProxyHandler(handler)
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	options := NewSSOOptions(ts.URL, config.SSOSecret)
	ssoOverride(&options)
	options = RegisterTestNonce(t, options)

	res, _ := http.Get(BuildTestSSOURL(options))
	return res
}

func TestBadSecret(t *testing.T) {
	res := GetTestResult(
		t,
		func(config *Config) {
			config.AllowAll = true
		},
		func(options *SSOOptions) {
			options.Secret = "BAD SECRET"
		},
	)

	assert.Equal(t, 400, res.StatusCode)
}

func TestForbiddenGroup(t *testing.T) {
	res := GetTestResult(
		t,
		func(config *Config) {
			config.AllowGroups = NewStringSet("group_a,group_b")
		},
		func(options *SSOOptions) {
			options.Groups = "group_c,group_d"
		},
	)

	assert.Equal(t, 403, res.StatusCode)
}

func TestAllowedGroup(t *testing.T) {
	res := GetTestResult(
		t,
		func(config *Config) {
			config.AllowGroups = NewStringSet("group_a,group_b")
		},
		func(options *SSOOptions) {
			options.Groups = "group_c,group_a"
		},
	)

	assert.Equal(t, 200, res.StatusCode)
}

func TestForbiddenAnon(t *testing.T) {
	res := GetTestResult(
		t,
		func(config *Config) {
			config.AllowGroups = NewStringSet("")
			config.AllowAll = false
		},
		func(options *SSOOptions) {
			options.Admin = false
		},
	)

	assert.Equal(t, 403, res.StatusCode)
}

func TestAllowedAnon(t *testing.T) {
	res := GetTestResult(
		t,
		func(config *Config) {
			config.AllowGroups = NewStringSet("")
			config.AllowAll = true
		},
		func(options *SSOOptions) {
			options.Admin = false
		},
	)

	assert.Equal(t, 200, res.StatusCode)
}

func TestExpiredNonce(t *testing.T) {
	res := GetTestResult(
		t,
		func(config *Config) {
			config.AllowGroups = NewStringSet("")
			config.AllowAll = true
		},
		func(options *SSOOptions) {
			options.Admin = false
			options.Nonce = "somenonexistentnonce"
		},
	)
	assert.Equal(t, 400, res.StatusCode)
}

func TestInvalidSecretFails(t *testing.T) {
	signed := signCookie("user,group", "secretfoo")
	_, _, parseError := parseCookie(signed, "secretbar")

	assert.Error(t, parseError)
}

func TestInvalidPayloadFails(t *testing.T) {
	signed := signCookie("user,group", "secretfoo") + "garbage"
	_, _, parseError := parseCookie(signed, "secretfoo")

	assert.Error(t, parseError)
}

func TestValidPayload(t *testing.T) {
	signed := signCookie("user,group", "secretfoo")
	username, group, parseError := parseCookie(signed, "secretfoo")

	assert.NoError(t, parseError)
	assert.Equal(t, username, "user")
	assert.Equal(t, group, "group")
}

func TestStoresAddNonceMethod(t *testing.T) {
	for _, store := range stores {
		nonce := "this-is-a-test-nonce"
		err := store.AddNonce(nonce, "auth proxy hello world")
		assert.NoError(t, err)
		val, err := store.GetAndDeleteNonce(nonce)
		assert.NoError(t, err)
		assert.Equal(t, "auth proxy hello world", val)
	}
}

func TestStoresGetAndDeleteMethod(t *testing.T) {
	for _, store := range stores {
		nonce := "this-is-a-test-nonce"
		err := store.AddNonce(nonce, "auth proxy hello world")
		assert.NoError(t, err)
		val, err := store.GetAndDeleteNonce(nonce)
		assert.NoError(t, err)
		assert.Equal(t, "auth proxy hello world", val)
		val, err = store.GetAndDeleteNonce(nonce)
		assert.Error(t, err)
		assert.Equal(
			t,
			fmt.Sprintf("[%T] nonce not found: this-is-a-test-nonce", store),
			fmt.Sprintf("%s", err),
		)
		assert.Equal(t, "", val)
	}
}

func TestRedisStorePrefix(t *testing.T) {
	assert.Equal(t, "_discourse-auth-proxy-test_osama", redisStore.Prefix("osama"))
	assert.Equal(t, "_discourse-auth-proxy-test_DiSCoUrsE", redisStore.Prefix("DiSCoUrsE"))
}

func TestRedisGetSetNXCookieSecret(t *testing.T) {
	secret, err := redisStore.GetSetNXCookieSecret()
	assert.NoError(t, err)
	assert.Equal(t, 36, len(secret))
	secret2, err := redisStore.GetSetNXCookieSecret()
	assert.NoError(t, err)
	assert.Equal(t, secret, secret2)
}

func TestSetupStorage(t *testing.T) {
	c := NewTestConfig()

	c.RedisAddress = "127.0.0.1:6379"
	setupStorage(&c)
	_, ok := storageInstance.(*RedisStore)
	assert.Equal(t, true, ok)

	c.RedisPassword = "somesecretpa$$word"
	setupStorage(&c)
	_, ok = storageInstance.(*RedisStore)
	assert.Equal(t, true, ok)

	c.RedisPassword = ""
	c.RedisAddress = ""
	setupStorage(&c)
	_, ok = storageInstance.(*MemoryStore)
	assert.Equal(t, true, ok)
}

func TestGetSetNXCookieSecretIfRedis(t *testing.T) {
	c := NewTestConfig()
	c.CookieSecret = "secret1"

	c.RedisAddress = "127.0.0.1:6379"
	setupStorage(&c)
	GetSetNXCookieSecretIfRedis(&c)
	assert.NotEqual(t, "secret1", c.CookieSecret)
	assert.Equal(t, 36, len(c.CookieSecret))
	secret2 := c.CookieSecret

	c = NewTestConfig()
	c.CookieSecret = "secret3"
	setupStorage(&c)
	GetSetNXCookieSecretIfRedis(&c)
	assert.Equal(t, "secret3", c.CookieSecret)

	c = NewTestConfig()
	c.CookieSecret = "secret4"
	c.RedisAddress = "127.0.0.1:6379"
	setupStorage(&c)
	GetSetNXCookieSecretIfRedis(&c)
	assert.Equal(t, secret2, c.CookieSecret)
}

func TestMain(m *testing.M) {
	for _, s := range stores {
		err := s.Clear()
		if err != nil {
			fmt.Printf("%s", err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.Exit(code)
}
