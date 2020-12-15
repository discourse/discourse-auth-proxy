package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

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
	options.Nonce = addNonce("http://some.url/")
	t.Cleanup(func() {
		nonceCache.Clear()
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
