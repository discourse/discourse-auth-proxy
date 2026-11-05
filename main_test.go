package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

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
		WhitelistPrefix: "",
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

func TestNotWhitelistedPath(t *testing.T) {
	c := NewTestConfig()
	c.Whitelist = ""
	res := allowedByWhiteList(&c, "/some_path")

	assert.Equal(t, false, res)
}

func TestWhitelistedPath(t *testing.T) {
	c := NewTestConfig()
	c.Whitelist = "/some_path"
	res := allowedByWhiteList(&c, "/some_path")

	assert.Equal(t, true, res)
}

func TestWhitelistedPrefixPath(t *testing.T) {
	c := NewTestConfig()
	c.WhitelistPrefix = "/prefix/"
	res := allowedByWhiteList(&c, "/prefix/some_path")

	assert.Equal(t, true, res)
}

func TestCookieCarriesIssueTime(t *testing.T) {
	signed := signCookie("user,group,1700000000", "secretfoo")
	username, groups, issuedAt, err := parseCookiePayload(signed, "secretfoo")

	assert.NoError(t, err)
	assert.Equal(t, "user", username)
	assert.Equal(t, "group", groups)
	assert.Equal(t, int64(1700000000), issuedAt.Unix())
}

func TestLegacyCookieHasNoIssueTime(t *testing.T) {
	_, _, issuedAt, err := parseCookiePayload(signCookie("user,group", "secretfoo"), "secretfoo")

	assert.NoError(t, err)
	assert.True(t, issuedAt.IsZero())
}

func TestTamperedIssueTimeFails(t *testing.T) {
	signed := signCookie("user,group,1700000000", "secretfoo")
	tampered := strings.Replace(signed, "1700000000", "1900000000", 1)
	_, _, _, err := parseCookiePayload(tampered, "secretfoo")

	assert.Error(t, err)
}

func TestReauthDecision(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := NewTestConfig()

	// Without an interval nothing ever goes stale (historic behaviour).
	assert.Equal(t, reauthNotNeeded, reauthDecision(&c, time.Time{}, now, true))
	assert.Equal(t, reauthNotNeeded, reauthDecision(&c, now.Add(-400*24*time.Hour), now, true))

	c.ReauthorizeInterval = 15 * time.Minute
	c.ReauthorizeGrace = time.Hour
	fresh, stale, dead := now.Add(-time.Minute), now.Add(-20*time.Minute), now.Add(-2*time.Hour)

	assert.Equal(t, reauthNotNeeded, reauthDecision(&c, fresh, now, true))
	assert.Equal(t, reauthNotNeeded, reauthDecision(&c, fresh, now, false))
	assert.Equal(t, reauthRedirect, reauthDecision(&c, stale, now, true))
	assert.Equal(t, reauthNotNeeded, reauthDecision(&c, stale, now, false))
	assert.Equal(t, reauthRedirect, reauthDecision(&c, dead, now, true))
	assert.Equal(t, reauthRejected, reauthDecision(&c, dead, now, false))
	// Legacy cookies and cookies "from the future" count as stale.
	assert.Equal(t, reauthRedirect, reauthDecision(&c, time.Time{}, now, true))
	assert.Equal(t, reauthRejected, reauthDecision(&c, time.Time{}, now, false))
	assert.Equal(t, reauthRejected, reauthDecision(&c, now.Add(time.Hour), now, false))
}

func TestIsNavigation(t *testing.T) {
	req := func(method string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(method, "http://proxy.url/", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}

	assert.True(t, isNavigation(req("GET", map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "*/*"})))
	assert.False(t, isNavigation(req("GET", map[string]string{"Sec-Fetch-Mode": "cors", "Accept": "text/html"})))
	assert.False(t, isNavigation(req("GET", map[string]string{"Sec-Fetch-Mode": "no-cors"})))
	assert.True(t, isNavigation(req("GET", map[string]string{"Accept": "text/html,application/xhtml+xml"})))
	assert.False(t, isNavigation(req("GET", map[string]string{"Accept": "application/json"})))
	assert.False(t, isNavigation(req("POST", map[string]string{"Accept": "text/html"})))
}

// End to end through the handler: a stale cookie redirects page loads to the
// SSO provider and rejects fetches once the grace period is over.
func TestStaleCookieThroughHandler(t *testing.T) {
	c := NewTestConfig()
	c.AllowAll = true
	c.CookieSecret = "cookiesecret"
	c.SSOURLString = c.SSOURL.String() // memoised by ParseConfig, not by NewTestConfig
	c.ReauthorizeInterval = 15 * time.Minute
	c.ReauthorizeGrace = time.Hour
	config = &c

	handler := authProxyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("username-header"))
	}))
	do := func(issued time.Time, mode string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://proxy.url/page", nil)
		r.Header.Set("Sec-Fetch-Mode", mode)
		data := "sam,group," + strconv.FormatInt(issued.Unix(), 10)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: signCookie(data, c.CookieSecret)})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	now := time.Now()
	fresh := do(now.Add(-time.Minute), "navigate")
	assert.Equal(t, 200, fresh.Code)
	assert.Equal(t, "sam", fresh.Body.String())

	stale := do(now.Add(-20*time.Minute), "navigate")
	assert.Equal(t, 302, stale.Code)
	assert.True(t, strings.HasPrefix(stale.Header().Get("Location"), "http://sso.url/session/sso_provider?"))

	assert.Equal(t, 200, do(now.Add(-20*time.Minute), "cors").Code)
	assert.Equal(t, 401, do(now.Add(-2*time.Hour), "cors").Code)
}

func TestNewCookieLifetime(t *testing.T) {
	c := NewTestConfig()
	assert.Equal(t, defaultCookieLifetime, cookieLifetime(&c))
	c.ReauthorizeInterval = 15 * time.Minute
	c.ReauthorizeGrace = time.Hour
	assert.Equal(t, 75*time.Minute, cookieLifetime(&c))
}
