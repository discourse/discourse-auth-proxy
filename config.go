package main

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/namsral/flag"
	"github.com/pborman/uuid"
)

type Config struct {
	OriginURL      *url.URL
	ProxyURL       *url.URL
	ProxyURLString string // memoised - derives from ProxyURL
	ListenAddr     string
	SSOURL         *url.URL
	SSOURLString   string // memoised - derives from SSOURL
	SSOSecret      string
	CookieSecret   string
	AllowAll       bool
	BasicAuth      string
	Whitelist      string
	UsernameHeader string
	GroupsHeader   string
	Timeout        time.Duration
}

func ParseConfig() (*Config, error) {
	missing := func(name string) error {
		return fmt.Errorf("missing mandatory flag: %s", name)
	}

	rc := parseRawConfig()

	if *rc.OriginURL == "" {
		return nil, missing("origin-url")
	}
	if *rc.ProxyURL == "" {
		return nil, missing("proxy-url")
	}
	if *rc.SSOURL == "" {
		return nil, missing("sso-url")
	}
	if *rc.SSOSecret == "" {
		return nil, missing("sso-secret")
	}

	c := &Config{}
	{
		u, err := url.Parse(*rc.OriginURL)
		if err != nil {
			return nil, fmt.Errorf("invalid origin URL: %s", rc.OriginURL)
		}
		c.OriginURL = u
	}
	{
		u, err := url.Parse(*rc.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %s", rc.ProxyURL)
		}
		c.ProxyURL = u
		c.ProxyURLString = u.String()
	}
	{
		u, err := url.Parse(*rc.SSOURL)
		if err != nil {
			return nil, fmt.Errorf("invalid SSO URL - should point at Discourse site with enable sso: %s", rc.SSOURL)
		}
		c.SSOURL = u
		c.SSOURLString = u.String()
	}

	if *rc.ListenURL == "" {
		c.ListenAddr = c.ProxyURL.Host
	} else {
		c.ListenAddr = *rc.ListenURL
	}

	c.SSOSecret = *rc.SSOSecret
	c.AllowAll = *rc.AllowAll
	c.BasicAuth = *rc.BasicAuth
	c.Whitelist = *rc.Whitelist
	c.UsernameHeader = *rc.UsernameHeader
	c.GroupsHeader = *rc.GroupsHeader
	c.Timeout = time.Duration(*rc.Timeout) * time.Second

	c.CookieSecret = uuid.New()

	return c, nil
}

type rawConfig struct {
	OriginURL      *string
	ProxyURL       *string
	ListenURL      *string // Not actually a URL.  This is a TCP socket address, i.e.: 'host:port'.
	SSOURL         *string
	SSOSecret      *string
	AllowAll       *bool
	BasicAuth      *string
	Whitelist      *string
	UsernameHeader *string
	GroupsHeader   *string
	Timeout        *int
}

func parseRawConfig() *rawConfig {
	c := &rawConfig{
		OriginURL:      flag.String("origin-url", "", "origin to proxy eg: http://localhost:2002"),
		ProxyURL:       flag.String("proxy-url", "", "outer url of this host eg: http://secrets.example.com"),
		ListenURL:      flag.String("listen-url", "", "url to listen on eg: localhost:2001. leave blank to set equal to proxy-url"),
		SSOURL:         flag.String("sso-url", "", "SSO endpoint eg: http://discourse.forum.com"),
		SSOSecret:      flag.String("sso-secret", "", "SSO secret for origin"),
		AllowAll:       flag.Bool("allow-all", false, "allow all discourse users (default: admin users only)"),
		BasicAuth:      flag.String("basic-auth", "", "HTTP Basic authentication credentials to let through directly"),
		Whitelist:      flag.String("whitelist", "", "Path which does not require authorization"),
		UsernameHeader: flag.String("username-header", "Discourse-User-Name", "Request header to pass authenticated username into"),
		GroupsHeader:   flag.String("groups-header", "Discourse-User-Groups", "Request header to pass authenticated groups into"),
		Timeout:        flag.Int("timeout", 10, "Read/write timeout"),
	}
	flag.Parse()
	return c
}

func usage(err error) {
	flag.Usage()
	if err != nil {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(2)
}
