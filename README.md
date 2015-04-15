Discourse Auth Proxy
===

This package allows you to use Discourse as an SSO endpoint for an arbitrary site.

Discourse SSO is invoked prior to serving the proxied site. This allows you to reuse Discourse Auth in a site that ships with no auth.


Usage:

```
Usage of ./discourse-auth-proxy:
  -origin-url="": origin to proxy eg: http://somesecrethost:2001
  -proxy-url="": uri to listen on eg: http://localhost:2000
  -sso-secret="": SSO secret for origin
  -sso-url="": SSO endpoint eg: http://yourdiscourse.com
```

At the moment only "admin" users on the sso endpoint will be allowed through.

Note: you may use ENV vars as well to pass configuration EG:

ORIGIN_URL=http://somesite.com PROXY_URL=http://listen.com SSO_SECRET="somesecret" SSO_URL="http://somediscourse.com" ./discourse-auth-proxy
