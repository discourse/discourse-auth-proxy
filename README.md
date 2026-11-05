Discourse Auth Proxy
===

This package allows you to use Discourse as an SSO endpoint for an arbitrary site.

Discourse SSO is invoked prior to serving the proxied site. This allows you to reuse Discourse Auth in a site that ships with no auth.

Usage:

```
Usage of ./discourse-auth-proxy:
  -listen-url="": uri to listen on eg: localhost:2001. leave blank to set equal to proxy-url
  -origin-url="": origin to proxy eg: http://localhost:2002
  -proxy-url="": outer url of this host eg: http://secrets.example.com
  -sso-secret="": SSO secret for origin
  -sso-url="": SSO endpoint eg: http://discourse.example.com
  -allow-all: don't restrict access to "admin" users on the SSO endpoint
  -timeout="10": Read/Write timeout
  -reauthorize-interval=0: re-run the SSO round trip on page loads once the auth cookie is older than this (e.g. 15m)
  -reauthorize-grace=0: extra validity of a stale cookie for requests that are not page loads (fetch/XHR)
```

Re-authorization
---

By default the auth cookie is valid for a year: a user who logs out of Discourse, or whose account
gets suspended, keeps access until the cookie expires or the proxy restarts (the cookie secret is
generated at startup).

With `-reauthorize-interval` (env `REAUTHORIZE_INTERVAL`) the cookie records when it was issued, and a
page load with an older cookie goes through `/session/sso_provider` again. While the Discourse session
is alive this is two invisible redirects; after a logout or suspension the user lands on the Discourse
login page. Requests that cannot follow a cross-origin redirect (`fetch`/XHR, detected via
`Sec-Fetch-Mode`) are served for another `-reauthorize-grace` and get `401` afterwards.

```
+--------+    proxy-url   +---------+    listen-url    +----------------------+
|  User  |  ============> |  Nginx  |  ==============> | discourse-auth-proxy |
+--------+                +---------+                  +----------------------+
    |                                                             |
    | sso-url                                          origin-url |
    |                                                             |
    v                                                             v
+-----------+                                          +----------------------+
| Discourse |                                          | Protected web server |
+-----------+                                          +----------------------+
```

Environment variables may be used as a substitute for command-line flags, e.g.:

``` shell
ORIGIN_URL='http://somesite.com' \
PROXY_URL='http://listen.com' \
SSO_SECRET='somesecret' \
SSO_URL='http://somediscourse.com' \
./discourse-auth-proxy
```

`-origin-url` may specify a name equipped with [RFC 2782](https://tools.ietf.org/html/rfc2782) DNS SRV records, such as `http://_foo._tcp.example.com`.  If SRV records are found in the DNS, each request is proxied to a host and port taken from these records.


Docker Image
===

You may run using docker using

```
docker run discourse/auth-proxy
```

Running will display configuration instructions

A new OCI image is automatically published to [Docker Hub](https://hub.docker.com/r/discourse/auth-proxy/tags) upon every push to branch `main` on GitHub.  The release procedure is documented in t/120578 for the benefit of CDCK staff.
