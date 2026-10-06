# Architecture

## Overview

`oauth-proxy` sits in front of HTTP(S) applications or static files. It supports interactive OpenShift OAuth, validates the resulting session, optionally authorizes the user through Kubernetes APIs, and proxies requests with configured identity headers. It is commonly a sidecar beside an application listening only inside the pod.

```text
browser/API client
  -> HTTP/HTTPS server (http.go)
  -> OAuthProxy.ServeHTTP (oauthproxy.go)
       -> OAuth endpoints -> OpenShift OAuth server
       -> session/authz   -> Kubernetes/OpenShift API
       -> delegated authn/authz for bearer tokens or client certificates
  -> HTTP(S), WebSocket, or file upstream
```

## Startup and Configuration

`main.go` defines flags, reads an optional TOML file, applies supported environment variables, and resolves them into `Options`. `options.go` validates configuration and parses upstream and redirect URLs. The OpenShift provider can discover cluster OAuth endpoints and, with `--openshift-service-account`, derive the client ID from the namespace/account and read the mounted token as its client secret.

Startup constructs `OAuthProxy`, optionally loads htpasswd data and a pprof listener, then serves until SIGTERM or interrupt cancels the root context. HTTPS serving certificates are watched and reloaded.

## Request Flow

With the default `--proxy-prefix=/oauth`, proxy-owned paths are:

| Path | Purpose |
| --- | --- |
| `/robots.txt` | Disallow crawlers |
| `/oauth/healthz` | Liveness |
| `/oauth/sign_in`, `/oauth/sign_out` | Login UI and session removal |
| `/oauth/start`, `/oauth/callback` | Start and complete OAuth |
| `/oauth/auth` | Accepted/unauthorized response for `auth_request` |

For an ordinary request, the proxy applies protected-path and bypass rules; verifies and refreshes the session cookie; falls back to Basic Auth or delegated authentication when no session remains; validates identity rules and SubjectAccessReviews; normalizes untrusted header variants; adds configured trusted headers; and dispatches to the selected upstream. An unauthenticated browser enters OAuth, while failed delegated API authentication returns an error.

## OpenShift Provider

The provider contract is in `providers/providers.go`; the binary currently selects only OpenShift. `providers/openshift/` implements OAuth discovery/redemption/user lookup, session refresh, global and host-specific access reviews, TokenAccessReview and client-certificate authentication, SubjectAccessReview authorization, caches, and cluster CA handling.

`--openshift-sar` checks an interactively logged-in identity. `--openshift-delegate-urls` authenticates credentials supplied on the request and authorizes the longest matching path. Delegated bearer tokens are forwarded only when `--pass-user-bearer-token` is also enabled, extending the security boundary to the upstream.

## Sessions, Upstreams, and Headers

Session state lives in `providers/session_state.go`. Cookies are signed; contents are encrypted when token storage or refresh requires it. A separate CSRF cookie binds callback to login. Serialization is a compatibility boundary requiring tampering, expiry, and round-trip tests.

Each `--upstream` is registered by URL path. HTTP(S) uses Go's reverse proxy with HTTP/2 transport, WebSocket upgrades use the WebSocket proxy, and `file://` serves local files. Encoded paths are deliberately preserved.

Client-supplied variants of identity headers are normalized and removed. Configuration controls Basic Auth, `X-Forwarded-*`, access-token, and `X-Auth-Request-*` headers. Optional `GAP-Signature` HMAC protects selected request data for an upstream that verifies it.

## TLS

HTTP accepts TCP or Unix-socket addresses. HTTPS uses OpenShift secure TLS defaults and dynamically reloads its certificate/key. Upstream and OpenShift CA bundles have separate trust pools. Insecure certificate verification is a legacy escape hatch and should not be used in production.

