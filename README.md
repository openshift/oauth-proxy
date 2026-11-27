# OpenShift oauth-proxy

`oauth-proxy` is a reverse proxy and static file server that authenticates requests with OpenShift OAuth before forwarding them upstream. It can also delegate bearer-token or client-certificate authentication and authorization to the Kubernetes API.

It is usually deployed as a sidecar beside an application that listens only inside the pod. A Service and Route expose the proxy while the application remains unreachable directly.

Capabilities include automatic OAuth client configuration from an OpenShift service account, SubjectAccessReview authorization, delegated API authentication, path-based HTTP(S)/WebSocket/file upstreams, signed sessions with CSRF protection, and dynamic serving-certificate reload.

![Sign-in page](front.png)

## Quick Start on OpenShift

This starts the proxy in front of localhost, uses the mounted `default` service account as its OAuth client, and listens over HTTP:

```sh
./oauth-proxy \
  --upstream=http://localhost:8080 \
  --cookie-secret="$(openssl rand -base64 32)" \
  --openshift-service-account=default \
  --https-address=
```

See [contrib/sidecar.yaml](contrib/sidecar.yaml) for a sidecar deployment with a Route and service-serving certificate. Replace its placeholder cookie secret; in production, inject it from a Kubernetes Secret instead of pod arguments or source control. The service account must have an OAuth redirect annotation matching the Route, as shown in the example.

## Authorization Modes

### Interactive OAuth and RBAC

By default, any authenticated user is accepted. Email rules can restrict identities, but OpenShift RBAC is usually the better policy source. `--openshift-sar` accepts one rule or an array; every rule must allow the user:

```sh
--openshift-sar='{"namespace":"app-dev","resource":"services","resourceName":"proxy","verb":"get"}'
```

Host-specific rules supplied with `--openshift-sar-by-host` are combined with global rules:

```sh
--openshift-sar-by-host='{"foo.example.com":{"namespace":"app-dev","resource":"services","resourceName":"proxy","verb":"get"}}'
```

### Delegated API Access

`--openshift-delegate-urls` validates credentials on an incoming request and authorizes the longest matching path prefix. This is intended for infrastructure APIs, not browser login:

```sh
--openshift-delegate-urls='{"/api":{"group":"example.io","resource":"widgets","verb":"get"}}'
```

Only use delegation when cluster administrators control the proxy: clients send credentials to it. Delegation does not forward bearer tokens upstream unless `--pass-user-bearer-token` is also set; that flag extends trust to the upstream application.

## Configuration

Configuration comes from an optional TOML file, supported environment variables, and command-line flags. Start with [contrib/oauth-proxy.cfg.example](contrib/oauth-proxy.cfg.example) and use `--config=/path/to/oauth-proxy.cfg`.

Run the binary's help for the authoritative flags and current defaults:

```sh
./oauth-proxy --help
```

| Option | Purpose |
| --- | --- |
| `--upstream` | HTTP(S) URL or `file://` tree; repeat for path routing |
| `--openshift-service-account` | Derive OAuth client credentials in-cluster |
| `--openshift-sar` | Require access-review rules |
| `--openshift-delegate-urls` | Delegate authn/authz on matching API paths |
| `--cookie-secret` / `--cookie-secret-file` | Always sign cookies; encrypt session token fields only when `--pass-access-token` or `--cookie-refresh` is enabled |
| `--tls-cert`, `--tls-key` | Serve HTTPS with dynamically reloaded files |
| `--upstream-ca`, `--openshift-ca` | Configure upstream and API trust roots |
| `--skip-auth-regex` | Bypass authentication on matching paths |
| `--proxy-prefix` | Set proxy-owned path prefix (default `/oauth`) |

Supported environment variables are the `env` tags on `Options` in `options.go`. They currently cover client credentials, cookie settings, and the request signature key. Prefer file-based secrets where available.

### Upstreams

Repeat `--upstream` to route different prefixes:

```sh
--upstream=http://127.0.0.1:8080/ \
--upstream=http://127.0.0.1:9090/api/
```

HTTP(S) upstreams support ordinary and WebSocket traffic. For files, a URL fragment selects the public path: `file:///var/www/assets/#/static/` serves that directory below `/static/`.

### TLS

For direct TLS termination, set `--tls-cert` and `--tls-key`; replacements are reloaded dynamically. To terminate TLS elsewhere, set `--https-address=` and explicitly configure the needed HTTP bind address. Keep `--cookie-secure=true` when browsers use public HTTPS.

Do not use `--ssl-insecure-skip-verify` in production. Configure the appropriate CA option instead.

## Proxy Endpoints

With the default `--proxy-prefix=/oauth`:

| Endpoint | Behavior |
| --- | --- |
| `/robots.txt` | Disallows crawlers |
| `/oauth/healthz` | Returns `200 OK` |
| `/oauth/sign_in`, `/oauth/sign_out` | Login UI and session removal |
| `/oauth/start`, `/oauth/callback` | Starts and completes OAuth |
| `/oauth/auth` | Returns accepted/unauthorized without proxying |

All other matched requests go upstream after applicable access checks.

## Forwarded Identity and Signing

Configuration can enable Basic Auth, `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Access-Token`, and `X-Auth-Request-*`. Treat the upstream as part of the security boundary when sensitive identity or token headers are enabled.

With `--signature-key=algorithm:secret`, proxied requests receive a `GAP-Signature` HMAC over selected request data. The upstream must verify it; signing does not encrypt traffic.

## Build and Test

Use the Go version declared by `go.mod` (currently 1.25). Dependencies are vendored.

```sh
make build
make test-unit
```

Cluster-dependent end-to-end tests require a configured OpenShift cluster and run serially with a three-hour timeout:

```sh
make test-e2e
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development details and [ARCHITECTURE.md](ARCHITECTURE.md) for internal design.

Container images are produced by the OpenShift release process. Use the image reference for the OpenShift release you target, rather than the obsolete CI-only `registry.svc.ci.openshift.org/ci/oauth-proxy:v1` reference.

## History

This project originated as an OpenShift-focused fork of Bitly's `oauth2_proxy`. The current binary supports the OpenShift provider.
