# AGENTS.md

`oauth-proxy` is an OpenShift-focused reverse proxy that authenticates requests with the cluster OAuth server and can authorize them with Kubernetes APIs before forwarding them upstream.

## Commands

```sh
make build
make test-unit
go test ./providers/openshift/...
go test . -run TestName
make test-e2e # requires a configured OpenShift cluster; serial, 3h timeout
```

After dependency changes, run `go mod tidy`, `go mod vendor`, and the unit tests. The Makefile uses vendored `openshift/build-machinery-go`; inspect the included makefiles before assuming a target exists.

## Repository Map

```text
main.go                  flags, config loading, startup and shutdown
options.go               defaults and configuration validation
oauthproxy.go            OAuth handlers, sessions, routing and reverse proxy
http.go                  HTTP/HTTPS listeners and dynamic certificates
providers/openshift/     OpenShift OAuth, authentication and authorization
providers/               provider contract and session representation
cookie/                  signed and encrypted cookies
api/, util/              HTTP, certificate and file helpers
contrib/                 deployment and configuration examples
test/e2e/                cluster-dependent end-to-end tests
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for request flows and [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Engineering Rules

- Add co-located `*_test.go` coverage; prefer table-driven tests for related cases.
- Run `gofmt` on changed Go files and `make test-unit` before submitting.
- Keep flags in `main.go`, `Options` fields/tags/defaults in `options.go`, validation, examples, and tests aligned.
- Preserve `RequestURI`/`URL.Opaque` handling when changing proxy directors; it prevents encoded slash decoding. See `TestEncodedSlashes`.
- Strip or overwrite client-supplied authentication and forwarding headers before adding trusted identity headers. Include adversarial normalization tests.
- Propagate an available `context.Context` and keep shutdown/watchers tied to it.
- Use `library-go/pkg/crypto` secure TLS defaults. Do not weaken verification to make a deployment work.
- Never log or commit secrets, tokens, private keys, kubeconfigs, or real credentials.
- Never edit `vendor/` by hand; use Go module commands and commit all resulting changes.

Ask maintainers before changing public flags/defaults, endpoints, cookie formats, identity headers, OAuth scopes, or authentication/authorization cache semantics. Changes under `providers/openshift/` should consider interactive OAuth, delegated credentials, and SubjectAccessReview authorization, including malformed and deny paths.

