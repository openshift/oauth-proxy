OpenShift oauth-proxy
=====================

test change

A reverse proxy and static file server that provides authentication and authorization to an OpenShift OAuth
server or Kubernetes master supporting the 1.6+ remote authorization endpoints to validate access to content.
It is intended for use within OpenShift clusters to make it easy to run both end-user and infrastructure
services that don't provide their own authentication.

Features:

* Performs zero-configuration OAuth when run as a pod in OpenShift
* Able to perform simple authorization checks against the OpenShift and Kubernetes RBAC policy engine to grant access
* May also be configured to check bearer tokens or Kubernetes client certificates and verify access
* On OpenShift 3.6+ clusters, supports zero-configuration end-to-end TLS via the out of the box router

This is a fork of the https://github.com/bitly/oauth2_proxy project with other providers removed (for now). It's
focused on providing the simplest possible secure proxy on OpenShift

![Sign In Page](https://raw.githubusercontent.com/openshift/oauth-proxy/master/front.png)

## Using this proxy with OpenShift

This proxy is best used as a sidecar container in a Kubernetes pod, protecting another server that listens
only on localhost. On an OpenShift cluster, it can use the service account token as an OAuth client secret
to identify the current user and perform access control checks. For example:

    $ ./oauth-proxy --upstream=http://localhost:8080 --cookie-secret=SECRET \
          --openshift-service-account=default --https-address=

will start the proxy against localhost:8080, encrypt the login cookie with SECRET, use the default
service account in the current namespace, and only listen on http.

A full sidecar example is in [contrib/sidecar.yaml](contrib/sidecar.yaml) which also demonstrates using
OpenShift TLS service serving certificates (giving you an automatic in-cluster cert) with an external route.
Run against a 3.6+ cluster with:

    $ oc create -f https://raw.githubusercontent.com/openshift/oauth-proxy/master/contrib/sidecar.yaml

The OpenShift provider defaults to allowing any user that can log into the OpenShift cluster - the following
sections cover more on restricting access.

### Limiting access to users

While you can use the `--email-domains` and `--authenticated-emails-file` to match users directly,
the proxy works best when you delegate authorization to the OpenShift master by specifying what permissions
you expect the user to have. This allows you to leverage OpenShift RBAC and groups to map users to
permissions centrally.

#### Require specific permissions to login via OAuth with `--openshift-sar=JSON`

SAR stands for "Subject Access Review", which is a request sent to the OpenShift or Kubernetes server
to check the access for a particular user. Expects a single subject access review JSON object, or
a JSON array, all of which must be satisfied for a user to be able to access the backend server.

Pros:

* Easiest way to protect an entire website or API with an OAuth flow
* Requires no additional permissions to be granted for the proxy service account

Cons:

* Not well suited for service-to-service access
* All-or-nothing protection for the upstream server

Example:

    # Allows access if the user can view the service 'proxy' in namespace 'app-dev'
    --openshift-sar='{"namespace":"app-dev","resource":"services","resourceName":"proxy","verb":"get"}'

A user who visits the proxy will be redirected to an OAuth login with OpenShift, and must grant
access to the proxy to view their user info and request permissions for them. Once they have granted
that right to the proxy, it will check whether the user has the required permissions. If they do 
not, they'll be given a permission denied error. If they are, they'll be logged in via a cookie.

Run `oc explain subjectaccessreview` to see the schema for a review, including other fields.
Specifying multiple rules via a JSON array (`[{...}, {...}]`) will require all permissions to
be granted.

##### Require specific permissions per host with `--openshift-sar-by-host=JSON`

This is similar to the `--openshift-sar` option but instead of the rules applying to all hosts, you
can set up specific rules that are checked for a particular upstream host. Using a JSON object the
keys are hostnames and the value is a JSON array of SAR rules.

Both `--openshift-sar` and `--openshift-sar-by-host` can be used together which will require all
of the rules from the former as well as any rules that match the host to be satisified for a user
to be able to access the backed server.

Example:

    # Allows access to foo.example.com if the user can view the service 'proxy' in namespace 'app-dev'
    --openshift-sar-by-host='{"foo.example.com":{"namespace":"app-dev","resource":"services","resourceName":"proxy","verb":"get"}}'

#### Delegate authentication and authorization to OpenShift for infrastructure

OpenShift leverages bearer tokens for end users and for service accounts. When running
infrastructure services, it may be easier to delegate all authentication and authoration to
the master. The `--openshift-delegate-urls=JSON` flag enables delegation, asking the master
to validate any incoming requests with an `Authorization: Bearer` header or client certificate
to be forwarded to the master for verification. If the user authenticates, they are then
checked against one of the entries in the provided map

The value of the flag is a JSON map of path prefixes to `v1beta1.ResourceAttributes`, and the 
longest path prefix is checked. If no path matches the request, authentication and authorization
are skipped.

Pros:

* Allow other OpenShift service accounts or infrastructure components to authorize to specific APIs

Cons:

* Not suited for web browser use
* Should not be used by untrusted components (can steal tokens)

Example:

    # Allows access if the provided bearer token has view permission on a custom resource
    --openshift-delegate-urls='{"/":{"group":"custom.group","resource":"myproxy","verb":"get"}}'

    # Grant access only to paths under /api
    --openshift-delegate-urls='{"/api":{"group":"custom.group","resource":"myproxy","verb":"get"}}'

WARNING: Because users are sending their own credentials to the proxy, it's important to use this 
setting only when the proxy is under control of the cluster administrators. Otherwise, end users 
may unwittingly provide their credentials to untrusted components that can then act as them.

When configured for delegation, Oauth Proxy will not set the `X-Forwarded-Access-Token` header on
the upstream request. If you wish to forward the bearer token received from the client, you will
have to use the `--pass-user-bearer-token` option in addition to `--openshift-delegate-urls`.

WARNING: With `--pass-user-bearer-token` the client's bearer token will be passed upstream. This
could pose a security risk if the token is misused or leaked from the upstream service. Bear in
mind that the tokens received from client could be long term and hard to revoke.

### Other configuration flags

#### `--openshift-service-account=NAME`

Will attempt to read the `--client-id` and `--client-secret` from the service account information 
injected by OpenShift. Uses the value of `/var/run/secrets/kubernetes.io/serviceaccount/namespace`
to build the correct `--client-id`, and the contents of 
`/var/run/secrets/kubernetes.io/serviceaccount/token` as the `--client-secret`.

#### `--openshift-ca`

One or more paths to CA certificates that should be used when connecting to the OpenShift master.
If none are provided, the proxy will default to using `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.


### Discovering the OAuth configuration of an OpenShift cluster

OpenShift supports the `/.well-known/oauth-authorization-server` endpoint, which returns a JSON document
describing the authorize and token URLs, as well as the default scopes. If you are running outside
of OpenShift you can specify these flags directly using the existing flags for these URLs.


### Configuring the proxy's service account in OpenShift

In order for service accounts to be used as OAuth clients, they must have the [proper OAuth annotations set](https://docs.openshift.org/latest/architecture/additional_concepts/authentication.html#service-accounts-as-oauth-clients).
to point to a valid external URL. In most cases, this can be a route exposing the service fronting your
proxy. We recommend using a `Reencrypt` type route and [service serving certs](https://docs.openshift.org/latest/dev_guide/secrets.html#service-serving-certificate-secrets) to maximize end to end
security. See [contrib/sidecar.yaml](contrib/sidecar.yaml) for an example of these used in concert. 

By default, the redirect URI of a service account set up as an OAuth client must point to an HTTPS endpoint which
is a common configuration error.


## Developing

To build, ensure you are running Go 1.7+ and clone the repo:

```
$ go get -u github.com/openshift/oauth-proxy
$ cd $GOPATH/src/github.com/openshift/oauth-proxy
```

To build, run:

```
$ go test .
```

The docker images for this repository are built by [the OpenShift release process](https://github.com/openshift/release/blob/master/projects/oauth-proxy/pipeline.yaml) and are available at

```
$ docker pull registry.svc.ci.openshift.org/ci/oauth-proxy:v1
```

## End-to-end testing

To run the end-to-end test suite against a build of the current commit on an OpenShift cluster, use test/e2e.sh. You may need to change the DOCKER_REPO, KUBECONFIG, and TEST_NAMESPACE variables to accommodate your cluster. 
Each test sets up an oauth-proxy deployment and steps through the OAuth process, ensuring that the backend site can be reached (or not, depending on the test). The deployment is deleted before running the next test.
DEBUG_TEST=testname can be used to skip the cleanup step for a specific test and halt the suite to allow for further debugging on the cluster.

$ test/e2e.sh

## Architecture

![OAuth2 Proxy Architecture](https://cloud.githubusercontent.com/assets/45028/8027702/bd040b7a-0d6a-11e5-85b9-f8d953d04f39.png)


## Configuration

`oauth-proxy` can be configured via [config file](#config-file), [command line options](#command-line-options) or [environment variables](#environment-variables).

To generate a strong cookie secret use `python -c 'import os,base64; print base64.b64encode(os.urandom(16))'`

### Email Authentication

To authorize by email domain use `--email-domain=yourcompany.com`. To authorize individual email addresses use `--authenticated-emails-file=/path/to/file` with one email per line. To authorize all email addresses use `--email-domain=*`.

### Config File

An example [oauth-proxy.cfg](contrib/oauth-proxy.cfg.example) config file is in the contrib directory. It can be used by specifying `-config=/etc/oauth-proxy.cfg`

### Command Line Options

```
Usage of oauth-proxy:
  -approval-prompt string: OAuth approval_prompt (default "force")
  -authenticated-emails-file string: authenticate against emails via file (one per line)
  -basic-auth-password string: the password to set when passing the HTTP Basic Auth header
  -bypass-auth-except-for value: provide authentication ONLY for request paths under proxy-prefix and those that match the given regex (may be given multiple times). Cannot be set with -skip-auth-regex
  -bypass-auth-for value: alias for -skip-auth-regex
  -client-id string: the OAuth Client ID: ie: "123456.apps.googleusercontent.com"
  -client-secret string: the OAuth Client Secret
  -config string: path to config file
  -cookie-domain string: an optional cookie domain to force cookies to (ie: .yourcompany.com)*
  -cookie-expire duration: expire timeframe for cookie (default 168h0m0s)
  -cookie-httponly: set HttpOnly cookie flag (default true)
  -cookie-name string: the name of the cookie that the oauth_proxy creates (default "_oauth2_proxy")
  -cookie-refresh duration: refresh the cookie after this duration; 0 to disable
  -cookie-samesite string | set SameSite cookie attribute (ie: `"lax"`, `"strict"`, `"none"`, or `""`)
  -cookie-secret string: the seed string for secure cookies (optionally base64 encoded)
  -cookie-secret-file string: same as "-cookie-secret" but read it from a file
  -cookie-secure: set secure (HTTPS) cookie flag (default true)
  -custom-templates-dir string: path to custom html templates
  -display-htpasswd-form: display username / password login form if an htpasswd file is provided (default true)
  -email-domain value: authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email
  -footer string: custom footer string. Use "-" to disable default footer.
  -htpasswd-file string: additionally authenticate against a htpasswd file. Entries must be created with "htpasswd -s" for SHA encryption
  -http-address string: [http://]<addr>:<port> or unix://<path> to listen on for HTTP clients (default "127.0.0.1:4180")
  -https-address string: <addr>:<port> to listen on for HTTPS clients (default ":443")
  -login-url string: Authentication endpoint
  -pass-access-token: pass OAuth access_token to upstream via X-Forwarded-Access-Token header
  -pass-user-bearer-token: pass OAuth access token received from the client to upstream via X-Forwarded-Access-Token header
  -pass-basic-auth: pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -pass-host-header: pass the request Host Header to upstream (default true)
  -pass-user-headers: pass X-Forwarded-User and X-Forwarded-Email information to upstream (default true)
  -profile-url string: Profile access endpoint
  -provider string: OAuth provider (default "google")
  -proxy-prefix string: the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in) (default "/oauth")
  -proxy-websockets: enables WebSocket proxying (default true)
  -redeem-url string: Token redemption endpoint
  -redirect-url string: the OAuth Redirect URL. ie: "https://internalapp.yourcompany.com/oauth2/callback"
  -request-logging: Log requests to stdout (default false)
  -scope string: OAuth scope specification
  -set-xauthrequest: set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)
  -signature-key string: GAP-Signature request signature key (algorithm:secretkey)
  -skip-auth-preflight: will skip authentication for OPTIONS requests
  -skip-auth-regex value: bypass authentication for requests path's that match (may be given multiple times). Cannot be set with -bypass-auth-except-for
  -skip-provider-button: will skip sign-in-page to directly reach the next step: oauth/start
  -ssl-insecure-skip-verify: skip validation of certificates presented when using HTTPS
  -tls-cert string: path to certificate file
  -tls-key string: path to private key file
  -upstream value: the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path
  -upstream-timeout duration: maximum amount of time the server will wait for a response from the upstream (default 30s)
  -validate-url string: Access token validation endpoint
  -version: print version string
```

See below for provider specific options

### Upstream Configuration

`oauth-proxy` supports having multiple upstreams, and has the option to pass requests on to HTTP(S) servers or serve static files from the file system. HTTP and HTTPS upstreams are configured by providing a URL such as `http://127.0.0.1:8080/` for the upstream parameter, that will forward all authenticated requests to be forwarded to the upstream server. If you instead provide `http://127.0.0.1:8080/some/path/` then it will only be requests that start with `/some/path/` which are forwarded to the upstream.

Static file paths are configured as a file:// URL. `file:///var/www/static/` will serve the files from that directory at `http://[oauth-proxy url]/var/www/static/`, which may not be what you want. You can provide the path to where the files should be available by adding a fragment to the configured URL. The value of the fragment will then be used to specify which path the files are available at. `file:///var/www/static/#/static/` will ie. make `/var/www/static/` available at `http://[oauth-proxy url]/static/`.

Multiple upstreams can either be configured by supplying a comma separated list to the `-upstream` parameter, supplying the parameter multiple times or provinding a list in the [config file](#config-file). When multiple upstreams are used routing to them will be based on the path they are set up with.

### Environment variables

The following environment variables can be used in place of the corresponding command-line arguments:

- `OAUTH2_PROXY_CLIENT_ID`
- `OAUTH2_PROXY_CLIENT_SECRET`
- `OAUTH2_PROXY_COOKIE_NAME`
- `OAUTH2_PROXY_COOKIE_SAMESITE`
- `OAUTH2_PROXY_COOKIE_SECRET`
- `OAUTH2_PROXY_COOKIE_DOMAIN`
- `OAUTH2_PROXY_COOKIE_EXPIRE`
- `OAUTH2_PROXY_COOKIE_REFRESH`
- `OAUTH2_PROXY_SIGNATURE_KEY`

## SSL Configuration

There are two recommended configurations.

1) Configure SSL Terminiation with OAuth2 Proxy by providing a `--tls-cert=/path/to/cert.pem` and `--tls-key=/path/to/cert.key`.

The command line to run `oauth-proxy` in this configuration would look like this:

```bash
./oauth-proxy \
   --email-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --tls-cert=/path/to/cert.pem \
   --tls-key=/path/to/cert.key \
   --cookie-secret=... \
   --cookie-secure=true \
   --provider=... \
   --client-id=... \
   --client-secret=...
```


2) Configure SSL Termination with [Nginx](http://nginx.org/) (example config below), Amazon ELB, Google Cloud Platform Load Balancing, or ....

Because `oauth-proxy` listens on `127.0.0.1:4180` by default, to listen on all interfaces (needed when using an
external load balancer like Amazon ELB or Google Platform Load Balancing) use `--http-address="0.0.0.0:4180"` or
`--http-address="http://:4180"`.

Nginx will listen on port `443` and handle SSL connections while proxying to `oauth-proxy` on port `4180`.
`oauth-proxy` will then authenticate requests for an upstream application. The external endpoint for this example
would be `https://internal.yourcompany.com/`.

An example Nginx config follows. Note the use of `Strict-Transport-Security` header to pin requests to SSL
via [HSTS](http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security):

```
server {
    listen 443 default ssl;
    server_name internal.yourcompany.com;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/cert.key;
    add_header Strict-Transport-Security max-age=2592000;

    location / {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Scheme $scheme;
        proxy_connect_timeout 1;
        proxy_send_timeout 30;
        proxy_read_timeout 30;
    }
}
```

The command line to run `oauth-proxy` in this configuration would look like this:

```bash
./oauth-proxy \
   --email-domain="yourcompany.com"  \
   --upstream=http://127.0.0.1:8080/ \
   --cookie-secret=... \
   --cookie-secure=true \
   --provider=... \
   --client-id=... \
   --client-secret=...
```

## Endpoint Documentation

oauth-proxy responds directly to the following endpoints. All other endpoints will be proxied upstream when authenticated. The `/oauth` prefix can be changed with the `--proxy-prefix` config variable.

* /robots.txt - returns a 200 OK response that disallows all User-agents from all paths; see [robotstxt.org](http://www.robotstxt.org/) for more info
* /oauth/healthz - returns an 200 OK response
* /oauth/sign_in - the login page, which also doubles as a sign out page (it clears cookies)
* /oauth/start - a URL that will redirect to start the OAuth cycle
* /oauth/callback - the URL used at the end of the OAuth cycle. The oauth app will be configured with this as the callback url.
* /oauth/auth - only returns a 202 Accepted response or a 401 Unauthorized response; for use with the [Nginx `auth_request` directive](#nginx-auth-request)

## Request signatures

If `signature-key` is defined, proxied requests will be signed with the
`GAP-Signature` header, which is a [Hash-based Message Authentication Code
(HMAC)](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
of selected request information and the request body [see `SIGNATURE_HEADERS`
in `oauthproxy.go`](./oauthproxy.go).

`signature_key` must be of the form `algorithm:secretkey`, (ie: `signature_key = "sha1:secret0"`)

For more information about HMAC request signature validation, read the
following:

* [Amazon Web Services: Signing and Authenticating REST
  Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
* [rc3.org: Using HMAC to authenticate Web service
  requests](http://rc3.org/2011/12/02/using-hmac-to-authenticate-web-service-requests/)

## Logging Format

oauth-proxy logs requests to stdout in a format similar to Apache Combined Log.

```
<REMOTE_ADDRESS> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

## <a name="nginx-auth-request"></a>Configuring for use with the Nginx `auth_request` directive

The [Nginx `auth_request` directive](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) allows Nginx to authenticate requests via the oauth-proxy's `/auth` endpoint, which only returns a 202 Accepted response or a 401 Unauthorized response without proxying the request through. For example:

```nginx
server {
  listen 443 ssl spdy;
  server_name ...;
  include ssl/ssl.conf;

  location = /oauth2/auth {
    internal;
    proxy_pass http://127.0.0.1:4180;
  }

  location /oauth2/ {
    proxy_pass       http://127.0.0.1:4180;
    proxy_set_header Host                    $host;
    proxy_set_header X-Real-IP               $remote_addr;
    proxy_set_header X-Scheme                $scheme;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
  }

  location /upstream/ {
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in;

    # pass information via X-User and X-Email headers to backend,
    # requires running with --set-xauthrequest flag
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $email  $upstream_http_x_auth_request_email;
    proxy_set_header X-User  $user;
    proxy_set_header X-Email $email;

    proxy_pass http://backend/;
  }

  location / {
    auth_request /oauth2/auth;
    error_page 401 = https://example.com/oauth2/sign_in;

    root /path/to/the/site;
  }
}
```
