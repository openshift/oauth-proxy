package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mreiferson/go-options"
	"github.com/openshift/oauth-proxy/providers"
	"github.com/openshift/oauth-proxy/providers/openshift"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	flagSet := flag.NewFlagSet("oauth2_proxy", flag.ExitOnError)

	emailDomains := NewStringArray()
	upstreams := NewStringArray()
	skipAuthRegex := NewStringArray()
	bypassAuthRegex := NewStringArray()
	bypassAuthExceptRegex := NewStringArray()
	openshiftCAs := NewStringArray()
	clientCA := ""
	upstreamCAs := NewStringArray()

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":8443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.Duration("upstream-flush", time.Duration(5)*time.Millisecond, "force flush upstream responses after this duration(useful for streaming responses). 0 to never force flush. Defaults to 5ms")
	flagSet.String("tls-cert", "", "path to certificate file")
	flagSet.String("tls-key", "", "path to private key file")
	flagSet.StringVar(&clientCA, "tls-client-ca", clientCA, "path to a CA file for admitting client certificates.")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth/callback\"")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Var(upstreams, "upstream", "the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path")
	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-user-bearer-token", false, "pass OAuth access token received from the client to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Var(bypassAuthExceptRegex, "bypass-auth-except-for", "provide authentication ONLY for request paths under proxy-prefix and those that match the given regex (may be given multiple times). Cannot be set with -skip-auth-regex/-bypass-auth-for")
	flagSet.Var(bypassAuthRegex, "bypass-auth-for", "alias for skip-auth-regex")
	flagSet.Var(skipAuthRegex, "skip-auth-regex", "bypass authentication for request paths that match (may be given multiple times). Cannot be set with -bypass-auth-except-for. Alias for -bypass-auth-for")
	flagSet.Bool("skip-provider-button", false, "will skip sign-in-page to directly reach the next step: oauth/start")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS")
	flagSet.String("debug-address", "", "[http://]<addr>:<port> or unix://<path> to listen on for debug and requests")

	flagSet.Var(emailDomains, "email-domain", "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("client-secret-file", "", "a file containing the client-secret")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA password hashes or \"htpasswd -B\" for bcrypt hashes")
	flagSet.Bool("display-htpasswd-form", true, "display username / password login form if an htpasswd file is provided")
	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("footer", "", "custom footer string. Use \"-\" to disable default footer.")
	flagSet.String("proxy-prefix", "/oauth", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")

	flagSet.String("openshift-group", "", "restrict logins to members of this group (or groups, if encoded as a JSON array).")
	flagSet.String("openshift-sar", "", "require this encoded subject access review to authorize (may be a JSON list).")
	flagSet.String("openshift-sar-by-host", "", "require this encoded subject access review to authorize (must be a JSON array).")
	flagSet.Var(openshiftCAs, "openshift-ca", "paths to CA roots for the OpenShift API (may be given multiple times, defaults to /var/run/secrets/kubernetes.io/serviceaccount/ca.crt).")
	flagSet.String("openshift-review-url", "", "Permission check endpoint (defaults to the subject access review endpoint)")
	flagSet.String("openshift-delegate-urls", "", "If set, perform delegated authorization against the OpenShift API server. Value is a JSON map of path prefixes to v1beta1.ResourceAttribute records that must be granted to the user to continue. E.g. {\"/\":{\"resource\":\"pods\",\"namespace\":\"default\",\"name\":\"test\"}} only allows users who can see the pod test in namespace default.")
	flagSet.String("openshift-service-account", "", "An optional name of an OpenShift service account to act as. If set, the injected service account info will be used to determine the client ID and client secret.")

	flagSet.String("cookie-name", "_oauth_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.String("cookie-secret-file", "", "a file containing a cookie-secret")
	flagSet.String("cookie-domain", "", "an optional cookie domain to force cookies to (ie: .yourcompany.com)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")
	flagSet.String("cookie-samesite", "", "set SameSite cookie attribute (ie: \"lax\", \"strict\", \"none\", or \"\"). ")

	flagSet.Bool("request-logging", false, "Log requests to stdout")

	flagSet.String("provider", "openshift", "OAuth provider")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("logout-url", "", "absolute URL to redirect web browsers to after logging out of openshift oauth server")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("validate-url", "", "Access token validation endpoint")
	flagSet.String("scope", "", "OAuth scope specification")
	flagSet.String("approval-prompt", "force", "OAuth approval_prompt")

	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")
	flagSet.Var(upstreamCAs, "upstream-ca", "paths to CA roots for the Upstream (target) Server (may be given multiple times, defaults to system trust store).")

	providerOpenShift := openshift.New()
	providerOpenShift.Bind(flagSet)

	flagSet.Parse(os.Args[1:])

	providerOpenShift.SetClientCAFile(clientCA)
	providerOpenShift.SetReviewCAs(openshiftCAs.Get().([]string))

	if *showVersion {
		fmt.Printf("oauth2_proxy was built with %s\n", runtime.Version())
		return
	}

	opts := NewOptions()
	opts.TLSClientCAFile = clientCA

	cfg := make(EnvOptions)
	if *config != "" {
		_, err := toml.DecodeFile(*config, &cfg)
		if err != nil {
			log.Fatalf("ERROR: failed to load config file %s - %s", *config, err)
		}
	}
	cfg.LoadEnvForStruct(opts)
	options.Resolve(opts, flagSet, cfg)

	var p providers.Provider
	switch opts.Provider {
	case "openshift":
		p = providerOpenShift
	default:
		log.Printf("Invalid configuration: provider %q is not recognized", opts.Provider)
		os.Exit(1)
	}

	err := opts.Validate(p)
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy := NewOAuthProxy(opts, validator)

	if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}

	if opts.HtpasswdFile != "" {
		log.Printf("using htpasswd file %s", opts.HtpasswdFile)
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(opts.HtpasswdFile)
		oauthproxy.DisplayHtpasswdForm = opts.DisplayHtpasswdForm
		if err != nil {
			log.Fatalf("FATAL: unable to open %s %s", opts.HtpasswdFile, err)
		}
	}

	if opts.DebugAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("/debug/pprof/", http.DefaultServeMux)
		go func() {
			log.Fatalf("FATAL: unable to serve debug %s: %v", opts.DebugAddress, http.ListenAndServe(opts.DebugAddress, mux))
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-term
		log.Print("received SIGTERM, exiting gracefully...")
		cancel()
	}()

	var h http.Handler = oauthproxy
	if opts.RequestLogging {
		h = LoggingHandler(os.Stdout, h, true)
	}
	s := &Server{
		Handler: h,
		Opts:    opts,
	}
	s.ListenAndServe(ctx)
}
