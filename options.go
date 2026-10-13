package main

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/18F/hmacauth"

	oscrypto "github.com/openshift/library-go/pkg/crypto"

	"github.com/openshift/oauth-proxy/providers"
	"github.com/openshift/oauth-proxy/providers/openshift"
)

const (
	// DefaultUpstreamTimeout is the maximum duration a network dial to a upstream server for a response.
	DefaultUpstreamTimeout = 30 * time.Second
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	ProxyPrefix      string        `flag:"proxy-prefix" cfg:"proxy-prefix"`
	ProxyWebSockets  bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	HttpAddress      string        `flag:"http-address" cfg:"http_address"`
	HttpsAddress     string        `flag:"https-address" cfg:"https_address"`
	DebugAddress     string        `flag:"debug-address" cfg:"debug_address"`
	UpstreamFlush    time.Duration `flag:"upstream-flush" cfg:"upstream_flush"`
	RedirectURL      string        `flag:"redirect-url" cfg:"redirect_url"`
	ClientID         string        `flag:"client-id" cfg:"client_id" env:"OAUTH2_PROXY_CLIENT_ID"`
	ClientSecret     string        `flag:"client-secret" cfg:"client_secret" env:"OAUTH2_PROXY_CLIENT_SECRET"`
	ClientSecretFile string        `flag:"client-secret-file" cfg:"client_secret_file" env:"OAUTH2_PROXY_CLIENT_SECRET_FILE"`
	TLSCertFile      string        `flag:"tls-cert" cfg:"tls_cert_file"`
	TLSKeyFile       string        `flag:"tls-key" cfg:"tls_key_file"`
	TLSClientCAFile  string        `flag:"tls-client-ca" cfg:"tls_client_ca"`

	AuthenticatedEmailsFile string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	EmailDomains            []string `flag:"email-domain" cfg:"email_domains"`
	HtpasswdFile            string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	DisplayHtpasswdForm     bool     `flag:"display-htpasswd-form" cfg:"display_htpasswd_form"`
	CustomTemplatesDir      string   `flag:"custom-templates-dir" cfg:"custom_templates_dir"`
	Footer                  string   `flag:"footer" cfg:"footer"`

	OpenShiftSAR            string   `flag:"openshift-sar" cfg:"openshift_sar"`
	OpenShiftSARByHost      string   `flag:"openshift-sar-by-host" cfg:"openshift_sar_by_host"`
	OpenShiftReviewURL      string   `flag:"openshift-review-url" cfg:"openshift_review_url"`
	OpenShiftCAs            []string `flag:"openshift-ca" cfg:"openshift_ca"`
	OpenShiftServiceAccount string   `flag:"openshift-service-account" cfg:"openshift_service_account"`
	OpenShiftDelegateURLs   string   `flag:"openshift-delegate-urls" cfg:"openshift_delegate_urls"`

	CookieName       string        `flag:"cookie-name" cfg:"cookie_name" env:"OAUTH2_PROXY_COOKIE_NAME"`
	CookieSecret     string        `flag:"cookie-secret" cfg:"cookie_secret" env:"OAUTH2_PROXY_COOKIE_SECRET"`
	CookieSecretFile string        `flag:"cookie-secret-file" cfg:"cookie_secret_file" env:"OAUTH2_PROXY_COOKIE_SECRET_FILE"`
	CookieDomain     string        `flag:"cookie-domain" cfg:"cookie_domain" env:"OAUTH2_PROXY_COOKIE_DOMAIN"`
	CookieExpire     time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"OAUTH2_PROXY_COOKIE_EXPIRE"`
	CookieRefresh    time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh" env:"OAUTH2_PROXY_COOKIE_REFRESH"`
	CookieSecure     bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	CookieHttpOnly   bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`
	CookieSameSite   string        `flag:"cookie-samesite" cfg:"cookie_samesite" env:"OAUTH2_PROXY_COOKIE_SAMESITE"`

	Upstreams             []string `flag:"upstream" cfg:"upstreams"`
	BypassAuthExceptRegex []string `flag:"bypass-auth-except-for" cfg:"bypass_auth_except_for"`
	BypassAuthRegex       []string `flag:"bypass-auth-for" cfg:"bypass_auth_for"`
	SkipAuthRegex         []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	PassBasicAuth         bool     `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	BasicAuthPassword     string   `flag:"basic-auth-password" cfg:"basic_auth_password"`
	PassAccessToken       bool     `flag:"pass-access-token" cfg:"pass_access_token"`
	PassUserBearerToken   bool     `flag:"pass-user-bearer-token" cfg:"pass_user_bearer_token"`
	PassHostHeader        bool     `flag:"pass-host-header" cfg:"pass_host_header"`
	SkipProviderButton    bool     `flag:"skip-provider-button" cfg:"skip_provider_button"`
	PassUserHeaders       bool     `flag:"pass-user-headers" cfg:"pass_user_headers"`
	SSLInsecureSkipVerify bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	SetXAuthRequest       bool     `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SkipAuthPreflight     bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	Provider       string `flag:"provider" cfg:"provider"`
	LoginURL       string `flag:"login-url" cfg:"login_url"`
	RedeemURL      string `flag:"redeem-url" cfg:"redeem_url"`
	ProfileURL     string `flag:"profile-url" cfg:"profile_url"`
	ValidateURL    string `flag:"validate-url" cfg:"validate_url"`
	Scope          string `flag:"scope" cfg:"scope"`
	ApprovalPrompt string `flag:"approval-prompt" cfg:"approval_prompt"`
	RequestLogging bool   `flag:"request-logging" cfg:"request_logging"`

	SignatureKey string   `flag:"signature-key" cfg:"signature_key" env:"OAUTH2_PROXY_SIGNATURE_KEY"`
	UpstreamCAs  []string `flag:"upstream-ca" cfg:"upstream_ca"`

	// An optional, absolute URL to redirect web browsers to after logging out of
	// the console. If not specified, it will redirect to the default login page.
	// This is required when using an identity provider that supports single
	// sign-on (SSO) such as:
	// - OpenID (Keycloak, Azure)
	// - RequestHeader (GSSAPI, SSPI, SAML)
	// - OAuth (GitHub, GitLab, Google)
	// Logging out of the console will destroy the user's token. The logoutRedirect
	// provides the user the option to perform single logout (SLO) through the identity
	// provider to destroy their single sign-on session.
	LogoutRedirectURL string `flag:"logout-url" cfg:"logout_url"`

	// Timeout is the maximum duration the server will wait for a response from the upstream server.
	// Defaults to 30 seconds.
	Timeout time.Duration `flag:"upstream-timeout" cfg:"upstream_timeout"`

	// internal values that are set after config validation
	redirectURL       *url.URL
	proxyURLs         []*url.URL
	CompiledAuthRegex []*regexp.Regexp
	CompiledSkipRegex []*regexp.Regexp
	provider          providers.Provider
	signatureData     *SignatureData
}

type SignatureData struct {
	hash crypto.Hash
	key  string
}

func NewOptions() *Options {
	return &Options{
		ProxyPrefix:         "/oauth2",
		ProxyWebSockets:     true,
		HttpAddress:         "127.0.0.1:4180",
		HttpsAddress:        ":443",
		UpstreamFlush:       time.Duration(5) * time.Millisecond,
		DisplayHtpasswdForm: true,
		CookieName:          "_oauth2_proxy",
		CookieSecure:        true,
		CookieHttpOnly:      true,
		CookieExpire:        time.Duration(168) * time.Hour,
		CookieRefresh:       time.Duration(0),
		SetXAuthRequest:     false,
		SkipAuthPreflight:   false,
		PassBasicAuth:       true,
		PassUserHeaders:     true,
		PassAccessToken:     false,
		PassUserBearerToken: false,
		PassHostHeader:      true,
		ApprovalPrompt:      "force",
		RequestLogging:      true,
		Timeout:             DefaultUpstreamTimeout,
	}
}

func parseURL(to_parse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(to_parse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, to_parse, err))
	}
	return parsed, msgs
}

func (o *Options) Validate(p providers.Provider) error {
	msgs := make([]string, 0)

	// allow the provider to default some values
	switch provider := p.(type) {
	case *openshift.OpenShiftProvider:
		defaults, err := provider.LoadDefaults(o.OpenShiftServiceAccount, o.OpenShiftSAR, o.OpenShiftSARByHost, o.OpenShiftDelegateURLs)
		if err != nil {
			return err
		}
		if len(o.ClientID) == 0 {
			o.ClientID = defaults.ClientID
		}
		if len(o.ClientSecret) == 0 {
			o.ClientSecret = defaults.ClientSecret
		}
		if len(o.Scope) == 0 {
			o.Scope = defaults.Scope
		}
		if len(o.ValidateURL) == 0 && defaults.ValidateURL != nil {
			o.ValidateURL = defaults.ValidateURL.String()
		}
		if len(o.EmailDomains) == 0 {
			o.EmailDomains = []string{"*"}
		}
		if len(o.RedirectURL) == 0 {
			o.RedirectURL = "https:///"
		}
	}

	if o.CookieSecretFile != "" {
		if contents, err := ioutil.ReadFile(o.CookieSecretFile); err != nil {
			msgs = append(msgs, fmt.Sprintf("cannot read cookie-secret-file: %v", err))
		} else {
			o.CookieSecret = string(contents)
		}
	}
	if o.ClientSecretFile != "" {
		if contents, err := ioutil.ReadFile(o.ClientSecretFile); err != nil {
			msgs = append(msgs, fmt.Sprintf("cannot read client-secret-file: %v", err))
		} else {
			o.ClientSecret = string(contents)
		}
	}

	if len(o.Upstreams) < 1 {
		msgs = append(msgs, "missing setting: upstream")
	}
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o.ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}
	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required.\n      use email-domain=* to authorize all email addresses")
	}

	o.redirectURL, msgs = parseURL(o.RedirectURL, "redirect", msgs)

	o.proxyURLs = nil
	for _, u := range o.Upstreams {
		upstreamURL, err := url.Parse(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error parsing upstream=%q %s",
				upstreamURL, err))
			continue
		}
		if upstreamURL.Path == "" {
			upstreamURL.Path = "/"
		}
		o.proxyURLs = append(o.proxyURLs, upstreamURL)
	}

	if len(o.BypassAuthRegex) != 0 {
		o.SkipAuthRegex = o.BypassAuthRegex
	}

	if len(o.BypassAuthExceptRegex) != 0 && len(o.SkipAuthRegex) != 0 {
		msgs = append(msgs, "error: cannot set -skip-auth-regex and -bypass-auth-except-for together")
	}

	for _, u := range o.BypassAuthExceptRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", u, err))
		}
		o.CompiledAuthRegex = append(o.CompiledAuthRegex, CompiledRegex)
	}

	// Ensure paths under ProxyPrefix are still protected when using -bypass-auth-except-for
	if len(o.CompiledAuthRegex) > 0 {
		proxyRegex, err := regexp.Compile(o.ProxyPrefix + "*")
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", o.ProxyPrefix+"*", err))
		}
		o.CompiledAuthRegex = append(o.CompiledAuthRegex, proxyRegex)
	}

	for _, u := range o.SkipAuthRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"error compiling regex=%q %s", u, err))
		}
		o.CompiledSkipRegex = append(o.CompiledSkipRegex, CompiledRegex)
	}

	if o.PassAccessToken || (o.CookieRefresh != time.Duration(0)) {
		valid_cookie_secret_size := false
		for _, i := range []int{16, 24, 32} {
			if len(secretBytes(o.CookieSecret)) == i {
				valid_cookie_secret_size = true
			}
		}
		var decoded bool
		if string(secretBytes(o.CookieSecret)) != o.CookieSecret {
			decoded = true
		}
		if valid_cookie_secret_size == false {
			var suffix string
			if decoded {
				suffix = fmt.Sprintf(" note: cookie secret was base64 decoded from %q", o.CookieSecret)
			}
			msgs = append(msgs, fmt.Sprintf(
				"cookie_secret must be 16, 24, or 32 bytes "+
					"to create an AES cipher when "+
					"pass_access_token == true or "+
					"cookie_refresh != 0, but is %d bytes.%s",
				len(secretBytes(o.CookieSecret)), suffix))
		}
	}

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	if len(o.TLSClientCAFile) > 0 && len(o.TLSKeyFile) == 0 && len(o.TLSCertFile) == 0 {
		msgs = append(msgs, "tls-client-ca requires tls-key-file or tls-cert-file to be set to listen on tls")
	}

	switch o.CookieSameSite {
	case "", "none", "lax", "strict":
	default:
		msgs = append(msgs, fmt.Sprintf("cookie_samesite (%q) must be one of ['', 'lax', 'strict', 'none']", o.CookieSameSite))
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = validateCookieName(o, msgs)

	if o.SSLInsecureSkipVerify {
		insecureTransport := &http.Transport{
			TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{InsecureSkipVerify: true}), // eh
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}

	msgs = append(msgs, o.validateProvider(p)...)
	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	o.provider = p

	return nil
}

func (o *Options) validateProvider(provider providers.Provider) []string {
	var msgs []string
	data := &providers.ProviderData{
		Scope:          o.Scope,
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		ApprovalPrompt: o.ApprovalPrompt,
	}
	data.ConfigLoginURL, msgs = parseURL(o.LoginURL, "login", msgs)
	data.ConfigRedeemURL, msgs = parseURL(o.RedeemURL, "redeem", msgs)

	data.ProfileURL, msgs = parseURL(o.ProfileURL, "profile", msgs)
	data.ValidateURL, msgs = parseURL(o.ValidateURL, "validate", msgs)
	if len(msgs) != 0 {
		return msgs
	}

	switch p := provider.(type) {
	case *openshift.OpenShiftProvider:
		var reviewURL *url.URL
		reviewURL, msgs = parseURL(o.OpenShiftReviewURL, "openshift-review", msgs)
		if len(msgs) != 0 {
			return msgs
		}
		if err := p.Complete(data, reviewURL); err != nil {
			msgs = append(msgs, fmt.Sprintf("unable to load OpenShift configuration: %v", err))
		}
	case *providers.ProviderData:
		p.Scope = data.Scope
		p.ClientID = data.ClientID
		p.ClientSecret = data.ClientSecret
		p.ApprovalPrompt = data.ApprovalPrompt
		p.ConfigLoginURL = data.ConfigLoginURL
		p.ConfigRedeemURL = data.ConfigRedeemURL
		p.ProfileURL = data.ProfileURL
		p.ValidateURL = data.ValidateURL
	}
	return msgs
}

func parseSignatureKey(o *Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	if hash, err := hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
	} else {
		o.signatureData = &SignatureData{hash, secretKey}
	}
	return msgs
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}
