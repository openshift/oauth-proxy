package main

import (
	"crypto"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bmizerany/assert"
	"github.com/openshift/oauth-proxy/providers"
)

type testProvider struct {
	providers.ProviderData
}

func testOptions() *Options {
	o := NewOptions()
	o.Upstreams = []string{"http://127.0.0.1:8080"}
	o.CookieSecret = "foobar"
	o.ClientID = "bazquux"
	o.ClientSecret = "xyzzyplugh"
	o.EmailDomains = []string{"*"}
	if err := o.Validate(&testProvider{}); err != nil {
		panic(err)
	}
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "Invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o := NewOptions()
	o.EmailDomains = []string{"*"}
	err := o.Validate(&testProvider{})
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: upstream",
		"missing setting: cookie-secret",
		"missing setting: client-id",
		"missing setting: client-secret"})
	assert.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate(&testProvider{}))
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions()
	o.RedirectURL = "https://myhost.com/oauth2/callback"
	assert.Equal(t, nil, o.Validate(&testProvider{}))
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	assert.Equal(t, expected, o.redirectURL)
}

func TestProxyURLs(t *testing.T) {
	o := testOptions()
	t.Logf("%#v / %#v", o.Upstreams, o.proxyURLs)
	o.Upstreams = append(o.Upstreams, "http://127.0.0.1:8081")
	assert.Equal(t, nil, o.Validate(&testProvider{}))
	t.Logf("%#v / %#v", o.Upstreams, o.proxyURLs)
	expected := []*url.URL{
		{Scheme: "http", Host: "127.0.0.1:8080", Path: "/"},
		// note the '/' was added
		{Scheme: "http", Host: "127.0.0.1:8081", Path: "/"},
	}
	assert.Equal(t, expected, o.proxyURLs)
}

func TestCompiledRegex(t *testing.T) {
	o := testOptions()
	regexps := []string{"/foo/.*", "/ba[rz]/quux"}
	o.SkipAuthRegex = regexps
	assert.Equal(t, nil, o.Validate(&testProvider{}))
	actual := make([]string, 0)
	for _, regex := range o.CompiledSkipRegex {
		actual = append(actual, regex.String())
	}
	assert.Equal(t, regexps, actual)
}

func TestCompiledRegexError(t *testing.T) {
	o := testOptions()
	o.SkipAuthRegex = []string{"(foobaz", "barquux)"}
	err := o.Validate(&testProvider{})
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"error compiling regex=\"(foobaz\" error parsing regexp: " +
			"missing closing ): `(foobaz`",
		"error compiling regex=\"barquux)\" error parsing regexp: " +
			"unexpected ): `barquux)`"})
	assert.Equal(t, expected, err.Error())
}

func TestDefaultProviderApiSettings(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate(&testProvider{}))
	p := o.provider.Data()
	assert.Equal(t, "", p.Scope)
}

func TestPassAccessTokenRequiresSpecificCookieSecretLengths(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	assert.Equal(t, false, o.PassAccessToken)
	o.PassAccessToken = true
	o.CookieSecret = "cookie of invalid length-"
	assert.NotEqual(t, nil, o.Validate(&testProvider{}))

	o.PassAccessToken = false
	o.CookieRefresh = time.Duration(24) * time.Hour
	assert.NotEqual(t, nil, o.Validate(&testProvider{}))

	o.CookieSecret = "16 bytes AES-128"
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	o.CookieSecret = "24 byte secret AES-192--"
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	o.CookieSecret = "32 byte secret for AES-256------"
	assert.Equal(t, nil, o.Validate(&testProvider{}))
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	o.CookieSecret = "0123456789abcdefabcd"
	o.CookieRefresh = o.CookieExpire
	assert.NotEqual(t, nil, o.Validate(&testProvider{}))

	o.CookieRefresh -= time.Duration(1)
	assert.Equal(t, nil, o.Validate(&testProvider{}))
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	// 32 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	// 24 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "Kp33Gj-GQmYtz4zZUyUDdqQKx5_Hgkv3"
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	// 16 byte, base64 (urlsafe) encoded key
	o.CookieSecret = "LFEqZYvYUwKwzn0tEuTpLA=="
	assert.Equal(t, nil, o.Validate(&testProvider{}))

	// 16 byte, base64 (urlsafe) encoded key, w/o padding
	o.CookieSecret = "LFEqZYvYUwKwzn0tEuTpLA"
	assert.Equal(t, nil, o.Validate(&testProvider{}))
}

func TestValidateSignatureKey(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "sha1:secret"
	assert.Equal(t, nil, o.Validate(&testProvider{}))
	assert.Equal(t, o.signatureData.hash, crypto.SHA1)
	assert.Equal(t, o.signatureData.key, "secret")
}

func TestValidateSignatureKeyInvalidSpec(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "invalid spec"
	err := o.Validate(&testProvider{})
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		"  invalid signature hash:key spec: "+o.SignatureKey)
}

func TestValidateSignatureKeyUnsupportedAlgorithm(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "unsupported:default secret"
	err := o.Validate(&testProvider{})
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		"  unsupported signature hash algorithm: "+o.SignatureKey)
}

func TestValidateCookie(t *testing.T) {
	o := testOptions()
	o.CookieName = "_valid_cookie_name"
	assert.Equal(t, nil, o.Validate(&testProvider{}))
}

func TestValidateCookieBadName(t *testing.T) {
	o := testOptions()
	o.CookieName = "_bad_cookie_name{}"
	err := o.Validate(&testProvider{})
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		fmt.Sprintf("  invalid cookie name: %q", o.CookieName))
}

func TestValidateCookieSameSiteUnknown(t *testing.T) {
	o := testOptions()
	o.CookieSameSite = "foo"
	err := o.Validate(&testProvider{})
	assert.Equal(t, err.Error(), "Invalid configuration:\n"+
		fmt.Sprintf("  cookie_samesite (%q) must be one of ['', 'lax', 'strict', 'none']", o.CookieSameSite))
}

func TestValidateCookieSameSite(t *testing.T) {
	testCases := []string{"", "lax", "strict", "none"}
	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			o := testOptions()
			o.CookieSameSite = tc
			assert.Equal(t, nil, o.Validate(&testProvider{}))
		})
	}
}
