package providers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/openshift/oauth-proxy/cookie"
)

type Provider interface {
	Data() *ProviderData

	ReviewUser(name, accessToken, host string) error
	GetEmailAddress(*SessionState) (string, error)
	Redeem(*url.URL, string, string) (*SessionState, error)
	ValidateGroup(string) bool
	ValidateSessionState(*SessionState) bool
	GetLoginRedirectURL(loginURL url.URL, redirectURI, state string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher) (string, error)
	ValidateRequest(*http.Request) (*SessionState, error)
	GetLoginURL() (*url.URL, error)
	GetRedeemURL() (*url.URL, error)
}

// ErrPermissionDenied may be returned from Redeem() to indicate the user is not allowed to login.
var ErrPermissionDenied = errors.New("permission denied")
