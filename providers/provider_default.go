package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/openshift/oauth-proxy/cookie"
)

func (p *ProviderData) Redeem(redeemURL *url.URL, redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", redeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, redeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

// GetLoginRedirectURL with typical oauth parameters
func (p *ProviderData) GetLoginRedirectURL(loginURL url.URL, redirectURI, state string) string {
	params, _ := url.ParseQuery(loginURL.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	loginURL.RawQuery = params.Encode()
	return loginURL.String()
}

// CookieForSession serializes a session state for storage in a cookie
func (p *ProviderData) CookieForSession(s *SessionState, c *cookie.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}

// SessionFromCookie deserializes a session from a cookie value
func (p *ProviderData) SessionFromCookie(v string, c *cookie.Cipher) (s *SessionState, err error) {
	return DecodeSessionState(v, c)
}

func (p *ProviderData) GetEmailAddress(s *SessionState) (string, error) {
	return "", errors.New("not implemented")
}

func (p *ProviderData) ReviewUser(name, accessToken, host string) error {
	return nil
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *ProviderData) ValidateGroup(email string) bool {
	return true
}

func (p *ProviderData) ValidateRequest(_ *http.Request) (*SessionState, error) {
	return nil, nil
}

func (p *ProviderData) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, nil)
}

// RefreshSessionIfNeeded
func (p *ProviderData) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	return false, nil
}

func (p *ProviderData) GetLoginURL() (*url.URL, error) {
	if !(p.ConfigLoginURL == nil || p.ConfigLoginURL.String() == "") {
		return p.ConfigLoginURL, nil
	}

	return nil, fmt.Errorf("no login endpoint was configured")
}

func (p *ProviderData) GetRedeemURL() (*url.URL, error) {
	if !(p.ConfigRedeemURL == nil || p.ConfigRedeemURL.String() == "") {
		return p.ConfigRedeemURL, nil
	}

	return nil, fmt.Errorf("no redeem endpoint was configured")
}
