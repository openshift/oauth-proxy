package providers

import (
	"net/url"
)

type ProviderData struct {
	ProviderName string
	ClientID     string
	ClientSecret string
	// Config* attributes are set in the options, if set, these endpoints won't
	// be refetched
	ConfigLoginURL    *url.URL
	ConfigRedeemURL   *url.URL
	ValidateURL       *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	Scope             string
	ApprovalPrompt    string
}

func (p *ProviderData) Data() *ProviderData { return p }
