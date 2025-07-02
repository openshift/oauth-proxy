package openshift

// this file is partially copied from k8s.io/apiserver/pkg/server/options

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	serveroptions "k8s.io/apiserver/pkg/server/options"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

type RequestHeaderAuthenticationOptions struct {
	UsernameHeaders     StringSlice
	GroupHeaders        StringSlice
	ExtraHeaderPrefixes StringSlice
	ClientCAFile        string
	AllowedNames        StringSlice
}

type StringSlice []string

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}
func (s *StringSlice) String() string {
	return strings.Join(*s, " ")
}

func (s *RequestHeaderAuthenticationOptions) AddFlags(fs *flag.FlagSet) {
	fs.Var(&s.UsernameHeaders, "requestheader-username-headers", ""+
		"List of request headers to inspect for usernames. X-Remote-User is common.")

	fs.Var(&s.GroupHeaders, "requestheader-group-headers", ""+
		"List of request headers to inspect for groups. X-Remote-Group is suggested.")

	fs.Var(&s.ExtraHeaderPrefixes, "requestheader-extra-headers-prefix", ""+
		"List of request header prefixes to inspect. X-Remote-Extra- is suggested.")

	fs.StringVar(&s.ClientCAFile, "requestheader-client-ca-file", s.ClientCAFile, ""+
		"Root certificate bundle to use to verify client certificates on incoming requests "+
		"before trusting usernames in headers specified by --requestheader-username-headers")

	fs.Var(&s.AllowedNames, "requestheader-allowed-names", ""+
		"List of client certificate common names to allow to provide usernames in headers "+
		"specified by --requestheader-username-headers. If empty, any client certificate validated "+
		"by the authorities in --requestheader-client-ca-file is allowed.")
}

// ToAuthenticationRequestHeaderConfig returns a RequestHeaderConfig config object for these options
// if necessary, nil otherwise.
func (s *RequestHeaderAuthenticationOptions) ToAuthenticationRequestHeaderConfig() (*authenticatorfactory.RequestHeaderConfig, error) {
	if len(s.ClientCAFile) == 0 {
		return nil, nil
	}

	dynamicCAProvider, err := dynamiccertificates.NewDynamicCAContentFromFile("request-header", s.ClientCAFile)
	if err != nil {
		return nil, err
	}

	return &authenticatorfactory.RequestHeaderConfig{
		UsernameHeaders:     headerrequest.StaticStringSlice(s.UsernameHeaders),
		GroupHeaders:        headerrequest.StaticStringSlice(s.GroupHeaders),
		ExtraHeaderPrefixes: headerrequest.StaticStringSlice(s.ExtraHeaderPrefixes),
		CAContentProvider:   dynamicCAProvider,
		AllowedClientNames:  headerrequest.StaticStringSlice(s.AllowedNames),
	}, nil
}

type ClientCertAuthenticationOptions struct {
	// ClientCA is the certificate bundle for all the signers that you'll recognize for incoming client certificates
	ClientCA string
}

// DelegatingAuthenticationOptions provides an easy way for composing API servers to delegate their authentication to
// the root kube API server.  The API federator will act as
// a front proxy and direction connections will be able to delegate to the core kube API server
type DelegatingAuthenticationOptions struct {
	// RemoteKubeConfigFile is the file to use to connect to a "normal" kube API server which hosts the
	// TokenAccessReview.authentication.k8s.io endpoint for checking tokens.
	RemoteKubeConfigFile string

	// CacheTTL is the length of time that a token authentication answer will be cached.
	CacheTTL time.Duration

	ClientCert    ClientCertAuthenticationOptions
	RequestHeader RequestHeaderAuthenticationOptions

	SkipInClusterLookup bool
}

func NewDelegatingAuthenticationOptions() *DelegatingAuthenticationOptions {
	return &DelegatingAuthenticationOptions{
		// very low for responsiveness, but high enough to handle storms
		CacheTTL:   10 * time.Second,
		ClientCert: ClientCertAuthenticationOptions{},
		RequestHeader: RequestHeaderAuthenticationOptions{
			UsernameHeaders:     []string{"x-remote-user"},
			GroupHeaders:        []string{"x-remote-group"},
			ExtraHeaderPrefixes: []string{"x-remote-extra-"},
		},
	}
}

func (s *DelegatingAuthenticationOptions) Validate() []error {
	allErrors := []error{}
	return allErrors
}

func (s *DelegatingAuthenticationOptions) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&s.RemoteKubeConfigFile, "authentication-kubeconfig", s.RemoteKubeConfigFile, ""+
		"kubeconfig file pointing at the 'core' kubernetes server with enough rights to create "+
		"tokenaccessreviews.authentication.k8s.io.")

	fs.DurationVar(&s.CacheTTL, "authentication-token-webhook-cache-ttl", s.CacheTTL,
		"The duration to cache responses from the webhook token authenticator.")

	s.RequestHeader.AddFlags(fs)
}

func (s *DelegatingAuthenticationOptions) ToAuthenticationConfig() (authenticatorfactory.DelegatingAuthenticatorConfig, error) {
	tokenClient, err := s.newTokenAccessReview()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}

	clientCA, err := s.getClientCA()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}
	requestHeader, err := s.getRequestHeader()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}

	requestHeaderConfig, err := requestHeader.ToAuthenticationRequestHeaderConfig()
	if err != nil {
		return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
	}

	var clientCAProvider *dynamiccertificates.DynamicFileCAContent
	if len(clientCA.ClientCA) > 0 {
		clientCAProvider, err = dynamiccertificates.NewDynamicCAContentFromFile("client-ca-bundle", clientCA.ClientCA)
		if err != nil {
			return authenticatorfactory.DelegatingAuthenticatorConfig{}, err
		}
	}

	ret := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:                          &apiserver.AnonymousAuthConfig{Enabled: true},
		TokenAccessReviewClient:            tokenClient,
		WebhookRetryBackoff:                serveroptions.DefaultAuthWebhookRetryBackoff(),
		CacheTTL:                           s.CacheTTL,
		ClientCertificateCAContentProvider: clientCAProvider,
		RequestHeaderConfig:                requestHeaderConfig,
	}
	return ret, nil
}

func (s *DelegatingAuthenticationOptions) getClientCA() (*ClientCertAuthenticationOptions, error) {
	if len(s.ClientCert.ClientCA) > 0 || s.SkipInClusterLookup {
		return &s.ClientCert, nil
	}
	return nil, fmt.Errorf("no client ca-file config")
}

func (s *DelegatingAuthenticationOptions) getRequestHeader() (*RequestHeaderAuthenticationOptions, error) {
	if len(s.RequestHeader.ClientCAFile) > 0 || s.SkipInClusterLookup {
		return &s.RequestHeader, nil
	}
	return nil, fmt.Errorf("no request header config")
}

func deserializeStrings(in string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	var ret []string
	if err := json.Unmarshal([]byte(in), &ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *DelegatingAuthenticationOptions) newTokenAccessReview() (authenticationclient.AuthenticationV1Interface, error) {
	clientConfig, err := GetClientConfig(s.RemoteKubeConfigFile)
	if err != nil {
		return nil, err
	}

	clientConfig.Wrap(auditIDRountripper)

	client, err := authenticationclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func auditIDRountripper(rt http.RoundTripper) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		const auditIDKey = "Audit-ID"

		auditID := r.Header.Get(auditIDKey)
		if len(auditID) == 0 {
			auditID = uuid.New().String()
		}

		r.Header.Add("Audit-ID", auditID)
		resp, err := rt.RoundTrip(r)
		if err != nil {
			err = fmt.Errorf("audit-ID %q request failed: %w", auditID, err)
		}
		return resp, err
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
