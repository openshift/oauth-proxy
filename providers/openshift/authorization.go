package openshift

// this file is partially copied from k8s.io/apiserver/pkg/server/options

import (
	"flag"
	"time"

	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	serveroptions "k8s.io/apiserver/pkg/server/options"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// DelegatingAuthorizationOptions provides an easy way for composing API servers to delegate their authorization to
// the root kube API server
type DelegatingAuthorizationOptions struct {
	// RemoteKubeConfigFile is the file to use to connect to a "normal" kube API server which hosts the
	// SubjectAccessReview.authorization.k8s.io endpoint for checking tokens.
	RemoteKubeConfigFile string

	// AllowCacheTTL is the length of time that a successful authorization response will be cached
	AllowCacheTTL time.Duration

	// DenyCacheTTL is the length of time that an unsuccessful authorization response will be cached.
	// You generally want more responsive, "deny, try again" flows.
	DenyCacheTTL time.Duration
}

func NewDelegatingAuthorizationOptions() *DelegatingAuthorizationOptions {
	return &DelegatingAuthorizationOptions{
		// very low for responsiveness, but high enough to handle storms
		AllowCacheTTL: 10 * time.Second,
		DenyCacheTTL:  10 * time.Second,
	}
}

func (s *DelegatingAuthorizationOptions) Validate() []error {
	allErrors := []error{}
	return allErrors
}

func (s *DelegatingAuthorizationOptions) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&s.RemoteKubeConfigFile, "authorization-kubeconfig", s.RemoteKubeConfigFile, ""+
		"kubeconfig file pointing at the 'core' kubernetes server with enough rights to create "+
		" subjectaccessreviews.authorization.k8s.io.")

	fs.DurationVar(&s.AllowCacheTTL, "authorization-webhook-cache-authorized-ttl",
		s.AllowCacheTTL,
		"The duration to cache 'authorized' responses from the webhook authorizer.")

	fs.DurationVar(&s.DenyCacheTTL,
		"authorization-webhook-cache-unauthorized-ttl", s.DenyCacheTTL,
		"The duration to cache 'unauthorized' responses from the webhook authorizer.")
}

func (s *DelegatingAuthorizationOptions) ToAuthorizationConfig() (authorizerfactory.DelegatingAuthorizerConfig, error) {
	sarClient, err := s.newSubjectAccessReview()
	if err != nil {
		return authorizerfactory.DelegatingAuthorizerConfig{}, err
	}

	ret := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: sarClient,
		AllowCacheTTL:             s.AllowCacheTTL,
		DenyCacheTTL:              s.DenyCacheTTL,
		WebhookRetryBackoff:       serveroptions.DefaultAuthWebhookRetryBackoff(),
	}
	return ret, nil
}

func (s *DelegatingAuthorizationOptions) newSubjectAccessReview() (authorizationclient.AuthorizationV1Interface, error) {
	clientConfig, err := GetClientConfig(s.RemoteKubeConfigFile)
	if err != nil {
		return nil, err
	}

	clientConfig.Wrap(auditIDRountripper)

	client, err := authorizationclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}
