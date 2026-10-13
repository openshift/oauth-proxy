package openshift

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"

	oscrypto "github.com/openshift/library-go/pkg/crypto"

	"github.com/openshift/oauth-proxy/providers"
	"github.com/openshift/oauth-proxy/util"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/informers"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func emptyURL(u *url.URL) bool {
	return u == nil || u.String() == ""
}

type OpenShiftProvider struct {
	*providers.ProviderData

	ReviewURL *url.URL
	ReviewCAs []string

	AuthenticationOptions DelegatingAuthenticationOptions
	AuthorizationOptions  DelegatingAuthorizationOptions
	KubeClientOptions     KubeClientOptions

	authenticator   authenticator.Request
	authorizer      authorizer.Authorizer
	configMapLister corev1listers.ConfigMapLister
	defaultRecord   authorizer.AttributesRecord
	reviews         []string
	paths           recordsByPath
	hostreviews     map[string][]string

	// httpClientCache stores httpClient objects so that new client does not have to
	// be created on each request just to prevent CAs content changed
	// key is bytes of the hashed metadata of the files for CAs the client was
	// created with
	// NOTE: the entries of the map are currently not being cleaned up
	httpClientCache sync.Map
}

func (p *OpenShiftProvider) GetReviewCAs() []string {
	return p.ReviewCAs
}

func (p *OpenShiftProvider) SetReviewCAs(cas []string) {
	p.ReviewCAs = cas
}

func New() *OpenShiftProvider {
	p := &OpenShiftProvider{}
	p.AuthenticationOptions.SkipInClusterLookup = true
	p.AuthenticationOptions.CacheTTL = 2 * time.Minute
	p.AuthorizationOptions.AllowCacheTTL = 2 * time.Minute
	p.AuthorizationOptions.DenyCacheTTL = 5 * time.Second
	return p
}

func (p *OpenShiftProvider) SetClientCAFile(file string) {
	p.AuthenticationOptions.ClientCert.ClientCA = file
}

func (p *OpenShiftProvider) Bind(flags *flag.FlagSet) {
	p.KubeClientOptions.AddFlags(flags)
	p.AuthenticationOptions.AddFlags(flags)
	p.AuthorizationOptions.AddFlags(flags)
}

// LoadDefaults accepts configuration and loads defaults from the environment, or returns an error.
// The provider may partially initialize config for subsequent calls.
func (p *OpenShiftProvider) LoadDefaults(serviceAccount string, reviewJSON, reviewByHostJSON, resources string) (*providers.ProviderData, error) {
	if len(resources) > 0 {
		paths, err := parseResources(resources)
		if err != nil {
			return nil, err
		}
		p.paths = paths
	}
	reviews, err := parseSubjectAccessReviews(reviewJSON)
	if err != nil {
		return nil, err
	}
	p.reviews = reviews

	hostreviews, err := parseSubjectAccessReviewsByHost(reviewByHostJSON)
	if err != nil {
		return nil, err
	}
	p.hostreviews = hostreviews

	defaults := &providers.ProviderData{
		Scope: "user:info user:check-access",
	}

	// all OpenShift service accounts are OAuth clients, use this if we have it
	if len(serviceAccount) > 0 {
		if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil && len(data) > 0 {
			defaults.ClientID = fmt.Sprintf("system:serviceaccount:%s:%s", strings.TrimSpace(string(data)), serviceAccount)
			log.Printf("Defaulting client-id to %s", defaults.ClientID)
		}
		tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
		if data, err := ioutil.ReadFile(tokenPath); err == nil && len(data) > 0 {
			defaults.ClientSecret = strings.TrimSpace(string(data))
			log.Printf("Defaulting client-secret to service account token %s", tokenPath)
		}
	}

	// provide default URLs
	defaults.ValidateURL = getKubeAPIURLWithPath("/apis/user.openshift.io/v1/users/~")

	return defaults, nil
}

// newOpenShiftClient returns a client for connecting to the master.
func (p *OpenShiftProvider) newOpenShiftClient() (*http.Client, error) {
	paths := p.GetReviewCAs()
	//defaults
	capaths := []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}
	system_roots := true
	if len(paths) != 0 {
		capaths = paths
		system_roots = false
	}

	// try to retrieve a cached client
	metadataHash, err := util.GetFilesMetadataHash(capaths)
	if err != nil {
		return nil, err
	}

	cachedKey := metadataHash

	oauthServerCert, err := p.configMapLister.ConfigMaps("openshift-config-managed").Get("oauth-serving-cert")
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	if oauthServerCert != nil {
		cachedKey += oauthServerCert.ResourceVersion
	}

	if httpClient, ok := p.httpClientCache.Load(cachedKey); ok {
		return httpClient.(*http.Client), nil
	}

	// client not in cache, create new
	pool, err := util.GetCertPool(capaths, system_roots)
	if err != nil {
		return nil, err
	}

	if oauthServerCert != nil {
		if ok := pool.AppendCertsFromPEM([]byte(oauthServerCert.Data["ca-bundle.crt"])); !ok {
			log.Println("failed to add the oauth-server certificate to the OpenShift client CA bundle")
		}
	}

	httpClient := &http.Client{
		Jar: http.DefaultClient.Jar,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: oscrypto.SecureTLSConfig(&tls.Config{RootCAs: pool}),
		},
		Timeout: 1 * time.Minute,
	}
	p.httpClientCache.Store(cachedKey, httpClient)

	return httpClient, nil
}

// encodeSARWithScope adds a "scopes" array to the SAR if it does not have one already, and outputs
// encoded bytes.
func encodeSARWithScope(json *simplejson.Json) ([]byte, error) {
	if len(json.Get("scopes").MustArray()) == 0 {
		json.Set("scopes", []interface{}{})
	}
	return json.Encode()
}

func parseSubjectAccessReviewsByHost(review string) (map[string][]string, error) {
	if len(review) == 0 {
		return nil, nil
	}
	json, err := simplejson.NewJson([]byte(review))
	if err != nil {
		return nil, fmt.Errorf("unable to decode review: %v", err)
	}

	reviews := make(map[string][]string)
	for k := range json.MustMap() {
		data, err := json.Get(k).EncodePretty()
		if err != nil {
			return nil, err
		}
		r, err := parseSubjectAccessReviews(string(data))
		if err != nil {
			return nil, err
		}
		reviews[k] = r
	}
	return reviews, nil
}

// parseSubjectAccessReviews parses a list of SAR records and ensures they are properly scoped.
func parseSubjectAccessReviews(review string) ([]string, error) {
	review = strings.TrimSpace(review)
	if len(review) == 0 {
		return nil, nil
	}

	// Convert to a json array to simplify encoding later
	if review[0] != '[' && review[len(review)-1] != ']' {
		review = "[" + review + "]"
	}

	json, err := simplejson.NewJson([]byte(review))
	if err != nil {
		return nil, fmt.Errorf("unable to decode review: %v", err)
	}

	var reviews []string
	for i := range json.MustArray() {
		data, err := encodeSARWithScope(json.GetIndex(i))
		if err != nil {
			return nil, fmt.Errorf("unable to encode modified review: %v (%#v)", err, json)
		}
		reviews = append(reviews, string(data))
	}
	return reviews, nil
}

type pathRecord struct {
	path   string
	record authorizer.AttributesRecord
}

type recordsByPath []pathRecord

func (o recordsByPath) Len() int      { return len(o) }
func (o recordsByPath) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o recordsByPath) Less(i, j int) bool {
	// match longest paths first
	if len(o[j].path) < len(o[i].path) {
		return true
	}
	// match in lexographic order otherwise
	return o[i].path < o[j].path
}

func (o recordsByPath) Match(path string) (pathRecord, bool) {
	for i := range o {
		if strings.HasPrefix(path, o[i].path) {
			return o[i], true
		}
	}
	return pathRecord{}, false
}

// parseResources creates a map of path prefixes (the keys in the provided input) to
// SubjectAccessReview ResourceAttributes (the keys) and returns the records ordered
// by longest path first, or an error.
func parseResources(resources string) (recordsByPath, error) {
	defaults := authorizer.AttributesRecord{
		Verb:            "proxy",
		ResourceRequest: true,
	}
	var paths recordsByPath
	mappings := make(map[string]authorizationv1.ResourceAttributes)
	if err := json.Unmarshal([]byte(resources), &mappings); err != nil {
		return nil, fmt.Errorf("resources must be a JSON map of paths to authorizationv1beta1.ResourceAttributes: %v", err)
	}
	for path, attrs := range mappings {
		r := defaults
		if len(attrs.Verb) > 0 {
			r.Verb = attrs.Verb
		}
		if len(attrs.Group) > 0 {
			r.APIGroup = attrs.Group
		}
		if len(attrs.Version) > 0 {
			r.APIVersion = attrs.Version
		}
		if len(attrs.Resource) > 0 {
			r.Resource = attrs.Resource
		}
		if len(attrs.Subresource) > 0 {
			r.Subresource = attrs.Subresource
		}
		if len(attrs.Namespace) > 0 {
			r.Namespace = attrs.Namespace
		}
		if len(attrs.Name) > 0 {
			r.Name = attrs.Name
		}
		paths = append(paths, pathRecord{
			path:   path,
			record: r,
		})
	}
	sort.Sort(paths)
	return paths, nil
}

// Complete performs final setup on the provider or returns an error.
func (p *OpenShiftProvider) Complete(data *providers.ProviderData, reviewURL *url.URL) error {
	if emptyURL(reviewURL) {
		reviewURL = getKubeAPIURLWithPath("/apis/authorization.openshift.io/v1/subjectaccessreviews")
	}

	p.ProviderData = data
	p.ReviewURL = reviewURL

	kubeClient, err := p.KubeClientOptions.ToKubeClientConfig()
	if err != nil {
		return err
	}

	kubeInformersMachineConfigNS := informers.NewSharedInformerFactoryWithOptions(
		kubeClient,
		10*time.Minute,
		informers.WithNamespace("openshift-config-managed"),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", "oauth-serving-cert").String()
		}))
	go kubeInformersMachineConfigNS.Core().V1().ConfigMaps().Informer().Run(context.TODO().Done())
	p.configMapLister = kubeInformersMachineConfigNS.Core().V1().ConfigMaps().Lister()

	if len(p.paths) > 0 {
		log.Printf("Delegation of authentication and authorization to OpenShift is enabled for bearer tokens and client certificates.")

		authenticator, err := p.AuthenticationOptions.ToAuthenticationConfig()
		if err != nil {
			return fmt.Errorf("unable to configure authenticator: %v", err)
		}
		// check whether we have access to perform authentication review
		if authenticator.TokenAccessReviewClient != nil {
			wait.PollImmediate(2*time.Second, 10*time.Second, func() (bool, error) {
				_, err := authenticator.TokenAccessReviewClient.TokenReviews().Create(context.TODO(),
					&authenticationv1.TokenReview{
						Spec: authenticationv1.TokenReviewSpec{
							Token: "TEST",
						},
					},
					metav1.CreateOptions{})
				if err != nil {
					log.Printf("unable to retrieve authentication information for tokens: %v", err)
					return false, nil
				}
				return true, nil
			})
		}

		authorizer, err := p.AuthorizationOptions.ToAuthorizationConfig()
		if err != nil {
			return fmt.Errorf("unable to configure authorizer: %v", err)
		}
		// check whether we have access to perform authentication review
		if authorizer.SubjectAccessReviewClient != nil {
			wait.PollImmediate(2*time.Second, 10*time.Second, func() (bool, error) {
				_, err := authorizer.SubjectAccessReviewClient.SubjectAccessReviews().Create(context.TODO(),
					&authorizationv1.SubjectAccessReview{
						Spec: authorizationv1.SubjectAccessReviewSpec{
							User: "TEST",
							ResourceAttributes: &authorizationv1.ResourceAttributes{
								Resource: "TEST",
								Verb:     "TEST",
							},
						},
					}, metav1.CreateOptions{})
				if err != nil {
					log.Printf("unable to retrieve authorization information for users: %v", err)
					return false, nil
				}
				return true, nil
			})
		}

		p.authenticator, _, err = authenticator.New()
		if err != nil {
			return fmt.Errorf("unable to configure authenticator: %v", err)
		}

		p.authorizer, err = authorizer.New()
		if err != nil {
			return fmt.Errorf("unable to configure authorizer: %v", err)
		}
	}
	return nil
}

func (p *OpenShiftProvider) ValidateRequest(req *http.Request) (*providers.SessionState, error) {
	// no authenticator is registered
	if p.authenticator == nil {
		return nil, nil
	}

	// find a match
	record, ok := p.paths.Match(req.URL.Path)
	if !ok {
		log.Printf("no resource mapped path")
		return nil, nil
	}

	auth := req.Header.Get("Authorization")

	// authenticate
	response, ok, err := p.authenticator.AuthenticateRequest(req)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	// authorize
	record.record.User = response.User
	decision, _, err := p.authorizer.Authorize(context.Background(), record.record)
	if err != nil {
		return nil, err
	}
	if decision != authorizer.DecisionAllow {
		return nil, nil
	}

	parts := strings.SplitN(auth, " ", 2)
	session := &providers.SessionState{User: response.User.GetName(), Email: response.User.GetName() + "@cluster.local"}
	if parts[0] == "Bearer" {
		session.AccessToken = parts[1]
	}
	return session, nil
}

func (p *OpenShiftProvider) GetEmailAddress(s *providers.SessionState) (string, error) {
	req, err := http.NewRequest("GET", p.ValidateURL.String(), nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", fmt.Errorf("unable to build request to get user email info: %v", err)
	}

	client, err := p.newOpenShiftClient()
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
	json, err := request(client, req)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve email address for user from token: %v", err)
	}
	name, err := json.Get("metadata").Get("name").String()
	if err != nil {
		return "", fmt.Errorf("user information has no name field: %v", err)
	}
	if !strings.Contains(name, "@") {
		name = name + "@cluster.local"
	}
	return name, nil
}

func (p *OpenShiftProvider) ReviewUser(name, accessToken, host string) error {
	var tocheck []string

	hostreviews, ok := p.hostreviews[host]
	if ok {
		tocheck = append(tocheck, hostreviews...)
	}
	if len(p.reviews) > 0 {
		tocheck = append(tocheck, p.reviews...)
	}

	client, err := p.newOpenShiftClient()
	if err != nil {
		return err
	}

	for _, review := range tocheck {
		req, err := http.NewRequest("POST", p.ReviewURL.String(), bytes.NewBufferString(review))
		if err != nil {
			log.Printf("failed building request %s", err)
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		json, err := request(client, req)
		if err != nil {
			return err
		}
		allowed, err := json.Get("allowed").Bool()
		if err != nil {
			return err
		}
		if !allowed {
			log.Printf("Permission denied for %s for check %s", name, review)
			return providers.ErrPermissionDenied
		}
	}
	return nil
}

// Copied up only to set a different client CA
func (p *OpenShiftProvider) Redeem(redeemURL *url.URL, redirectURL, code string) (s *providers.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	client, caErr := p.newOpenShiftClient()
	if caErr != nil {
		err = caErr
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
	resp, err = client.Do(req)
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
		s = &providers.SessionState{
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
		s = &providers.SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

func (p *OpenShiftProvider) GetLoginURL() (*url.URL, error) {
	if !emptyURL(p.ConfigLoginURL) {
		return p.ConfigLoginURL, nil
	}
	client, err := p.newOpenShiftClient()
	if err != nil {
		return nil, err
	}

	loginURL, _, err := discoverOpenShiftOAuth(client)
	return loginURL, err
}

func (p *OpenShiftProvider) GetRedeemURL() (*url.URL, error) {
	if !emptyURL(p.ConfigRedeemURL) {
		return p.ConfigRedeemURL, nil
	}
	client, err := p.newOpenShiftClient()
	if err != nil {
		return nil, err
	}

	_, redeemURL, err := discoverOpenShiftOAuth(client)
	return redeemURL, err
}

// discoverOpenshiftOAuth returns the urls of the login and code redeem endpoitns
// it receives from the /.well-known/oauth-authorization-server endpoint
func discoverOpenShiftOAuth(client *http.Client) (*url.URL, *url.URL, error) {
	wellKnownAuthorization := getKubeAPIURLWithPath("/.well-known/oauth-authorization-server")
	log.Printf("Performing OAuth discovery against %s", wellKnownAuthorization)
	req, err := http.NewRequest("GET", wellKnownAuthorization.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	json, err := request(client, req)
	if err != nil {
		return nil, nil, err
	}

	var loginURL, redeemURL *url.URL
	if value, err := json.Get("authorization_endpoint").String(); err == nil && len(value) > 0 {
		if loginURL, err = url.Parse(value); err != nil {
			return nil, nil, fmt.Errorf("Unable to parse 'authorization_endpoint' from %s: %v", wellKnownAuthorization, err)
		}
	} else {
		return nil, nil, fmt.Errorf("No 'authorization_endpoint' provided by %s: %v", wellKnownAuthorization, err)
	}
	if value, err := json.Get("token_endpoint").String(); err == nil && len(value) > 0 {
		if redeemURL, err = url.Parse(value); err != nil {
			return nil, nil, fmt.Errorf("Unable to parse 'token_endpoint' from %s: %v", wellKnownAuthorization, err)
		}
	} else {
		return nil, nil, fmt.Errorf("No 'token_endpoint' provided by %s: %v", wellKnownAuthorization, err)
	}
	return loginURL, redeemURL, nil
}

// Copied to override http.Client so that CA can be set
func request(client *http.Client, req *http.Request) (*simplejson.Json, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s %s %s", req.Method, req.URL, err)
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("%d %s %s %s", resp.StatusCode, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("got %d %s", resp.StatusCode, body)
	}
	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getKubeAPIURLWithPath(path string) *url.URL {
	ret := &url.URL{
		Scheme: "https",
		Host:   "kubernetes.default.svc",
		Path:   path,
	}

	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); len(host) > 0 {
		// assume IPv6 if host contains colons
		if strings.IndexByte(host, ':') != -1 {
			host = "[" + host + "]"
		}
		ret.Host = host
	}

	return ret
}

func GetClientConfig(remoteKubeConfigFile string) (*rest.Config, error) {
	var clientConfig *rest.Config
	var err error
	if len(remoteKubeConfigFile) > 0 {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: remoteKubeConfigFile}
		loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})

		clientConfig, err = loader.ClientConfig()

	} else {
		// without the remote kubeconfig file, try to use the in-cluster config.  Most addon API servers will
		// use this path
		clientConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	// set high qps/burst limits since this will effectively limit API server responsiveness
	clientConfig.QPS = 200
	clientConfig.Burst = 400

	return clientConfig, nil
}
