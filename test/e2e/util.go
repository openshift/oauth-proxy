package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	cmdapi "k8s.io/client-go/tools/clientcmd/api"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	projectclient "github.com/openshift/client-go/project/clientset/versioned"
	routev1client "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	userclients "github.com/openshift/client-go/user/clientset/versioned"
	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/openshift/library-go/pkg/operator/resource/retry"
)

const (
	// How often to poll for conditions
	Poll = 2 * time.Second
	// Default time to wait for operations to complete
	defaultTimeout = 30 * time.Second
)

func CreateTestProject(t *testing.T, kubeClient kubernetes.Interface, projectClient *projectclient.Clientset) string {
	newNamespace := names.SimpleNameGenerator.GenerateName("e2e-oauth-proxy-")

	// e2e.Logf("Creating project %q", newNamespace)
	_, err := kubeClient.CoreV1().Namespaces().Create(context.Background(),
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: newNamespace,
				Labels: map[string]string{
					"test": "oauth-proxy",
				},
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)

	err = waitForSelfSAR(1*time.Second, 60*time.Second, kubeClient, authorizationv1.SelfSubjectAccessReviewSpec{
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: newNamespace,
			Verb:      "create",
			Group:     "",
			Resource:  "pods",
		},
	})
	require.NoError(t, err)

	return newNamespace
}

func waitForSelfSAR(interval, timeout time.Duration, c kubernetes.Interface, selfSAR authorizationv1.SelfSubjectAccessReviewSpec) error {
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		res, err := c.AuthorizationV1().SelfSubjectAccessReviews().Create(
			context.Background(),
			&authorizationv1.SelfSubjectAccessReview{
				Spec: selfSAR,
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			return false, err
		}

		return res.Status.Allowed, nil
	})

	if err != nil {
		return fmt.Errorf("failed to wait for SelfSAR (ResourceAttributes: %#v, NonResourceAttributes: %#v), err: %v", selfSAR.ResourceAttributes, selfSAR.NonResourceAttributes, err)
	}

	return nil
}

// Waits default amount of time (PodStartTimeout) for the specified pod to become running.
// Returns an error if timeout occurs first, or pod goes in to failed state.
func waitForPodRunningInNamespace(c kubernetes.Interface, pod *corev1.Pod) error {
	if pod.Status.Phase == corev1.PodRunning {
		return nil
	}
	return waitTimeoutForPodRunningInNamespace(c, pod.Name, pod.Namespace, defaultTimeout)
}

func waitTimeoutForPodRunningInNamespace(c kubernetes.Interface, podName, namespace string, timeout time.Duration) error {
	return wait.PollImmediate(Poll, defaultTimeout, podRunning(c, podName, namespace))
}

func waitForPodDeletion(c kubernetes.Interface, podName, namespace string) error {
	return wait.PollImmediate(Poll, defaultTimeout, podDeleted(c, podName, namespace))
}

func waitForHealthzCheck(t *testing.T, transport http.RoundTripper, url string) error {
	client := newHTTPSClient(t, transport)
	return wait.PollImmediate(time.Second, 50*time.Second, func() (bool, error) {
		resp, err := getResponse(url+"/oauth/healthz", client)
		if err != nil {
			return false, err
		}
		if resp.StatusCode != 200 {
			return false, nil
		}
		resp.Body.Close()
		return true, nil
	})
}

func podDeleted(c kubernetes.Interface, podName, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		_, err := c.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	}
}

func podRunning(c kubernetes.Interface, podName, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		switch pod.Status.Phase {
		case corev1.PodRunning:
			return true, nil
		case corev1.PodFailed, corev1.PodSucceeded:
			return false, fmt.Errorf("pod ran to completion")
		}
		return false, nil
	}
}

func waitUntilRouteIsReady(t *testing.T, transport http.RoundTripper, url string) error {
	client := newHTTPSClient(t, transport)
	return wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		resp, err := getResponse(url, client)
		if err != nil {
			if err.Error()[len(err.Error())-3:] == "EOF" {
				return false, nil
			}
			return false, err
		}
		resp.Body.Close()
		return true, nil
	})
}

func getResponse(host string, client *http.Client) (*http.Response, error) {
	req, err := http.NewRequest("GET", host, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func createParsedCertificate(template, parent *x509.Certificate, sigKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Self-signed
	if sigKey == nil {
		sigKey = key
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), sigKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func encodeCert(certificate *x509.Certificate) ([]byte, error) {
	var certBytes bytes.Buffer
	wb := bufio.NewWriter(&certBytes)
	err := pem.Encode(wb, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err != nil {
		return nil, err
	}
	wb.Flush()
	return certBytes.Bytes(), nil
}

func encodeKey(key *rsa.PrivateKey) ([]byte, error) {
	var keyBytes bytes.Buffer
	wb := bufio.NewWriter(&keyBytes)
	err := pem.Encode(wb, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}
	wb.Flush()
	return keyBytes.Bytes(), nil
}

func newHTTPSClient(t *testing.T, transport http.RoundTripper) *http.Client {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := &http.Client{Transport: transport, Jar: jar}
	return client
}

func createCAandCertSet(host string) ([]byte, []byte, []byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	casub := pkix.Name{
		CommonName: "oauth-proxy-test-ca",
	}
	serverSubj := pkix.Name{
		CommonName: host,
	}

	caTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(1),
		Issuer:                casub,
		Subject:               casub,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            10,
	}

	caCert, caKey, err := createParsedCertificate(caTemplate, caTemplate, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	serverTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(2),
		Issuer:                casub,
		Subject:               serverSubj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{host},
	}

	serverCert, serverKey, err := createParsedCertificate(serverTemplate, caCert, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	pemCA, err := encodeCert(caCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding CA cert %v", err)
	}
	pemServerCert, err := encodeCert(serverCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding server cert %v", err)
	}
	pemServerKey, err := encodeKey(serverKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding server key %v", err)
	}

	return pemCA, pemServerCert, pemServerKey, nil
}

func visit(n *html.Node, visitor func(*html.Node)) {
	visitor(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		visit(c, visitor)
	}
}

func getTextNodes(root *html.Node) []*html.Node {
	elements := []*html.Node{}
	visit(root, func(n *html.Node) {
		if n.Type == html.TextNode {
			elements = append(elements, n)
		}
	})
	return elements
}

func getElementsByTagName(root *html.Node, tagName string) []*html.Node {
	elements := []*html.Node{}
	visit(root, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tagName {
			elements = append(elements, n)
		}
	})
	return elements
}

func getAttr(element *html.Node, attrName string) (string, bool) {
	for _, attr := range element.Attr {
		if attr.Key == attrName {
			return attr.Val, true
		}
	}
	return "", false
}

// newRequestFromForm builds a request that simulates submitting the given form.
func newRequestFromForm(form *html.Node, currentURL *url.URL, user, password string) (*http.Request, error) {
	var (
		reqMethod string
		reqURL    *url.URL
		reqBody   io.Reader
		reqHeader = http.Header{}
		err       error
	)

	// Method defaults to GET if empty
	if method, _ := getAttr(form, "method"); len(method) > 0 {
		reqMethod = strings.ToUpper(method)
	} else {
		reqMethod = "GET"
	}

	// URL defaults to current URL if empty
	action, _ := getAttr(form, "action")
	reqURL, err = currentURL.Parse(action)
	if err != nil {
		return nil, err
	}

	formData := url.Values{}
	if reqMethod == "GET" {
		// Start with any existing query params when we're submitting via GET
		formData = reqURL.Query()
	}
	addedSubmit := false
	for _, input := range getElementsByTagName(form, "input") {
		if name, ok := getAttr(input, "name"); ok {
			if value, ok := getAttr(input, "value"); ok {
				inputType, _ := getAttr(input, "type")

				switch inputType {
				case "text":
					if name == "username" {
						formData.Add(name, user)
					}
				case "password":
					if name == "password" {
						formData.Add(name, password)
					}
				case "submit":
					// If this is a submit input, only add the value of the first one.
					// We're simulating submitting the form.
					if !addedSubmit {
						formData.Add(name, value)
						addedSubmit = true
					}
				case "radio", "checkbox":
					if _, checked := getAttr(input, "checked"); checked {
						formData.Add(name, value)
					}
				default:
					formData.Add(name, value)
				}
			}
		}
	}

	switch reqMethod {
	case "GET":
		reqURL.RawQuery = formData.Encode()
	case "POST":
		reqHeader.Set("Content-Type", "application/x-www-form-urlencoded")
		reqBody = strings.NewReader(formData.Encode())
	default:
		return nil, fmt.Errorf("unknown method: %s", reqMethod)
	}

	req, err := http.NewRequest(reqMethod, reqURL.String(), reqBody)
	if err != nil {
		return nil, err
	}

	req.Header = reqHeader
	return req, nil
}

// Varying the login name for each test ensures we test a fresh grant
func createTestIdP(
	t *testing.T,
	kubeClient *kubernetes.Clientset,
	oauthClient configv1client.OAuthInterface,
	userClientSet *userclients.Clientset,
	nsName string,
	numUsers int,
) ([]string, func()) {
	oauthConfig, err := oauthClient.Get(context.TODO(), "cluster", metav1.GetOptions{})
	require.NoError(t, err)

	var users []string
	for i := 0; i < numUsers; i++ {
		users = append(users, fmt.Sprintf("testuser%d", i))
	}

	htpasswdSecretName := nsName + "htpasswd"
	kubeClient.CoreV1().Secrets("openshift-config").Create(context.TODO(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: htpasswdSecretName,
			},
			Data: map[string][]byte{
				"htpasswd": []byte(strings.Join(users, ":$2y$05$0Fk2s.0FbLy0FZ82JAqajOV/kbT/wqKX5/QFKgps6J69J2jY6r5ZG\n")), // bcrypt of 'password'
			},
		},
		metav1.CreateOptions{},
	)

	oauthConfig.Spec.IdentityProviders = append(
		oauthConfig.Spec.IdentityProviders, configv1.IdentityProvider{
			Name: nsName,
			IdentityProviderConfig: configv1.IdentityProviderConfig{
				Type: "HTPasswd",
				HTPasswd: &configv1.HTPasswdIdentityProvider{
					FileData: configv1.SecretNameReference{
						Name: htpasswdSecretName,
					},
				},
			},
		},
	)

	_, err = oauthClient.Update(context.TODO(), oauthConfig, metav1.UpdateOptions{})
	require.NoError(t, err)

	cleanup := func() {
		err := kubeClient.CoreV1().Secrets("openshift-config").Delete(context.TODO(), nsName+"htpasswd", metav1.DeleteOptions{})
		if err != nil {
			t.Logf("failed to delete secret openshift-config/%shtpasswd: %v", nsName, err)
		}
		oauthConfig, err := oauthClient.Get(context.TODO(), "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("failed to get the oauth/cluster config during cleanup: %v", err)
		}
		for i := range oauthConfig.Spec.IdentityProviders {
			if providers := oauthConfig.Spec.IdentityProviders; providers[i].Name == nsName {
				oauthConfig.Spec.IdentityProviders = deleteProvider(providers, i)
				break
			}
		}
		_, err = oauthClient.Update(context.TODO(), oauthConfig, metav1.UpdateOptions{})
		if err != nil {
			t.Logf("failed to remove the test IdP from oauth/cluster: %s", err)
		}

		for i := 0; i < numUsers; i++ {
			username := fmt.Sprintf("testuser%d", i)
			identityName := fmt.Sprintf("%s:%s", nsName, username)
			if err := userClientSet.UserV1().Users().Delete(context.TODO(), username, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
				t.Logf("failed to remove user: %s", username)
			}
			if err := userClientSet.UserV1().Identities().Delete(context.TODO(), identityName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
				t.Logf("failed to remove identity: %s", identityName)
			}
		}
	}
	return users, cleanup
}

func deleteProvider(provider []configv1.IdentityProvider, idx int) []configv1.IdentityProvider {
	provider[idx] = provider[len(provider)-1]
	return provider[:len(provider)-1]
}

// execCmd executes a command and returns the stdout + error, if any
func execCmd(cmd string, args []string, input string) (string, error) {
	c := exec.Command(cmd, args...)
	stdin, err := c.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer stdin.Close()
		if input != "" {
			io.WriteString(stdin, input)
		}
	}()

	out, err := c.CombinedOutput()
	if err != nil {
		fmt.Printf("Command '%s' failed with: %s\n", cmd, err)
		fmt.Printf("Output: %s\n", out)
		return "", err
	}
	return string(out), nil
}

func deleteTestRoute(routeName, namespace string) error {
	_, err := execCmd("oc", []string{"delete", fmt.Sprintf("route/%s", routeName), "-n", namespace}, "")
	if err != nil {
		return err
	}
	return nil
}

func getRouteHost(routeName, namespace string) (string, error) {
	out, err := execCmd("oc", []string{"get", fmt.Sprintf("route/%s", routeName), "-o", "jsonpath='{.spec.host}'", "-n", namespace}, "")
	if err != nil {
		return "", err
	}
	// strip surrounding single quotes
	return out[1 : len(out)-1], nil
}

func newOAuthProxyService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Labels: map[string]string{
				"app": "proxy",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "proxy",
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       int32(443),
					TargetPort: intstr.FromInt(8443),
				},
			},
		},
	}
}

// create a route using oc create directly
func createOAuthProxyRoute(t *testing.T, routeClient routev1client.RouteInterface) string {
	route, err := routeClient.Create(
		context.TODO(),
		&routev1.Route{
			ObjectMeta: metav1.ObjectMeta{
				Name: "proxy-route",
				Labels: map[string]string{
					"app": "proxy",
				},
			},
			Spec: routev1.RouteSpec{
				Port: &routev1.RoutePort{
					TargetPort: intstr.FromInt(8443),
				},
				To: routev1.RouteTargetReference{
					Kind:   "Service",
					Name:   "proxy",
					Weight: pint32(100),
				},
				WildcardPolicy: routev1.WildcardPolicyNone,
				TLS: &routev1.TLSConfig{
					Termination: routev1.TLSTerminationPassthrough,
				},
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err, "setup: error creating route: %s", err)

	return route.Spec.Host
}

func pint32(i int32) *int32 { return &i }
func pbool(b bool) *bool    { return &b }

func newOAuthProxySA() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Annotations: map[string]string{
				"serviceaccounts.openshift.io/oauth-redirectreference.primary": `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"proxy-route"}}`,
			},
		},
	}
}

func newOAuthProxyConfigMap(namespace string, pemCA, pemServerCert, pemServerKey, upstreamCA, upstreamCert, upstreamKey []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-certs",
			Namespace: namespace,
		},
		Data: map[string]string{
			"ca.crt":         "|\n" + string(pemCA),
			"tls.crt":        "|\n" + string(pemServerCert),
			"tls.key":        "|\n" + string(pemServerKey),
			"upstreamca.crt": "|\n" + string(upstreamCA),
			"upstream.crt":   "|\n" + string(upstreamCert),
			"upstream.key":   "|\n" + string(upstreamKey),
		},
	}
}

func newOAuthProxyPod(proxyImage, backendImage string, extraProxyArgs []string, envVars ...string) *corev1.Pod {
	backendEnvVars := []corev1.EnvVar{}
	for _, env := range envVars {
		e := strings.Split(env, "=")
		if len(e) <= 1 {
			continue
		}
		backendEnvVars = append(backendEnvVars, corev1.EnvVar{Name: e[0], Value: e[1]})
	}

	proxyArgs := append([]string{
		"--provider=openshift",
		"--openshift-service-account=proxy",
		"--https-address=:8443",
		"--tls-cert=/etc/tls/private/tls.crt",
		"--tls-key=/etc/tls/private/tls.key",
		"--tls-client-ca=/etc/tls/private/ca.crt",
		"--cookie-secret=SECRET",
		"--skip-provider-button",
	}, extraProxyArgs...)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Labels: map[string]string{
				"app": "proxy",
			},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "proxy-cert-volume",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "proxy-certs"},
						},
					},
				},
			},
			ServiceAccountName: "proxy",
			Containers: []corev1.Container{
				{
					Image:           proxyImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Name:            "oauth-proxy",
					Args:            proxyArgs,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8443,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/etc/tls/private",
							Name:      "proxy-cert-volume",
						},
					},
				},
				{
					Image: backendImage,
					Name:  "hello-openshift",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8080,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/etc/tls/private",
							Name:      "proxy-cert-volume",
						},
					},
					Env: backendEnvVars,
				},
			},
		},
	}
}

// NewClientConfigForTest returns a config configured to connect to the api server
func NewClientConfigForTest(t *testing.T) *rest.Config {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{ClusterInfo: cmdapi.Cluster{InsecureSkipTLSVerify: true}})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		t.Logf("Found configuration for host %v.\n", config.Host)
	}

	require.NoError(t, err)
	return config
}

func WaitForClusterOperatorStatus(t *testing.T, client configv1client.ConfigV1Interface, available, progressing, degraded *bool) error {
	status := map[configv1.ClusterStatusConditionType]bool{} // struct for easy printing the conditions
	return wait.PollImmediate(time.Second, 10*time.Minute, func() (bool, error) {
		clusterOperator, err := client.ClusterOperators().Get(context.TODO(), "authentication", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("clusteroperators.config.openshift.io/authentication: %v", err)
			return false, nil
		}
		if retry.IsHTTPClientError(err) {
			t.Logf("clusteroperators.config.openshift.io/authentication: %v", err)
			return false, nil
		}
		availableStatusIsMatch, progressingStatusIsMatch, degradedStatusIsMatch := true, true, true
		conditions := clusterOperator.Status.Conditions
		status[configv1.OperatorAvailable] = v1helpers.IsStatusConditionTrue(conditions, configv1.OperatorAvailable)
		status[configv1.OperatorProgressing] = v1helpers.IsStatusConditionTrue(conditions, configv1.OperatorProgressing)
		status[configv1.OperatorDegraded] = v1helpers.IsStatusConditionTrue(conditions, configv1.OperatorDegraded)
		if available != nil {
			availableStatusIsMatch = status[configv1.OperatorAvailable] == *available
		}
		if progressing != nil {
			progressingStatusIsMatch = status[configv1.OperatorProgressing] == *progressing
		}
		if degraded != nil {
			degradedStatusIsMatch = status[configv1.OperatorDegraded] == *degraded
		}

		t.Logf("current authentication operator status: %v", status)
		done := availableStatusIsMatch && progressingStatusIsMatch && degradedStatusIsMatch
		return done, nil
	})
}
