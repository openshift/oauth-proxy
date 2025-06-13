package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	configclient "github.com/openshift/client-go/config/clientset/versioned"
	projectclient "github.com/openshift/client-go/project/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

func TestOAuthProxyE2E(t *testing.T) {
	ctx := context.Background()

	testConfig := NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(testConfig)
	require.NoError(t, err)
	configClient, err := configclient.NewForConfig(testConfig)
	require.NoError(t, err)
	projectClient, err := projectclient.NewForConfig(testConfig)
	require.NoError(t, err)
	routeClient, err := routeclient.NewForConfig(testConfig)
	require.NoError(t, err)
	userClient, err := userclient.NewForConfig(testConfig)
	require.NoError(t, err)
	ns := CreateTestProject(t, kubeClient, projectClient)
	defer func() {
		if len(os.Getenv("DEBUG_TEST")) > 0 {
			return
		}
		kubeClient.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	}()

	testCases := []struct {
		name          string
		proxyArgs     []string
		expectedErr   string
		accessSubPath string
		pageResult    string
		bypass        bool
	}{
		{
			name: "basic",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
			},
			pageResult: "URI: /",
		},
		{
			name: "scope-full",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				"--scope=user:full",
			},
			expectedErr: "403 Forbidden",
		},
		{
			name: "sar-ok",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"` + ns + `","resource":"services","verb":"list"}`,
			},
			pageResult: "URI: /",
		},
		{
			name: "sar-fail",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"other","resource":"services","verb":"list"}`,
			},
			expectedErr: "403 Forbidden",
		},
		{
			name: "sar-name-ok",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"` + ns + `","resource":"routes","resourceName":"proxy-route","verb":"get"}`,
			},
			pageResult: "URI: /",
		},
		{
			name: "sar-name-fail",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"other","resource":"routes","resourceName":"proxy-route","verb":"get"}`,
			},
			expectedErr: "403 Forbidden",
		},
		{
			name: "sar-multi-ok",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar=[{"namespace":"` + ns + `","resource":"services","verb":"list"}, {"namespace":"` + ns + `","resource":"routes","verb":"list"}]`,
			},
			pageResult: "URI: /",
		},
		{
			name: "sar-multi-fail",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar=[{"namespace":"` + ns + `","resource":"services","verb":"list"}, {"namespace":"other","resource":"pods","verb":"list"}]`,
			},
			expectedErr: "403 Forbidden",
		},
		{
			name: "skip-auth-regex-bypass-foo",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--skip-auth-regex=^/foo`,
			},
			accessSubPath: "/foo",
			pageResult:    "URI: /foo\n",
			bypass:        true,
		},
		{
			name: "skip-auth-regex-protect-bar",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--skip-auth-regex=^/foo`,
			},
			accessSubPath: "/bar",
			pageResult:    "URI: /bar",
		},
		{
			name: "bypass-auth-foo",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--bypass-auth-for=^/foo`,
			},
			accessSubPath: "/foo",
			pageResult:    "URI: /foo\n",
			bypass:        true,
		},
		{
			name: "bypass-auth-except-protected",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--bypass-auth-except-for=^/foo`,
			},
			accessSubPath: "/foo",
			pageResult:    "URI: /foo\n",
		},
		{
			name: "bypass-auth-except-bypassed",
			proxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--bypass-auth-except-for=^/foo`,
			},
			accessSubPath: "/bar",
			pageResult:    "URI: /bar",
			bypass:        true,
		},
	}

	registry := strings.Split(os.Getenv("RELEASE_IMAGE_LATEST"), "/")[0]
	require.NotEmpty(t, registry, "Registry is empty. Check RELEASE_IMAGE_LATEST environment variable.")
	namespace := os.Getenv("NAMESPACE")
	require.NotEmpty(t, namespace, "Namespace is empty. Check NAMESPACE environment variable.")
	image := registry + "/" + namespace + "/pipeline:oauth-proxy"

	// get rid of kubeadmin user to remove the additional step of choosing an idp
	err = kubeClient.CoreV1().Secrets("kube-system").Delete(context.TODO(), "kubeadmin", metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Fatalf("couldn't remove the kubeadmin user: %v", err)
	}

	users, idpCleanup := createTestIdP(t, kubeClient, configClient.ConfigV1().OAuths(), userClient, ns, len(testCases))
	defer func() {
		if len(os.Getenv("DEBUG_TEST")) == 0 {
			idpCleanup()
		}
	}()

	// wait for the IdP to be honored in the oauth-server
	WaitForClusterOperatorStatus(t, configClient.ConfigV1(), nil, pbool(true), nil)
	WaitForClusterOperatorStatus(t, configClient.ConfigV1(), pbool(true), pbool(false), nil)

	t.Logf("test image: %s, test namespace: %s", image, ns)

	backendImage := "nginxdemos/nginx-hello:plain-text"
	currentTestIdx := 0 // to pick the current user so that each test gets a fresh grant
	for _, tc := range testCases {
		runOnly := os.Getenv("TEST")
		if len(runOnly) > 0 && runOnly != tc.name {
			continue
		}

		t.Run(fmt.Sprintf("setting up e2e tests %s", tc.name), func(t *testing.T) {
			_, err := kubeClient.CoreV1().ServiceAccounts(ns).Create(ctx, newOAuthProxySA(tc.name), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating SA: %s", err)
			}

			proxyRouteHost := createOAuthProxyRoute(t, routeClient.RouteV1().Routes(ns), tc.name)

			// Create the TLS certificate set for the client and service (with the route hostname attributes)
			caPem, serviceCert, serviceKey, err := createCAandCertSet(proxyRouteHost)
			if err != nil {
				t.Fatalf("setup: error creating TLS certs: %s", err)
			}

			// Create the TLS certificate set for the proxy backend (-upstream-ca) and the upstream site
			upstreamCA, upstreamCert, upstreamKey, err := createCAandCertSet("localhost")
			if err != nil {
				t.Fatalf("setup: error creating upstream TLS certs: %s", err)
			}

			_, err = kubeClient.CoreV1().Services(ns).Create(ctx, newOAuthProxyService(tc.name), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating service: %s", err)
			}

			// configMap provides oauth-proxy with the certificates we created above
			_, err = kubeClient.CoreV1().ConfigMaps(ns).Create(ctx, newOAuthProxyConfigMap(ns, tc.name, caPem, serviceCert, serviceKey, upstreamCA, upstreamCert, upstreamKey), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating certificate configMap: %s", err)
			}

			oauthProxyPod, err := kubeClient.CoreV1().Pods(ns).Create(ctx, newOAuthProxyPod(image, backendImage, tc.name, tc.proxyArgs), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating oauth-proxy pod with image '%s' and args '%v': %s", image, tc.proxyArgs, err)
			}

			err = waitForPodRunningInNamespace(kubeClient, oauthProxyPod)
			if err != nil {
				t.Fatalf("setup: error waiting for pod to run: %s", err)
			}

			openshiftTransport, err := rest.TransportFor(testConfig)
			require.NoError(t, err)

			host := "https://" + proxyRouteHost + "/oauth/start"
			// Wait for the route, we get an EOF if we move along too fast
			err = waitUntilRouteIsReady(t, openshiftTransport, host)
			if err != nil {
				t.Fatalf("setup: error waiting for route availability: %s", err)
			}

			user := users[currentTestIdx]
			// For SAR tests the random user needs the admin role for this namespace.
			t.Logf("Setting admin role for user %s in namespace %s", user, ns)
			roleBinding := newOAuthProxyRoleBinding(user, ns)
			_, err = kubeClient.RbacV1().RoleBindings(ns).
				Create(ctx, roleBinding, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error setting test user role: %s", err)
			}
			defer func() {
				_ = kubeClient.RbacV1().RoleBindings(ns).
					Delete(ctx, "sar-"+user, metav1.DeleteOptions{})
			}()

			defer func() {
				t.Logf("cleaning up test %s", tc.name)
				kubeClient.CoreV1().Pods(ns).Delete(ctx, "proxy", metav1.DeleteOptions{})
				kubeClient.CoreV1().Services(ns).Delete(ctx, "proxy", metav1.DeleteOptions{})
				deleteTestRoute(t, routeClient, "proxy-route")
				kubeClient.CoreV1().ConfigMaps(ns).Delete(ctx, "proxy-certs", metav1.DeleteOptions{})
				kubeClient.CoreV1().ServiceAccounts(ns).Delete(ctx, "proxy", metav1.DeleteOptions{})
				waitForPodDeletion(kubeClient, oauthProxyPod.Name, ns)
				execCmd("oc", []string{"adm", "policy", "remove-role-from-user", "admin", user, "-n", ns}, "")
			}()

			waitForHealthzCheck(t, openshiftTransport, "https://"+proxyRouteHost)

			check3DESDisabled(t, "https://"+proxyRouteHost, caPem)

			err = testOAuthProxyLogin(t, openshiftTransport, proxyRouteHost, tc.accessSubPath, user, "password", tc.pageResult, tc.expectedErr, tc.bypass)

			if err == nil && len(tc.expectedErr) > 0 {
				t.Errorf("expected error '%s', but test passed", tc.expectedErr)
			}

			if err != nil {
				if len(tc.expectedErr) > 0 {
					if tc.expectedErr != err.Error() {
						t.Errorf("expected error '%s', got '%s'", tc.expectedErr, err)
					}
				} else {
					t.Errorf("test failed with '%s'", err)
				}
			}
		})

		// increase the current user
		currentTestIdx++
	}
}

func confirmOAuthFlow(client *http.Client, requestURL, user, password,
	expectedErr string, expectBypass bool) error {
	authorizeResponse, err := client.Get(requestURL)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to get authorization page: %v", err)
	}
	defer authorizeResponse.Body.Close()
	if authorizeResponse.StatusCode != 200 {
		r, _ := io.ReadAll(authorizeResponse.Body)
		return fmt.Errorf("OAuth authorization page returned status %s: %s",
			authorizeResponse.Status, string(r))
	}

	loginPageContent, err := io.ReadAll(authorizeResponse.Body)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to read login page: %v", err)
	}
	loginPageParsed, err := html.Parse(strings.NewReader(string(loginPageContent)))
	if err != nil {
		return fmt.Errorf("OAuth flow failed to parse login page: %v", err)
	}
	loginTitle := getElementsByTagName(loginPageParsed, "title")
	actualTitle := getPageTitle(loginTitle)
	if len(loginTitle) == 0 || !strings.Contains(actualTitle, "Log in") {
		return fmt.Errorf("OAuth flow expected login page but got title: %q",
			actualTitle)
	}
	loginForm := getElementsByTagName(loginPageParsed, "form")
	if len(loginForm) != 1 {
		return fmt.Errorf("OAuth flow expected single login form, got %d forms",
			len(loginForm))
	}
	loginFormRequest, err := newRequestFromForm(loginForm[0],
		authorizeResponse.Request.URL, user, password)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to create login request: %v", err)
	}

	loginRequestContent, err := io.ReadAll(loginFormRequest.Body)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to read login request body: %v", err)
	}
	loginFormRequest.Body = io.NopCloser(bytes.NewReader(loginRequestContent))

	loginResp, err := client.Do(loginFormRequest)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to submit login form: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		r, _ := io.ReadAll(loginResp.Body)
		return fmt.Errorf("OAuth login form returned status %s: %s",
			loginResp.Status, string(r))
	}
	loginRespContent, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to read login response: %v", err)
	}
	loginRespParsed, err := html.Parse(strings.NewReader(string(loginRespContent)))
	if err != nil {
		return fmt.Errorf("OAuth flow failed to parse login response: %v", err)
	}

	loginRespTitle := getElementsByTagName(loginRespParsed, "title")
	actualAuthTitle := getPageTitle(loginRespTitle)
	if len(loginRespTitle) == 0 ||
		!strings.Contains(actualAuthTitle, "Authorize") {
		return fmt.Errorf("OAuth flow expected authorization page but got title: %q",
			actualAuthTitle)
	}

	grantForm := getElementsByTagName(loginRespParsed, "form")
	if len(grantForm) != 1 {
		return fmt.Errorf("OAuth flow expected single authorization form, got %d forms",
			len(grantForm))
	}
	grantFormRequest, err := newRequestFromForm(grantForm[0],
		loginResp.Request.URL, user, password)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to create authorization request: %v",
			err)
	}
	grantFormRequestContent, err := io.ReadAll(grantFormRequest.Body)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to read authorization request body: %v",
			err)
	}

	grantFormRequest.Body = io.NopCloser(bytes.NewReader(grantFormRequestContent))

	grantResp, err := client.Do(grantFormRequest)
	if err != nil {
		return fmt.Errorf("OAuth flow failed to submit authorization form: %v", err)
	}
	defer grantResp.Body.Close()
	if grantResp.StatusCode != 200 {
		r, _ := io.ReadAll(grantResp.Body)
		return fmt.Errorf("OAuth authorization form returned status %s: %s",
			grantResp.Status, string(r))
	}

	return nil
}

func testOAuthProxyLogin(t *testing.T, transport http.RoundTripper, host, subPath, user, password, expectedResult, expectedErr string, expectBypass bool) error {
	client := newHTTPSClient(t, transport)

	if !expectBypass {
		if err := confirmOAuthFlow(client, "https://"+host+subPath, user, password, expectedErr, expectBypass); err != nil {
			return err
		}
	}

	authenticateResp, err := client.Get("https://" + host + subPath)
	if err != nil {
		return fmt.Errorf("failed to retrieve the base page")
	}
	defer authenticateResp.Body.Close()

	// we should be authenticated now
	if authenticateResp.StatusCode != 200 {
		r, _ := ioutil.ReadAll(authenticateResp.Body)
		return fmt.Errorf("expected to be authenticated, got status %q, page:\n%s", authenticateResp.Status, r)
	}

	if authenticateResp.Request.Host != host {
		return fmt.Errorf("did not reach upstream site")
	}

	authenticatedContent, err := ioutil.ReadAll(authenticateResp.Body)
	require.NoError(t, err)

	if !strings.Contains(string(authenticatedContent), expectedResult) {
		// don't print the whole returned page, it makes the test result unreadable
		t.Fatalf("expected authenticated page to contain %s, but it's missing", expectedResult)
	}

	return nil
}

func check3DESDisabled(t *testing.T, proxyURL string, proxyCA []byte) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(proxyCA) {
		t.Fatalf("error loading CA for client config")
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			// TLS 1.3 uses specific cipher suites and ignores the cipher suite config above
			MaxVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr, Jar: jar}
	resp, err := getResponse(proxyURL, client)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected to fail with weak ciphers")
	}
	if !strings.Contains(err.Error(), "handshake failure") {
		t.Fatalf("expected TLS handshake error with weak ciphers, got: %v", err)
	}
}
