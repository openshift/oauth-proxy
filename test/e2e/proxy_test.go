package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
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
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

func TestOAuthProxyE2E(t *testing.T) {
	testConfig := NewClientConfigForTest(t)
	kubeClient, err := kubernetes.NewForConfig(testConfig)
	require.NoError(t, err)

	ns, cancel := CreateTestProjectWithCancel(t, kubeClient)
	defer cancel()

	// TODO@ibihim: replace with proper image after fixing
	image := "quay.io/kostrows/oauth-proxy:latest"
	t.Logf("Using custom debug image: %s", image)

	t.Log("Removing kubeadmin user if exists")
	kubeadminSecret, err := kubeClient.CoreV1().Secrets("kube-system").
		Get(context.TODO(), "kubeadmin", metav1.GetOptions{})
	var kubeadminExisted bool
	if err != nil && !errors.IsNotFound(err) {
		t.Fatalf("couldn't check for kubeadmin user: %v", err)
	}
	if err == nil {
		kubeadminExisted = true
		t.Log("kubeadmin user found, backing up for restoration")
	}

	err = kubeClient.CoreV1().Secrets("kube-system").
		Delete(context.TODO(), "kubeadmin", metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Fatalf("couldn't remove the kubeadmin user: %v", err)
	}

	if kubeadminExisted {
		defer func() {
			t.Log("Restoring kubeadmin user")
			kubeadminSecret.ResourceVersion = ""
			kubeadminSecret.UID = ""
			_, err := kubeClient.CoreV1().Secrets("kube-system").
				Create(context.TODO(), kubeadminSecret, metav1.CreateOptions{})
			if err != nil {
				t.Errorf("Failed to restore kubeadmin user: %v", err)
			}
		}()
	}

	configClient, err := configclient.NewForConfig(testConfig)
	require.NoError(t, err)
	userClient, err := userclient.NewForConfig(testConfig)
	require.NoError(t, err)

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

	users, idpCleanup := createTestIdP(t, kubeClient,
		configClient.ConfigV1().OAuths(), userClient, ns, len(testCases))
	t.Logf("Created test IdP with %d users", len(users))
	defer idpCleanup()

	// wait for the IdP to be honored in the oauth-server
	t.Log("Waiting for IdP to be honored in oauth-server")
	err = WaitForClusterOperatorStatus(t, configClient.ConfigV1(), nil,
		pbool(true), nil)
	require.NoError(t, err, "Error waiting for oauth-server operator to be ready")
	err = WaitForClusterOperatorStatus(t, configClient.ConfigV1(),
		pbool(true), pbool(false), nil)
	require.NoError(t, err, "Error waiting for oauth-server operator to be ready")

	routeClient, err := routeclient.NewForConfig(testConfig)
	require.NoError(t, err)

	openshiftTransport, err := rest.TransportFor(testConfig)
	require.NoError(t, err)

	backendImage := "nginxdemos/nginx-hello:plain-text"

	upstreamCA, upstreamCert, upstreamKey, err := createCAandCertSet("localhost")
	require.NoError(t, err, "Error creating upstream TLS certificates")

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("setting up e2e tests %s", tc.name), func(t *testing.T) {
			ctx := t.Context()
			user := users[i]
			t.Logf("Using test user: %s", user)

			sa, err := kubeClient.CoreV1().ServiceAccounts(ns).Create(
				ctx, newOAuthProxySA(tc.name), metav1.CreateOptions{},
			)
			if err != nil {
				t.Fatalf("setup: error creating SA: %s", err)
			}
			defer func() {
				_ = kubeClient.CoreV1().ServiceAccounts(ns).
					Delete(ctx, sa.Name, metav1.DeleteOptions{})
			}()

			proxyRouteHost := createOAuthProxyRoute(t,
				routeClient.RouteV1().Routes(ns), tc.name)
			defer func() {
				_ = deleteTestRoute(fmt.Sprintf("proxy-route-%s", tc.name), ns)
			}()

			caPem, serviceCert, serviceKey, err := createCAandCertSet(proxyRouteHost)
			if err != nil {
				t.Fatalf("setup: error creating TLS certs: %s", err)
			}

			svc, err := kubeClient.CoreV1().Services(ns).
				Create(ctx, newOAuthProxyService(tc.name), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating service: %s", err)
			}
			defer func() {
				_ = kubeClient.CoreV1().Services(ns).
					Delete(ctx, svc.Name, metav1.DeleteOptions{})
			}()

			cm, err := kubeClient.CoreV1().ConfigMaps(ns).Create(
				ctx,
				newOAuthProxyConfigMap(
					ns, tc.name,
					caPem,
					serviceCert, serviceKey,
					upstreamCA, upstreamCert, upstreamKey,
				), metav1.CreateOptions{},
			)
			if err != nil {
				t.Fatalf("setup: error creating certificate configMap: %s", err)
			}
			defer func() {
				_ = kubeClient.CoreV1().ConfigMaps(ns).
					Delete(ctx, cm.Name, metav1.DeleteOptions{})
			}()

			t.Logf("Creating OAuth proxy pod with args: %v", tc.proxyArgs)
			oauthProxyPod, err := kubeClient.CoreV1().Pods(ns).Create(
				ctx,
				newOAuthProxyPod(image, backendImage, tc.name, tc.proxyArgs),
				metav1.CreateOptions{},
			)
			if err != nil {
				t.Fatalf("setup: error creating oauth-proxy pod with image '%s' and args '%v': %s",
					image, tc.proxyArgs, err)
			}
			defer func() {
				_ = kubeClient.CoreV1().Pods(ns).
					Delete(ctx, oauthProxyPod.Name, metav1.DeleteOptions{})
				_ = waitForPodDeletion(kubeClient, oauthProxyPod.Name, ns)
			}()

			err = waitForPodRunningInNamespace(kubeClient, oauthProxyPod)
			if err != nil {
				t.Fatalf("setup: error waiting for pod to run: %s", err)
			}

			host := "https://" + proxyRouteHost + "/oauth/start"
			// Wait for the route, we get an EOF if we move along too fast
			t.Logf("Waiting for route %s to be ready", host)
			err = waitUntilRouteIsReady(t, openshiftTransport, host)
			if err != nil {
				t.Fatalf("setup: error waiting for route availability: %s", err)
			}

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

			_ = waitForHealthzCheck(t, openshiftTransport, "https://"+proxyRouteHost)

			check3DESDisabled(t, "https://"+proxyRouteHost, caPem)

			t.Logf("Testing OAuth proxy login with user %s to path %s",
				user, tc.accessSubPath)
			err = testOAuthProxyLogin(t, openshiftTransport, proxyRouteHost,
				tc.accessSubPath, user, "password", tc.pageResult,
				tc.expectedErr, tc.bypass)

			if err == nil && len(tc.expectedErr) > 0 {
				t.Errorf("expected error '%s', but test passed", tc.expectedErr)
			}

			if err != nil {
				if len(tc.expectedErr) > 0 {
					if strings.Contains(err.Error(), tc.expectedErr) {
						t.Logf("Got expected error containing '%s': %s",
						tc.expectedErr, err.Error())
					} else {
						t.Errorf("expected error containing '%s', got '%s'", tc.expectedErr, err)
					}
				} else {
					t.Errorf("test failed with '%s'", err)
				}
			}
		})
	}

}

func testOAuthProxyLogin(t *testing.T, transport http.RoundTripper,
	host, subPath, user, password, expectedResult, expectedErr string,
	expectBypass bool) error {
	t.Logf("Testing OAuth proxy login for host: %s, path: %s, user: %s",
		host, subPath, user)
	client := newHTTPSClient(t, transport)

	if !expectBypass {
		t.Log("Confirming OAuth flow (auth required)")
		if err := confirmOAuthFlow(client, "https://"+host+subPath, user,
			password, expectedErr, expectBypass); err != nil {
			t.Logf("OAuth flow failed: %v", err)
			return err
		}
	} else {
	}

	authenticateResp, err := client.Get("https://" + host + subPath)
	if err != nil {
		t.Logf("Failed to retrieve the base page: %v", err)
		return fmt.Errorf("failed to retrieve the base page")
	}
	defer authenticateResp.Body.Close()

	authenticatedContent, err := io.ReadAll(authenticateResp.Body)
	require.NoError(t, err)

	if authenticateResp.StatusCode != 200 {
		return fmt.Errorf("expected to be authenticated, got status %q, page:\n%s",
			authenticateResp.Status, string(authenticatedContent))
	}

	if authenticateResp.Request.Host != host {
		return fmt.Errorf("did not reach upstream site - host mismatch")
	}

	if !strings.Contains(string(authenticatedContent), expectedResult) {
		// don't print the whole returned page, it makes the test result unreadable
		t.Fatalf("expected authenticated page to contain %s, but it's missing",
			expectedResult)
	}

	t.Log("Page content contains expected result")
	return nil
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

func check3DESDisabled(t *testing.T, proxyURL string, proxyCA []byte) {
	t.Logf("Checking 3DES is disabled on: %s", proxyURL)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(proxyCA) {
		t.Fatalf("error loading CA for client config")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("error creating cookie jar: %v", err)
	}

	tr := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			// TLS 1.3 uses specific cipher suites and ignores the
			// cipher suite config above
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
	t.Log("3DES check passed - connection properly rejected")
}
