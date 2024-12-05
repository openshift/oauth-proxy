package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	testCtx := context.Background()

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
		kubeClient.CoreV1().Namespaces().Delete(testCtx, ns, metav1.DeleteOptions{})
	}()

	oauthProxyTests := map[string]struct {
		oauthProxyArgs []string
		expectedErr    string
		accessSubPath  string
		pageResult     string
		bypass         bool
	}{
		"basic": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
			},
			pageResult: "URI: /",
		},
		// Tests a scope that is not valid for SA OAuth client use
		"scope-full": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				"--scope=user:full",
			},
			expectedErr: "403 Permission Denied",
		},
		"sar-ok": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"` + ns + `","resource":"services","verb":"list"}`,
			},
			pageResult: "URI: /",
		},
		"sar-fail": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"other","resource":"services","verb":"list"}`,
			},
			expectedErr: "did not reach upstream site",
		},
		"sar-name-ok": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"` + ns + `","resource":"routes","resourceName":"proxy-route","verb":"get"}`,
			},
			pageResult: "URI: /",
		},
		"sar-name-fail": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar={"namespace":"other","resource":"routes","resourceName":"proxy-route","verb":"get"}`,
			},
			expectedErr: "did not reach upstream site",
		},
		"sar-multi-ok": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar=[{"namespace":"` + ns + `","resource":"services","verb":"list"}, {"namespace":"` + ns + `","resource":"routes","verb":"list"}]`,
			},
			pageResult: "URI: /",
		},
		"sar-multi-fail": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--openshift-sar=[{"namespace":"` + ns + `","resource":"services","verb":"list"}, {"namespace":"other","resource":"pods","verb":"list"}]`,
			},
			expectedErr: "did not reach upstream site",
		},
		"skip-auth-regex-bypass-foo": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--skip-auth-regex=^/foo`,
			},
			accessSubPath: "/foo",
			pageResult:    "URI: /foo\n",
			bypass:        true,
		},
		"skip-auth-regex-protect-bar": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--skip-auth-regex=^/foo`,
			},
			accessSubPath: "/bar",
			pageResult:    "URI: /bar",
		},
		// test --bypass-auth-for (alias for --skip-auth-regex); expect to bypass auth for /foo
		"bypass-auth-foo": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--bypass-auth-for=^/foo`,
			},
			accessSubPath: "/foo",
			pageResult:    "URI: /foo\n",
			bypass:        true,
		},
		// test --bypass-auth-except-for; expect to auth /foo
		"bypass-auth-except-try-protected": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--bypass-auth-except-for=^/foo`,
			},
			accessSubPath: "/foo",
			pageResult:    "URI: /foo\n",
		},
		// test --bypass-auth-except-for; expect to bypass auth for paths other than /foo
		"bypass-auth-except-try-bypassed": {
			oauthProxyArgs: []string{
				"--upstream=http://localhost:8080",
				`--bypass-auth-except-for=^/foo`,
			},
			accessSubPath: "/bar",
			pageResult:    "URI: /bar",
			bypass:        true,
		},
		// TODO: find or write a containerized test http server that allows simple TLS config
		// --upstream-ca set with the CA for the backend site's certificate
		// "upstream-ca": {
		// 	oauthProxyArgs: []string{
		// 		"--upstream=https://localhost:8080",
		// 		"--upstream-ca=/etc/tls/private/upstreamca.crt",
		// 	},
		// 	backendEnvs: []string{"HELLO_TLS_CERT=/etc/tls/private/upstream.crt", "HELLO_TLS_KEY=/etc/tls/private/upstream.key"},
		// 	pageResult:  "URI: /",
		// },
		// // --upstream-ca set multiple times, with one matching CA
		// "upstream-ca-multi": {
		// 	oauthProxyArgs: []string{
		// 		"--upstream=https://localhost:8080",
		// 		"--upstream-ca=/etc/tls/private/upstreamca.crt",
		// 		"--upstream-ca=/etc/tls/private/ca.crt",
		// 	},
		// 	backendEnvs: []string{"HELLO_TLS_CERT=/etc/tls/private/upstream.crt", "HELLO_TLS_KEY=/etc/tls/private/upstream.key"},
		// 	pageResult:  "URI: /",
		// },
		// // no --upstream-ca set, so there's no valid TLS connection between proxy and upstream
		// "upstream-ca-missing": {
		// 	oauthProxyArgs: []string{
		// 		"--upstream=https://localhost:8080",
		// 	},
		// 	backendEnvs: []string{"HELLO_TLS_CERT=/etc/tls/private/upstream.crt", "HELLO_TLS_KEY=/etc/tls/private/upstream.key"},
		// 	expectedErr: "did not reach upstream site",
		// },
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

	users, idpCleanup := createTestIdP(t, kubeClient, configClient.ConfigV1().OAuths(), userClient, ns, len(oauthProxyTests))
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
	for tcName, tc := range oauthProxyTests {
		runOnly := os.Getenv("TEST")
		if len(runOnly) > 0 && runOnly != tcName {
			continue
		}

		t.Run(fmt.Sprintf("setting up e2e tests %s", tcName), func(t *testing.T) {
			_, err := kubeClient.CoreV1().ServiceAccounts(ns).Create(testCtx, newOAuthProxySA(), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating SA: %s", err)
			}

			proxyRouteHost := createOAuthProxyRoute(t, routeClient.RouteV1().Routes(ns))

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

			_, err = kubeClient.CoreV1().Services(ns).Create(testCtx, newOAuthProxyService(), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating service: %s", err)
			}

			// configMap provides oauth-proxy with the certificates we created above
			_, err = kubeClient.CoreV1().ConfigMaps(ns).Create(testCtx, newOAuthProxyConfigMap(ns, caPem, serviceCert, serviceKey, upstreamCA, upstreamCert, upstreamKey), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating certificate configMap: %s", err)
			}

			oauthProxyPod, err := kubeClient.CoreV1().Pods(ns).Create(testCtx, newOAuthProxyPod(image, backendImage, tc.oauthProxyArgs), metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("setup: error creating oauth-proxy pod with image '%s' and args '%v': %s", image, tc.oauthProxyArgs, err)
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
			out, err := execCmd("oc", []string{"adm", "policy", "add-role-to-user", "admin", user, "-n", ns, "--rolebinding-name", "sar-" + user}, "")
			if err != nil {
				t.Fatalf("setup: error setting test user role: %s", err)
			}
			t.Logf("%s", out)

			defer func() {
				if os.Getenv("DEBUG_TEST") == tcName {
					t.Fatalf("skipping cleanup step for test '%s' and stopping on command", tcName)
				}
				t.Logf("cleaning up test %s", tcName)
				kubeClient.CoreV1().Pods(ns).Delete(testCtx, "proxy", metav1.DeleteOptions{})
				kubeClient.CoreV1().Services(ns).Delete(testCtx, "proxy", metav1.DeleteOptions{})
				deleteTestRoute("proxy-route", ns)
				kubeClient.CoreV1().ConfigMaps(ns).Delete(testCtx, "proxy-certs", metav1.DeleteOptions{})
				kubeClient.CoreV1().ServiceAccounts(ns).Delete(testCtx, "proxy", metav1.DeleteOptions{})
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

func submitOAuthForm(client *http.Client, response *http.Response, user, password, expectedErr string) (*http.Response, error) {
	bodyParsed, err := html.Parse(response.Body)
	if err != nil {
		return nil, err
	}

	forms := getElementsByTagName(bodyParsed, "form")
	if len(forms) != 1 {
		errMsg := "expected a single OpenShift form"
		if len(expectedErr) != 0 {
			// Return the expected error if it's found amongst the text elements
			textNodes := getTextNodes(bodyParsed)
			for i := range textNodes {
				if textNodes[i].Data == expectedErr {
					errMsg = expectedErr
				}
			}
		}
		return nil, fmt.Errorf(errMsg)

	}

	formReq, err := newRequestFromForm(forms[0], response.Request.URL, user, password)
	if err != nil {
		return nil, err
	}

	postResp, err := client.Do(formReq)
	if err != nil {
		return nil, err
	}

	return postResp, nil
}

func confirmOAuthFlow(client *http.Client, requestURL, user, password, expectedErr string, expectBypass bool) error {
	resp, err := client.Get(requestURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		r, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("expected to be redirected to the oauth-server login page, got %q; page content\n%s", resp.Status, r)
	}

	// OpenShift login page
	loginResp, err := submitOAuthForm(client, resp, user, password, expectedErr)
	if err != nil {
		return err
	}
	defer loginResp.Body.Close()
	if resp.StatusCode != 200 {
		r, _ := ioutil.ReadAll(loginResp.Body)
		return fmt.Errorf("failed to submit the login form: %q\n page content\n%s", resp.Status, r)
	}

	// authorization grant form; no password should be expected
	grantResp, err := submitOAuthForm(client, loginResp, user, "", expectedErr)
	if err != nil {
		return err
	}
	defer grantResp.Body.Close()
	if resp.StatusCode != 200 {
		r, _ := ioutil.ReadAll(grantResp.Body)
		return fmt.Errorf("failed to submit the grant form: %q\n pageC content\n%s", resp.Status, r)
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
