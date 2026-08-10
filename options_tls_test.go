package main

import (
	"strings"
	"testing"
)

func TestOptions_Validate_TLS(t *testing.T) {
	tests := []struct {
		name            string
		tlsMinVersion   string
		tlsCipherSuites []string
		httpsAddress    string
		wantErr         bool
		errContains     string
	}{
		{
			name:          "empty TLS config is valid",
			tlsMinVersion: "",
			httpsAddress:  ":8443",
			wantErr:       false,
		},
		{
			name:          "TLS 1.2 is allowed",
			tlsMinVersion: "VersionTLS12",
			httpsAddress:  ":8443",
			wantErr:       false,
		},
		{
			name:          "TLS 1.3 is allowed",
			tlsMinVersion: "VersionTLS13",
			httpsAddress:  ":8443",
			wantErr:       false,
		},
		{
			name:          "TLS 1.0 is rejected (insecure)",
			tlsMinVersion: "VersionTLS10",
			httpsAddress:  ":8443",
			wantErr:       true,
			errContains:   "tls-min-version must be VersionTLS12 or VersionTLS13",
		},
		{
			name:          "TLS 1.1 is rejected (insecure)",
			tlsMinVersion: "VersionTLS11",
			httpsAddress:  ":8443",
			wantErr:       true,
			errContains:   "tls-min-version must be VersionTLS12 or VersionTLS13",
		},
		{
			name:          "unknown TLS version is rejected",
			tlsMinVersion: "VersionTLS99",
			httpsAddress:  ":8443",
			wantErr:       true,
			errContains:   "invalid tls-min-version",
		},
		{
			name:            "valid cipher suites are allowed",
			tlsCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			httpsAddress:    ":8443",
			wantErr:         false,
		},
		{
			name:            "multiple valid cipher suites are allowed",
			tlsCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			httpsAddress:    ":8443",
			wantErr:         false,
		},
		{
			name:            "unknown cipher suite is rejected",
			tlsCipherSuites: []string{"TLS_UNKNOWN_CIPHER"},
			httpsAddress:    ":8443",
			wantErr:         true,
			errContains:     "invalid cipher suite",
		},
		{
			name:            "insecure cipher RC4 is rejected",
			tlsCipherSuites: []string{"TLS_RSA_WITH_RC4_128_SHA"},
			httpsAddress:    ":8443",
			wantErr:         true,
			errContains:     "insecure cipher suite",
		},
		{
			name:            "insecure cipher 3DES is rejected",
			tlsCipherSuites: []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
			httpsAddress:    ":8443",
			wantErr:         true,
			errContains:     "insecure cipher suite",
		},
		{
			name:            "mix of secure and insecure ciphers is rejected",
			tlsCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_RC4_128_SHA"},
			httpsAddress:    ":8443",
			wantErr:         true,
			errContains:     "insecure cipher suite",
		},
		{
			name:          "TLS config with HTTPS disabled",
			tlsMinVersion: "VersionTLS12",
			httpsAddress:  "", // HTTPS disabled
			wantErr:       false,
			// Note: This triggers a WARNING but doesn't fail validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start with defaults
			opts := NewOptions()
			opts.Upstreams = []string{"http://localhost:8080"}
			opts.CookieSecret = "0123456789abcdef" // 16 bytes
			opts.ClientID = "client"
			opts.ClientSecret = "secret"
			opts.EmailDomains = []string{"*"}
			opts.RedirectURL = "https:///"
			opts.TLSMinVersion = tt.tlsMinVersion
			opts.TLSCipherSuites = tt.tlsCipherSuites
			opts.HttpsAddress = tt.httpsAddress

			err := opts.Validate(&testProvider{})

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}
			}
		})
	}
}
