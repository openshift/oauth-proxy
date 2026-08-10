package main

import (
	"crypto/tls"
	"testing"
)

func TestBuildTLSConfig_Defaults(t *testing.T) {
	// Test that without TLS flags, library-go defaults are used
	opts := &Options{
		HttpsAddress: ":8443",
		// TLSMinVersion and TLSCipherSuites are empty
	}

	s := &Server{Opts: opts}
	config := s.buildTLSConfig()

	// Verify library-go defaults are applied
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected default MinVersion TLS 1.2 (%d), got %d", tls.VersionTLS12, config.MinVersion)
	}

	if len(config.CipherSuites) == 0 {
		t.Error("Expected library-go to set default cipher suites, got empty list")
	}

	if config.NextProtos == nil || len(config.NextProtos) == 0 {
		t.Error("Expected NextProtos to be set")
	}
}

func TestBuildTLSConfig_MinVersion(t *testing.T) {
	tests := []struct {
		name        string
		minVersion  string
		expected    uint16
		wantWarning bool
	}{
		{
			name:        "VersionTLS12 overrides default",
			minVersion:  "VersionTLS12",
			expected:    tls.VersionTLS12,
			wantWarning: false,
		},
		{
			name:        "VersionTLS13 overrides default",
			minVersion:  "VersionTLS13",
			expected:    tls.VersionTLS13,
			wantWarning: false,
		},
		{
			name:        "invalid version logs warning but doesn't crash",
			minVersion:  "VersionTLS99",
			expected:    tls.VersionTLS12, // Falls back to library-go default
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{
				TLSMinVersion: tt.minVersion,
			}

			s := &Server{Opts: opts}
			config := s.buildTLSConfig()

			if config.MinVersion != tt.expected {
				t.Errorf("Expected MinVersion %d, got %d", tt.expected, config.MinVersion)
			}
		})
	}
}

func TestBuildTLSConfig_CipherSuites(t *testing.T) {
	tests := []struct {
		name         string
		cipherSuites []string
		expectCount  int
		wantWarning  bool
	}{
		{
			name: "single valid cipher",
			cipherSuites: []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			},
			expectCount: 1,
			wantWarning: false,
		},
		{
			name: "multiple valid ciphers",
			cipherSuites: []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			},
			expectCount: 2,
			wantWarning: false,
		},
		{
			name: "invalid cipher logs warning and skips it",
			cipherSuites: []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_INVALID_CIPHER",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			},
			expectCount: 2, // Only valid ciphers
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{
				TLSCipherSuites: tt.cipherSuites,
			}

			s := &Server{Opts: opts}
			config := s.buildTLSConfig()

			if len(config.CipherSuites) != tt.expectCount {
				t.Errorf("Expected %d cipher suites, got %d", tt.expectCount, len(config.CipherSuites))
			}
		})
	}
}
