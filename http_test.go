package main

import (
	"crypto/tls"
	"testing"
)

func TestBuildTLSConfig_Defaults(t *testing.T) {
	s := &Server{Opts: &Options{}}
	config := s.buildTLSConfig()

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected default MinVersion TLS 1.3 (%d), got %d", tls.VersionTLS13, config.MinVersion)
	}
}

func TestBuildTLSConfig_MinVersion(t *testing.T) {
	tests := []struct {
		name       string
		minVersion string
		expected   uint16
	}{
		{
			name:       "VersionTLS12",
			minVersion: "VersionTLS12",
			expected:   tls.VersionTLS12,
		},
		{
			name:       "VersionTLS13",
			minVersion: "VersionTLS13",
			expected:   tls.VersionTLS13,
		},
		{
			name:       "unknown version keeps default",
			minVersion: "VersionTLS99",
			expected:   tls.VersionTLS13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Opts: &Options{TLSMinVersion: tt.minVersion}}
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
	}{
		{
			name:         "single valid cipher",
			cipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			expectCount:  1,
		},
		{
			name:         "multiple valid ciphers",
			cipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			expectCount:  2,
		},
		{
			name:         "unknown cipher is skipped",
			cipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_INVALID_CIPHER"},
			expectCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Opts: &Options{TLSCipherSuites: tt.cipherSuites}}
			config := s.buildTLSConfig()

			if len(config.CipherSuites) != tt.expectCount {
				t.Errorf("Expected %d cipher suites, got %d", tt.expectCount, len(config.CipherSuites))
			}
		})
	}
}
