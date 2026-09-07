package main

import (
	"crypto/tls"
	"testing"
)

func TestBuildTLSConfig_Defaults(t *testing.T) {
	s := &Server{Opts: &Options{tlsMinVersionValue: tls.VersionTLS13}}
	config := s.buildTLSConfig()

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected default MinVersion TLS 1.3 (%d), got %d", tls.VersionTLS13, config.MinVersion)
	}
}

func TestBuildTLSConfig_MinVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  uint16
		expected uint16
	}{
		{"TLS 1.2", tls.VersionTLS12, tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13, tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Opts: &Options{tlsMinVersionValue: tt.version}}
			config := s.buildTLSConfig()

			if config.MinVersion != tt.expected {
				t.Errorf("Expected MinVersion %d, got %d", tt.expected, config.MinVersion)
			}
		})
	}
}

func TestBuildTLSConfig_CipherSuites(t *testing.T) {
	tests := []struct {
		name        string
		suiteIDs    []uint16
		expectCount int
	}{
		{
			name:        "single cipher",
			suiteIDs:    []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			expectCount: 1,
		},
		{
			name:        "multiple ciphers",
			suiteIDs:    []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
			expectCount: 2,
		},
		{
			name:        "no ciphers uses default",
			suiteIDs:    nil,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Opts: &Options{
				tlsMinVersionValue: tls.VersionTLS13,
				tlsCipherSuiteIDs:  tt.suiteIDs,
			}}
			config := s.buildTLSConfig()

			if len(config.CipherSuites) != tt.expectCount {
				t.Errorf("Expected %d cipher suites, got %d", tt.expectCount, len(config.CipherSuites))
			}
		})
	}
}
