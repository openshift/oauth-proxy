package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	oscrypto "github.com/openshift/library-go/pkg/crypto"

	"github.com/openshift/oauth-proxy/util"
)

type Server struct {
	Handler http.Handler
	Opts    *Options
}

func (s *Server) ListenAndServe(ctx context.Context) {
	if s.Opts.HttpsAddress == "" && s.Opts.HttpAddress == "" {
		log.Fatalf("FATAL: must specify https-address or http-address")
	}
	if s.Opts.HttpsAddress != "" {
		go s.ServeHTTPS(ctx)
	}
	if s.Opts.HttpAddress != "" {
		go s.ServeHTTP()
	}

	select {
	case <-ctx.Done():
	}
}

func (s *Server) ServeHTTP() {
	httpAddress := s.Opts.HttpAddress
	scheme := ""

	i := strings.Index(httpAddress, "://")
	if i > -1 {
		scheme = httpAddress[0:i]
	}

	var networkType string
	switch scheme {
	case "", "http":
		networkType = "tcp"
	default:
		networkType = scheme
	}

	slice := strings.SplitN(httpAddress, "//", 2)
	listenAddr := slice[len(slice)-1]

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s, %s) failed - %s", networkType, listenAddr, err)
	}
	log.Printf("HTTP: listening on %s", listenAddr)

	server := &http.Server{Handler: s.Handler}
	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: http.Serve() - %s", err)
	}

	log.Printf("HTTP: closing %s", listener.Addr())
}

func (s *Server) ServeHTTPS(ctx context.Context) {
	addr := s.Opts.HttpsAddress

	config := oscrypto.SecureTLSConfig(&tls.Config{})
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	servingCertProvider, err := dynamiccertificates.NewDynamicServingContentFromFiles("serving", s.Opts.TLSCertFile, s.Opts.TLSKeyFile)
	if err != nil {
		log.Fatalf("FATAL: loading tls config (%s, %s) failed - %s", s.Opts.TLSCertFile, s.Opts.TLSKeyFile, err)
	}
	go servingCertProvider.Run(ctx, 1)

	config.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// this disregards information from ClientHello but we're not doing SNI anyway
		cert, key := servingCertProvider.CurrentCertKeyContent()

		certKeyPair, err := tls.X509KeyPair(cert, key)
		return &certKeyPair, err
	}

	if len(s.Opts.TLSClientCAFile) > 0 {
		config.ClientAuth = tls.RequestClientCert
		config.ClientCAs, err = util.GetCertPool([]string{s.Opts.TLSClientCAFile}, false)
		if err != nil {
			log.Fatalf("FATAL: %s", err)
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("FATAL: listen (%s) failed - %s", addr, err)
	}
	log.Printf("HTTPS: listening on %s", ln.Addr())

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	srv := &http.Server{Handler: s.Handler}
	err = srv.Serve(tlsListener)

	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("ERROR: https.Serve() - %s", err)
	}

	log.Printf("HTTPS: closing %s", tlsListener.Addr())
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
