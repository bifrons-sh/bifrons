package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
)

// ListenerTLSConfig returns a server-side TLS config for the proxy listener.
// If caFile is non-empty, client certs are verified against it. If required is true,
// the listener will fail the handshake when the client does not present a valid cert.
//
// A background file-watch Reloader is attached so the keypair can be hot-
// swapped without restarting the listener. Existing TLS sessions keep the
// cert they handshook with; the swap takes effect on the next handshake.
// The reloader leaks by design — it lives for the process lifetime.
func ListenerTLSConfig(certFile, keyFile, caFile string, required bool) (*tls.Config, error) {
	cfg, _, err := buildListenerTLSConfig(certFile, keyFile, caFile, required, slog.Default())
	return cfg, err
}

// buildListenerTLSConfig is the testable form that also returns the Reloader
// so tests can Close it. Production callers rely on process-lifetime leak.
func buildListenerTLSConfig(certFile, keyFile, caFile string, required bool, logger *slog.Logger) (*tls.Config, *Reloader, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load listener cert: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	reloader, err := NewReloader(certFile, keyFile, caFile, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("start cert reloader: %w", err)
	}
	// GetCertificate is consulted on every handshake and hot-reloads on
	// cert-file change, so it takes precedence over a static Certificates slot.
	cfg.GetCertificate = reloader.GetCertificate

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			_ = reloader.Close()
			return nil, nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			_ = reloader.Close()
			return nil, nil, fmt.Errorf("no valid certificates in %s", caFile)
		}
		cfg.ClientCAs = pool
		if required {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return cfg, reloader, nil
}

// DialerTLSConfig returns a client-side TLS config for connecting to the backend.
//
// When a client keypair is configured, a background Reloader hot-swaps it on
// disk changes. New dials pick up the new material immediately; existing
// connections keep their current session.
func DialerTLSConfig(caFile, certFile, keyFile string, insecure bool) (*tls.Config, error) {
	cfg, _, err := buildDialerTLSConfig(caFile, certFile, keyFile, insecure, slog.Default())
	return cfg, err
}

func buildDialerTLSConfig(caFile, certFile, keyFile string, insecure bool, logger *slog.Logger) (*tls.Config, *Reloader, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // user-controlled flag for dev/test
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("no valid certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load backend client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}

		reloader, err := NewReloader(certFile, keyFile, "", logger)
		if err != nil {
			return nil, nil, fmt.Errorf("start cert reloader: %w", err)
		}
		cfg.GetClientCertificate = reloader.GetClientCertificate
		return cfg, reloader, nil
	}

	return cfg, nil, nil
}
