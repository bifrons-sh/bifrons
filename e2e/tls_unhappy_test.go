//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/babs/poc-proxies/internal/config"
	mysqlproto "github.com/babs/poc-proxies/internal/protocol/mysql"
	"github.com/babs/poc-proxies/internal/proxy"
)

// certPaths holds paths to CA cert, server cert, server key written under t.TempDir().
type certPaths struct {
	CACert     string
	ServerCert string
	ServerKey  string
}

// genCerts mints an ECDSA CA + server leaf valid for 1 hour, signing for 127.0.0.1/localhost.
// Returns paths of PEM files usable by tlsutil.ListenerTLSConfig.
func genCerts(t *testing.T) certPaths {
	t.Helper()
	dir := t.TempDir()

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Leaf
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)

	serverCertPath := filepath.Join(dir, "server.pem")
	writePEM(t, serverCertPath, "CERTIFICATE", leafDER)

	serverKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyPath := filepath.Join(dir, "server.key")
	writePEM(t, serverKeyPath, "EC PRIVATE KEY", serverKeyDER)

	return certPaths{CACert: caPath, ServerCert: serverCertPath, ServerKey: serverKeyPath}
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// TestBackendTLS_PlaintextBackendRejected verifies the proxy dial path cleanly
// errors when the backend does not speak TLS but backend-tls is enabled.
func TestBackendTLS_PlaintextBackendRejected(t *testing.T) {
	certs := genCerts(t)

	// Plain TCP "backend" that reads+discards — no TLS.
	plainBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plainBackend.Close()
	go func() {
		for {
			c, err := plainBackend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:         "127.0.0.1:0",
		BackendAddr:        plainBackend.Addr().String(),
		BackendTLSEnabled:  true,
		BackendCACertFile:  certs.CACert,
		HandshakeTimeout:   2 * time.Second,
		BackendDialTimeout: 2 * time.Second,
	}
	srv, err := proxy.New(cfg, mysqlproto.NewFromConfig(logger, nil, nil, cfg), logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Client dial succeeds (TCP), but proxy's backend handshake fails → proxy closes us.
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 128)
	n, _ := c.Read(buf)
	_ = c.Close()
	if n > 0 {
		t.Fatalf("expected no data from proxy, got %d bytes: %x", n, buf[:n])
	}

	time.Sleep(100 * time.Millisecond)
	logs := logBuf.String()
	if !strings.Contains(logs, "dial backend") {
		t.Errorf("proxy should log backend dial failure, got: %s", logs)
	}
}

// TestClientTLS_RequiredCert_RejectsUnauthClient configures the proxy to require mTLS
// and verifies a client without a cert is rejected at TLS handshake.
func TestClientTLS_RequiredCert_RejectsUnauthClient(t *testing.T) {
	certs := genCerts(t)

	// Start a plain backend that never gets reached.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	cfg := &config.Config{
		ListenAddr:        "127.0.0.1:0",
		BackendAddr:       backend.Addr().String(),
		ClientTLSEnabled:  true,
		ClientCertFile:    certs.ServerCert,
		ClientKeyFile:     certs.ServerKey,
		ClientCACertFile:  certs.CACert,
		ClientTLSRequired: true,
		HandshakeTimeout:  2 * time.Second,
	}
	srv, err := proxy.New(cfg, mysqlproto.NewFromConfig(logger, nil, nil, cfg), logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	// Connect without presenting a client cert — must fail.
	tlsCfg := &tls.Config{ServerName: "localhost", InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", srv.Addr().String(), tlsCfg)
	if err == nil {
		defer conn.Close()
		// Handshake may succeed lazily; force it.
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		_, err = conn.Read(buf)
	}
	if err == nil {
		t.Fatal("expected TLS handshake/read failure when no client cert supplied")
	}
	// Reject manifests as either a TLS alert (certificate/bad_certificate/required) or
	// an RST from the kernel after the server aborts — both indicate refused access.
}

// Unused stubs to pacify import reset logic if sql is not used.
var _ = sql.Drivers
var _ = fmt.Sprintf
