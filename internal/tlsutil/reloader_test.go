package tlsutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// mintLeaf returns PEM-encoded cert + key material for a fresh ECDSA leaf
// signed by its own self-signed CA. CommonName is used as a stable identity
// marker so tests can tell one generation from the next.
func mintLeaf(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn + "-ca"},
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

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = caDER // keep caDER referenced (silences future lint; we don't need the CA bytes here)
	return
}

// writeAtomic mirrors the rename-over-target pattern most cert tools use so
// fsnotify reliably fires a CREATE on the watched filename.
func writeAtomic(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// leafCN pulls the CommonName out of the current cert for identity checks.
func leafCN(t *testing.T, r *Reloader) string {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf == nil {
		// tls.LoadX509KeyPair doesn't populate Leaf by default; parse from DER.
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		return parsed.Subject.CommonName
	}
	return cert.Leaf.Subject.CommonName
}

// waitFor retries fn up to 3s — fsnotify fires asynchronously and ext4 mtime
// resolution on some kernels rounds to 1s, so we can't assume instant.
func waitFor(t *testing.T, want string, get func() string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := get(); got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q, last=%q", want, get())
}

func TestReloader_InitialLoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certPEM, keyPEM := mintLeaf(t, "v1")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := NewReloader(certPath, keyPath, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if cn := leafCN(t, r); cn != "v1" {
		t.Fatalf("initial CN = %q, want v1", cn)
	}
}

func TestReloader_HotSwap(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certV1, keyV1 := mintLeaf(t, "v1")
	writeAtomic(t, certPath, certV1)
	writeAtomic(t, keyPath, keyV1)

	var logBuf syncBuffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r, err := NewReloader(certPath, keyPath, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if cn := leafCN(t, r); cn != "v1" {
		t.Fatalf("initial CN = %q, want v1", cn)
	}

	// Rotate. Write key first so that between-file reads during reload still
	// find a consistent pair (tls.LoadX509KeyPair re-reads both).
	certV2, keyV2 := mintLeaf(t, "v2")
	writeAtomic(t, keyPath, keyV2)
	writeAtomic(t, certPath, certV2)

	waitFor(t, "v2", func() string { return leafCN(t, r) })

	if !strings.Contains(logBuf.String(), "cert_reloaded") {
		t.Errorf("expected cert_reloaded log, got: %s", logBuf.String())
	}
}

func TestReloader_MalformedKeepsOldCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certV1, keyV1 := mintLeaf(t, "v1")
	writeAtomic(t, certPath, certV1)
	writeAtomic(t, keyPath, keyV1)

	var logBuf syncBuffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r, err := NewReloader(certPath, keyPath, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Corrupt the cert file — the key stays valid so the failure isolates to parse.
	writeAtomic(t, certPath, []byte("-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----\n"))

	// Give the watcher + debounce a chance to fire.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), "cert_reload_failed") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(logBuf.String(), "cert_reload_failed") {
		t.Fatalf("expected cert_reload_failed log, got: %s", logBuf.String())
	}

	// Old cert must still be served.
	if cn := leafCN(t, r); cn != "v1" {
		t.Fatalf("after malformed reload CN = %q, want v1 (unchanged)", cn)
	}
}

func TestReloader_CAReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	caPath := filepath.Join(dir, "ca.pem")

	certV1, keyV1 := mintLeaf(t, "v1")
	writeAtomic(t, certPath, certV1)
	writeAtomic(t, keyPath, keyV1)
	// Reuse the leaf cert as a trivial "CA" — AppendCertsFromPEM accepts any PEM cert.
	writeAtomic(t, caPath, certV1)

	r, err := NewReloader(certPath, keyPath, caPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if pool := r.CAPool(); pool == nil {
		t.Fatal("CAPool nil after init")
	}
}

func TestReloader_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	c, k := mintLeaf(t, "v1")
	if err := os.WriteFile(certPath, c, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, k, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewReloader(certPath, keyPath, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Second Close must not panic or block.
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReloader_GetClientCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	c, k := mintLeaf(t, "v1")
	writeAtomic(t, certPath, c)
	writeAtomic(t, keyPath, k)

	r, err := NewReloader(certPath, keyPath, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	cert, err := r.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("empty client certificate returned")
	}
}

func TestReloader_VerifyPeerCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	c, k := mintLeaf(t, "v1")
	writeAtomic(t, certPath, c)
	writeAtomic(t, keyPath, k)
	// Use the leaf itself as the CA so VerifyPeerCertificate can trust it.
	writeAtomic(t, caPath, c)

	r, err := NewReloader(certPath, keyPath, caPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// No CA path → no-op verify (nil pool branch).
	r2, err := NewReloader(certPath, keyPath, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if err := r2.VerifyPeerCertificate(nil, nil); err != nil {
		t.Errorf("no-CA verify returned error: %v", err)
	}

	// With a configured CA, zero raw certs is an error.
	if err := r.VerifyPeerCertificate(nil, nil); err == nil {
		t.Error("expected error when no peer cert presented")
	}

	// Verify against a valid leaf — decode our PEM back to DER.
	block, _ := pem.Decode(c)
	if block == nil {
		t.Fatal("cannot decode cert PEM")
	}
	if err := r.VerifyPeerCertificate([][]byte{block.Bytes}, nil); err != nil {
		t.Errorf("verify valid cert: %v", err)
	}

	// Malformed DER must fail cleanly.
	if err := r.VerifyPeerCertificate([][]byte{[]byte("not-a-der-cert")}, nil); err == nil {
		t.Error("expected parse error on malformed DER")
	}
}

func TestReloader_PollFallback(t *testing.T) {
	// Force the poll path and tighten the interval so the test runs fast.
	prevForce, prevInterval := forcePollFallback, pollInterval
	forcePollFallback = true
	pollInterval = 100 * time.Millisecond
	t.Cleanup(func() {
		forcePollFallback = prevForce
		pollInterval = prevInterval
	})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	c1, k1 := mintLeaf(t, "v1")
	writeAtomic(t, certPath, c1)
	writeAtomic(t, keyPath, k1)

	// Backdate the initial mtime so the post-write stamp is guaranteed newer
	// on coarse-resolution filesystems. 2s > typical 1s ext4 granularity.
	past := time.Now().Add(-2 * time.Second)
	if err := os.Chtimes(certPath, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, past, past); err != nil {
		t.Fatal(err)
	}

	r, err := NewReloader(certPath, keyPath, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	c2, k2 := mintLeaf(t, "v2")
	writeAtomic(t, keyPath, k2)
	writeAtomic(t, certPath, c2)
	// Bump mtime explicitly in case writeAtomic lands in the same second.
	now := time.Now()
	_ = os.Chtimes(certPath, now, now)
	_ = os.Chtimes(keyPath, now, now)

	waitFor(t, "v2", func() string { return leafCN(t, r) })
}

func TestReloader_InvalidArgs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewReloader("", "", "", logger); err == nil {
		t.Error("expected error with all empty paths")
	}
	if _, err := NewReloader("cert", "", "", logger); err == nil {
		t.Error("expected error with cert but no key")
	}
	if _, err := NewReloader("/no/such/cert", "/no/such/key", "", logger); err == nil {
		t.Error("expected error when files do not exist")
	}
}

// syncBuffer is a bytes.Buffer wrapped for concurrent Write/Read. The watcher
// goroutine logs concurrently with the test, so an unsynchronised buffer
// would trip -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
