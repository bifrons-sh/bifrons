package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mustCerts mints a throwaway CA + leaf into t.TempDir() and returns paths.
func mustCerts(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)

	caPath = filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)
	certPath = filepath.Join(dir, "cert.pem")
	writePEM(t, certPath, "CERTIFICATE", leafDER)

	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPath = filepath.Join(dir, "key.pem")
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	return
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

func TestListenerTLSConfig_Success(t *testing.T) {
	ca, cert, key := mustCerts(t)

	cfg, err := ListenerTLSConfig(cert, key, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 cert")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth without CA = %v, want NoClientCert", cfg.ClientAuth)
	}

	// With CA + required
	cfg, err = ListenerTLSConfig(cert, key, ca, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("required mTLS ClientAuth = %v", cfg.ClientAuth)
	}

	// With CA + optional
	cfg, err = ListenerTLSConfig(cert, key, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("optional mTLS ClientAuth = %v", cfg.ClientAuth)
	}
}

func TestListenerTLSConfig_Errors(t *testing.T) {
	_, cert, key := mustCerts(t)

	if _, err := ListenerTLSConfig("/no/such/cert", "/no/such/key", "", false); err == nil {
		t.Error("expected error for missing cert")
	}
	if _, err := ListenerTLSConfig(cert, key, "/no/such/ca", false); err == nil {
		t.Error("expected error for missing CA")
	}

	badCA := filepath.Join(t.TempDir(), "notpem.pem")
	_ = os.WriteFile(badCA, []byte("not pem data"), 0o644)
	if _, err := ListenerTLSConfig(cert, key, badCA, false); err == nil {
		t.Error("expected error for invalid CA PEM")
	}
}

func TestDialerTLSConfig(t *testing.T) {
	ca, cert, key := mustCerts(t)

	cfg, err := DialerTLSConfig(ca, cert, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs not set")
	}
	if len(cfg.Certificates) != 1 {
		t.Error("expected backend mTLS cert")
	}

	// Insecure skip
	cfg, err = DialerTLSConfig("", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not set")
	}
}

func TestDialerTLSConfig_Errors(t *testing.T) {
	if _, err := DialerTLSConfig("/no/such/ca", "", "", false); err == nil {
		t.Error("expected CA error")
	}
	_, cert, _ := mustCerts(t)
	if _, err := DialerTLSConfig("", cert, "/no/such/key", false); err == nil {
		t.Error("expected key error")
	}
	badCA := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(badCA, []byte("junk"), 0o644)
	if _, err := DialerTLSConfig(badCA, "", "", false); err == nil {
		t.Error("expected bad-PEM error")
	}
}
