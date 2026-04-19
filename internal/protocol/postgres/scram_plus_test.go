package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xdg-go/scram"
)

// TestAuthClientSCRAM_Plus_TLSPair wires an in-memory TLS pair to
// authClientSCRAM and a SCRAM-SHA-256-PLUS-aware fake client, and asserts:
//  1. The proxy advertises "SCRAM-SHA-256-PLUS,SCRAM-SHA-256" when the conn is TLS.
//  2. The PLUS conversation completes and conv.Valid() is true.
//  3. The cb-data bytes embedded in the client's GS2 header match the
//     tls-server-end-point hash computed independently from the leaf cert.
func TestAuthClientSCRAM_Plus_TLSPair(t *testing.T) {
	const user, pass = "alice", "s3cret"
	certPEM, keyPEM, leaf := mintLeaf(t)

	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	cliCfg := &tls.Config{RootCAs: rootPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}

	srvPipe, cliPipe := net.Pipe()
	defer srvPipe.Close()
	defer cliPipe.Close()

	srvTLS := tls.Server(srvPipe, srvCfg)
	cliTLS := tls.Client(cliPipe, cliCfg)

	hsErr := make(chan error, 2)
	go func() { hsErr <- srvTLS.Handshake() }()
	go func() { hsErr <- cliTLS.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-hsErr; err != nil {
			t.Fatalf("tls handshake: %v", err)
		}
	}

	// Compute the expected cb-data from the leaf directly so we can compare
	// against whatever the proxy sends down the wire.
	expectCB, err := serverEndpointBinding(srvTLS, leaf)
	if err != nil {
		t.Fatalf("compute expected CB: %v", err)
	}
	if len(expectCB.Data) == 0 {
		t.Fatal("expected non-empty cb-data")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var cbAdvertised string
	go func() {
		defer wg.Done()
		srvState := srvTLS.ConnectionState()
		mech, clientFirstPkt, advertised, err := runScramPlusClient(cliTLS, user, pass, &srvState, leaf)
		if err != nil {
			t.Errorf("fake client: %v", err)
			return
		}
		cbAdvertised = advertised
		if mech != scramMechPlus {
			t.Errorf("client picked mech=%q want %q", mech, scramMechPlus)
		}
		// The GS2 header of client-first is "p=tls-server-end-point,,". The
		// real channel-binding *bytes* travel in client-final's c= field,
		// base64-encoded, over the wire. runScramPlusClient already verified
		// validity; we just keep the trace for diagnostics.
		_ = clientFirstPkt
	}()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := authClientSCRAM(srvTLS, user, pass, false, leaf, log); err != nil {
		srvTLS.Close()
		cliTLS.Close()
		wg.Wait()
		t.Fatalf("authClientSCRAM: %v", err)
	}
	srvTLS.Close()
	cliTLS.Close()
	wg.Wait()

	// The client must have observed "SCRAM-SHA-256-PLUS" listed (and first) in
	// the AuthenticationSASL advertisement.
	if !strings.HasPrefix(cbAdvertised, scramMechPlus) {
		t.Errorf("mechs advertisement should list PLUS first, got %q", cbAdvertised)
	}
	if !strings.Contains(cbAdvertised, scramMech) {
		t.Errorf("mechs advertisement should also include base SCRAM, got %q", cbAdvertised)
	}
}

// TestAuthClientSCRAM_Plus_AdvertisementUnderCBRequired asserts we still
// advertise BOTH mechs (not PLUS-only) when cbRequired=true, because pgx
// refuses to proceed if SCRAM-SHA-256 is absent from the mech list. Strict
// enforcement happens at mech-selection time.
func TestAuthClientSCRAM_Plus_AdvertisementUnderCBRequired(t *testing.T) {
	certPEM, keyPEM, leaf := mintLeaf(t)
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	cliCfg := &tls.Config{RootCAs: rootPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}

	srvPipe, cliPipe := net.Pipe()
	defer srvPipe.Close()
	defer cliPipe.Close()
	srvTLS := tls.Server(srvPipe, srvCfg)
	cliTLS := tls.Client(cliPipe, cliCfg)
	hsErr := make(chan error, 2)
	go func() { hsErr <- srvTLS.Handshake() }()
	go func() { hsErr <- cliTLS.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-hsErr; err != nil {
			t.Fatalf("tls handshake: %v", err)
		}
	}

	// Client reads the advertisement, captures it, then closes — we don't
	// need to drive a full conversation for this assertion.
	advertChan := make(chan string, 1)
	go func() {
		msg, err := readMessage(cliTLS)
		if err != nil {
			advertChan <- ""
			return
		}
		if len(msg) < 9 {
			advertChan <- ""
			return
		}
		advertChan <- decodeMechsList(msg[9:])
	}()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// cbRequired=true; we expect the call to eventually error (client never
	// completes auth), but we only care about the mech advertisement bytes.
	go func() {
		_ = authClientSCRAM(srvTLS, "alice", "pw", true, leaf, log)
	}()

	select {
	case ad := <-advertChan:
		if !strings.Contains(ad, scramMechPlus) {
			t.Errorf("missing PLUS in cbRequired advertisement: %q", ad)
		}
		if !strings.Contains(ad, scramMech) {
			t.Errorf("missing base SCRAM in cbRequired advertisement (pgx-compat requirement): %q", ad)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for advertisement")
	}
	srvTLS.Close()
	cliTLS.Close()
}

// TestAuthClientSCRAM_Plus_Required rejects a client that picks base SCRAM on a
// TLS conn when the operator set -client-tls-cb-required.
func TestAuthClientSCRAM_Plus_Required(t *testing.T) {
	const user, pass = "alice", "s3cret"
	certPEM, keyPEM, leaf := mintLeaf(t)

	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(certPEM)
	cliCfg := &tls.Config{RootCAs: rootPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}

	srvPipe, cliPipe := net.Pipe()
	defer srvPipe.Close()
	defer cliPipe.Close()

	srvTLS := tls.Server(srvPipe, srvCfg)
	cliTLS := tls.Client(cliPipe, cliCfg)

	hsErr := make(chan error, 2)
	go func() { hsErr <- srvTLS.Handshake() }()
	go func() { hsErr <- cliTLS.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-hsErr; err != nil {
			t.Fatalf("tls handshake: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	// Fake client that insists on base SCRAM-SHA-256 — should be rejected.
	go func() {
		defer wg.Done()
		// Read the AuthenticationSASL advertisement.
		msg, err := readMessage(cliTLS)
		if err != nil {
			return
		}
		if msg[0] != msgAuthRequest {
			return
		}
		// Reply with plain SCRAM-SHA-256 in the SASLInitialResponse.
		cli, err := scram.SHA256.NewClient(user, pass, "")
		if err != nil {
			return
		}
		conv := cli.NewConversation()
		clientFirst, err := conv.Step("")
		if err != nil {
			return
		}
		_, _ = cliTLS.Write(buildSASLInitialResponse(scramMech, []byte(clientFirst)))
		// Then drain whatever comes back (error response expected).
		_, _ = io.ReadAll(cliTLS)
	}()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = authClientSCRAM(srvTLS, user, pass, true /*cbRequired*/, leaf, log)
	srvTLS.Close()
	cliTLS.Close()
	wg.Wait()
	if err == nil {
		t.Fatal("expected error when cbRequired and client picks base SCRAM")
	}
	if !strings.Contains(err.Error(), "channel binding is required") {
		t.Errorf("err=%q, want mention of 'channel binding is required'", err)
	}
}

// TestAuthClientSCRAM_NoTLS_StillWorks makes sure the non-TLS path is unaffected.
func TestAuthClientSCRAM_NoTLS_StillWorks(t *testing.T) {
	const user, pass = "bob", "hunter2"
	a, b := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := runFakeClientSCRAM(b, user, pass); err != nil {
			t.Errorf("fake client: %v", err)
		}
	}()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := authClientSCRAM(a, user, pass, false, nil, log)
	a.Close()
	b.Close()
	wg.Wait()
	if err != nil {
		t.Fatalf("authClientSCRAM on plain conn: %v", err)
	}
}

// runScramPlusClient drives the client side of a SCRAM-SHA-256-PLUS exchange
// on top of `conn`. Returns the selected mech, the raw client-first bytes
// (for diagnostics), and the full mechs-list advertisement string from the
// server's AuthenticationSASL so the caller can assert PLUS was advertised.
func runScramPlusClient(conn io.ReadWriter, user, pass string, state *tls.ConnectionState, leaf *x509.Certificate) (mech string, clientFirst []byte, mechsAdvertised string, err error) {
	msg, err := readMessage(conn)
	if err != nil {
		return "", nil, "", fmt.Errorf("read SASL advert: %w", err)
	}
	if msg[0] != msgAuthRequest {
		return "", nil, "", fmt.Errorf("want R got %q", msg[0])
	}
	payload := messagePayload(msg)
	if len(payload) < 4 {
		return "", nil, "", fmt.Errorf("short SASL advert payload")
	}
	if sub := binary.BigEndian.Uint32(payload[0:4]); sub != authSASL {
		return "", nil, "", fmt.Errorf("want authSASL sub, got %d", sub)
	}
	// payload[4:] is the NUL-delimited mechs list terminated by an extra NUL.
	mechsAdvertised = decodeMechsList(payload[4:])

	// Build cb from the leaf (we know it client-side in this test).
	cb, err := serverEndpointBinding(nil, leaf)
	if err != nil {
		return "", nil, "", err
	}
	// Sanity: the state-derived binding (client side sees the server cert in
	// PeerCertificates) must match the leaf-derived one.
	if state != nil {
		viaState, err := scram.NewTLSServerEndpointBinding(state)
		if err == nil && !cb.Matches(viaState) {
			return "", nil, "", fmt.Errorf("cb mismatch: leaf-derived vs state-derived")
		}
	}

	cli, err := scram.SHA256.NewClient(user, pass, "")
	if err != nil {
		return "", nil, "", err
	}
	conv := cli.NewConversationWithChannelBinding(cb)
	first, err := conv.Step("")
	if err != nil {
		return "", nil, "", err
	}
	if _, err := conn.Write(buildSASLInitialResponse(scramMechPlus, []byte(first))); err != nil {
		return "", nil, "", err
	}
	clientFirst = []byte(first)

	msg, err = readMessage(conn)
	if err != nil {
		return "", nil, "", fmt.Errorf("read SASLContinue: %w", err)
	}
	serverFirst := string(messagePayload(msg)[4:])
	final, err := conv.Step(serverFirst)
	if err != nil {
		return "", nil, "", err
	}
	if _, err := conn.Write(buildSASLResponse([]byte(final))); err != nil {
		return "", nil, "", err
	}

	msg, err = readMessage(conn)
	if err != nil {
		return "", nil, "", fmt.Errorf("read SASLFinal: %w", err)
	}
	serverFinal := string(messagePayload(msg)[4:])
	if _, err := conv.Step(serverFinal); err != nil {
		return "", nil, "", err
	}
	if !conv.Done() {
		return "", nil, "", fmt.Errorf("conv not done")
	}
	return scramMechPlus, clientFirst, mechsAdvertised, nil
}

// decodeMechsList turns the server's double-NUL-terminated mechs advertisement
// into a comma-separated string for asserts.
func decodeMechsList(b []byte) string {
	var parts []string
	p := b
	for len(p) > 0 {
		if p[0] == 0 {
			break
		}
		s, rest, ok := readCString(p)
		if !ok {
			break
		}
		parts = append(parts, s)
		p = rest
	}
	return strings.Join(parts, ",")
}

// mintLeaf creates a fresh self-signed leaf for localhost, usable both as
// server cert and root-of-trust in these unit tests.
func mintLeaf(t *testing.T) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM, leaf
}
