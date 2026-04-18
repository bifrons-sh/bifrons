package postgres

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xdg-go/scram"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
)

func TestParseStartupParams_Roundtrip(t *testing.T) {
	orig := map[string]string{
		"user":     "alice",
		"database": "orders",
	}
	pkt := buildStartupMessage(196608, orig)
	got, err := parseStartupParams(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.protocolVersion != 196608 {
		t.Errorf("version=%d want 196608", got.protocolVersion)
	}
	for k, v := range orig {
		if got.params[k] != v {
			t.Errorf("params[%q]=%q want %q", k, got.params[k], v)
		}
	}
}

func TestReadCString(t *testing.T) {
	s, rest, ok := readCString([]byte("hello\x00world\x00"))
	if !ok || s != "hello" || string(rest) != "world\x00" {
		t.Fatalf("readCString: ok=%v s=%q rest=%q", ok, s, rest)
	}
	if _, _, ok := readCString([]byte("no-null")); ok {
		t.Fatal("expected ok=false for no NUL")
	}
}

func TestMechsContain(t *testing.T) {
	buf := []byte("SCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00\x00")
	if !mechsContain(buf, "SCRAM-SHA-256") {
		t.Error("expected SCRAM-SHA-256 present")
	}
	if mechsContain(buf, "MD5") {
		t.Error("MD5 should not be present")
	}
}

func TestConstantTimeStringEq(t *testing.T) {
	if !constantTimeStringEq("abc", "abc") {
		t.Error("equal strings returned false")
	}
	if constantTimeStringEq("abc", "abd") {
		t.Error("different strings returned true")
	}
	if constantTimeStringEq("abc", "abcd") {
		t.Error("different lengths returned true")
	}
}

func TestParseSASLInitialResponse(t *testing.T) {
	body := []byte("SCRAM-SHA-256\x00")
	body = append(body, 0, 0, 0, 5)    // resp_len = 5
	body = append(body, "hello"...)
	mech, resp, err := parseSASLInitialResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if mech != "SCRAM-SHA-256" {
		t.Errorf("mech=%q", mech)
	}
	if string(resp) != "hello" {
		t.Errorf("resp=%q", resp)
	}
}

func TestFrameMessage(t *testing.T) {
	out := frameMessage('Z', []byte{'I'})
	if out[0] != 'Z' {
		t.Errorf("type byte = %q", out[0])
	}
	if l := binary.BigEndian.Uint32(out[1:5]); l != 5 {
		t.Errorf("length = %d want 5", l)
	}
	if out[5] != 'I' {
		t.Error("payload mismatch")
	}
}

// TestHandleAuth_Cleartext_FullFlow drives the cleartext client-auth path
// against a scripted backend and stub portal.
func TestHandleAuth_Cleartext_FullFlow(t *testing.T) {
	const (
		portalUser = "alice"
		portalPass = "alicepw"
		backendU   = "app_rw"
		backendP   = "backendpw"
	)

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.LookupRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Username != portalUser {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(auth.AuthResponse{
			Password: portalPass, BackendUser: backendU, BackendPass: backendP,
		})
	}))
	defer authSrv.Close()

	cfg := &config.Config{HandshakeTimeout: 5 * time.Second}
	h := NewFromConfig(slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
		auth.NewClient(authSrv.URL), nil, ClientAuthCleartext, cfg)

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	// Fake backend: receive Startup (mapped user), then run SCRAM-SHA-256 to
	// completion, then send ParameterStatus + BackendKeyData + ReadyForQuery.
	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		if err := runFakeBackendSCRAM(t, backendSrv, backendU, backendP); err != nil {
			t.Errorf("fake backend: %v", err)
		}
	}()

	// Fake client: send Startup, respond to AuthenticationCleartextPassword,
	// then expect AuthenticationOk + ParameterStatus + BackendKeyData + ReadyForQuery.
	go func() {
		defer wg.Done()
		defer clientApp.Close()
		startup := buildStartupMessage(196608, map[string]string{"user": portalUser, "database": "orders"})
		if _, err := clientApp.Write(startup); err != nil {
			t.Errorf("client write startup: %v", err)
			return
		}
		// Expect AuthenticationCleartextPassword
		msg, err := readMessage(clientApp)
		if err != nil {
			t.Errorf("client read auth req: %v", err)
			return
		}
		if msg[0] != msgAuthRequest {
			t.Errorf("got type %q want R", msg[0])
			return
		}
		if sub := binary.BigEndian.Uint32(messagePayload(msg)[0:4]); sub != authCleartextPass {
			t.Errorf("auth sub=%d want 3 (cleartext)", sub)
		}
		// Send password as NUL-terminated string in a 'p' message.
		pw := append([]byte(portalPass), 0)
		if _, err := clientApp.Write(frameMessage(msgPasswordOrSASL, pw)); err != nil {
			t.Errorf("client send password: %v", err)
			return
		}
		assertBringUpSequence(t, clientApp)
	}()

	// Handler handles startup + auth + bring-up. Read startup first because
	// handleStartup is the real entry — but we're testing handleAuth directly.
	startup, err := readStartupMessage(clientProxy)
	if err != nil {
		t.Fatalf("read startup: %v", err)
	}
	if _, err := h.handleAuth(context.Background(), clientProxy, backendProxy, startup, h.logger); err != nil {
		clientProxy.Close()
		backendProxy.Close()
		wg.Wait()
		t.Fatalf("handleAuth: %v", err)
	}
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()
}

// TestHandleAuth_SCRAM_FullFlow drives the SCRAM-SHA-256 client-auth path.
func TestHandleAuth_SCRAM_FullFlow(t *testing.T) {
	const (
		portalUser = "alice"
		portalPass = "alicepw"
		backendU   = "app_rw"
		backendP   = "backendpw"
	)

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.LookupRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Username != portalUser {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(auth.AuthResponse{
			Password: portalPass, BackendUser: backendU, BackendPass: backendP,
		})
	}))
	defer authSrv.Close()

	cfg := &config.Config{HandshakeTimeout: 5 * time.Second}
	h := NewFromConfig(slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
		auth.NewClient(authSrv.URL), nil, ClientAuthSCRAM, cfg)

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		if err := runFakeBackendSCRAM(t, backendSrv, backendU, backendP); err != nil {
			t.Errorf("fake backend: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer clientApp.Close()
		startup := buildStartupMessage(196608, map[string]string{"user": portalUser, "database": "orders"})
		if _, err := clientApp.Write(startup); err != nil {
			t.Errorf("client write startup: %v", err)
			return
		}
		if err := runFakeClientSCRAM(clientApp, portalUser, portalPass); err != nil {
			t.Errorf("fake client scram: %v", err)
			return
		}
		assertBringUpSequence(t, clientApp)
	}()

	startup, err := readStartupMessage(clientProxy)
	if err != nil {
		t.Fatalf("read startup: %v", err)
	}
	if _, err := h.handleAuth(context.Background(), clientProxy, backendProxy, startup, h.logger); err != nil {
		clientProxy.Close()
		backendProxy.Close()
		wg.Wait()
		t.Fatalf("handleAuth: %v", err)
	}
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()
}

// runFakeClientSCRAM drives the proxy's SCRAM server side from a fake client.
func runFakeClientSCRAM(conn net.Conn, user, pass string) error {
	// Expect AuthenticationSASL.
	msg, err := readMessage(conn)
	if err != nil {
		return err
	}
	if msg[0] != msgAuthRequest {
		return fmt.Errorf("want R got %q", msg[0])
	}
	if sub := binary.BigEndian.Uint32(messagePayload(msg)[0:4]); sub != authSASL {
		return fmt.Errorf("want SASL, sub=%d", sub)
	}

	cli, err := scram.SHA256.NewClient(user, pass, "")
	if err != nil {
		return err
	}
	conv := cli.NewConversation()
	clientFirst, err := conv.Step("")
	if err != nil {
		return err
	}
	if _, err := conn.Write(buildSASLInitialResponse(scramMech, []byte(clientFirst))); err != nil {
		return err
	}

	msg, err = readMessage(conn)
	if err != nil {
		return err
	}
	if sub := binary.BigEndian.Uint32(messagePayload(msg)[0:4]); sub != authSASLContinue {
		return fmt.Errorf("want SASLContinue, sub=%d", sub)
	}
	serverFirst := string(messagePayload(msg)[4:])
	clientFinal, err := conv.Step(serverFirst)
	if err != nil {
		return err
	}
	if _, err := conn.Write(buildSASLResponse([]byte(clientFinal))); err != nil {
		return err
	}

	msg, err = readMessage(conn)
	if err != nil {
		return err
	}
	if sub := binary.BigEndian.Uint32(messagePayload(msg)[0:4]); sub != authSASLFinal {
		return fmt.Errorf("want SASLFinal, sub=%d", sub)
	}
	serverFinal := string(messagePayload(msg)[4:])
	if _, err := conv.Step(serverFinal); err != nil {
		return err
	}
	return nil
}

// runFakeBackendSCRAM mimics a PG server that runs SCRAM-SHA-256 auth then
// sends ParameterStatus + BackendKeyData + ReadyForQuery.
func runFakeBackendSCRAM(t *testing.T, conn net.Conn, user, pass string) error {
	t.Helper()
	// Read startup
	if _, err := readStartupMessage(conn); err != nil {
		return err
	}

	// Send AuthenticationSASL
	mechs := append([]byte(scramMech), 0, 0)
	if _, err := conn.Write(buildAuthRequest(authSASL, mechs)); err != nil {
		return err
	}

	// Receive SASLInitialResponse
	msg, err := readMessage(conn)
	if err != nil {
		return err
	}
	if msg[0] != msgPasswordOrSASL {
		return fmt.Errorf("want p got %q", msg[0])
	}
	_, clientFirst, err := parseSASLInitialResponse(messagePayload(msg))
	if err != nil {
		return err
	}

	stored, err := auth.SCRAMStoredCredentials(pass, auth.DefaultSCRAMIters)
	if err != nil {
		return err
	}
	srv, err := scram.SHA256.NewServer(func(u string) (scram.StoredCredentials, error) {
		if u != user {
			return scram.StoredCredentials{}, fmt.Errorf("unknown user: %s", u)
		}
		return stored, nil
	})
	if err != nil {
		return err
	}
	conv := srv.NewConversation()
	serverFirst, err := conv.Step(string(clientFirst))
	if err != nil {
		return err
	}
	if _, err := conn.Write(buildAuthRequest(authSASLContinue, []byte(serverFirst))); err != nil {
		return err
	}

	// Receive SASLResponse
	msg, err = readMessage(conn)
	if err != nil {
		return err
	}
	clientFinal := messagePayload(msg)
	serverFinal, err := conv.Step(string(clientFinal))
	if err != nil {
		return err
	}
	if !conv.Valid() {
		return fmt.Errorf("backend scram invalid")
	}
	if _, err := conn.Write(buildAuthRequest(authSASLFinal, []byte(serverFinal))); err != nil {
		return err
	}

	// AuthenticationOk
	if _, err := conn.Write(buildAuthRequest(authOK, nil)); err != nil {
		return err
	}
	// ParameterStatus server_version=99.0
	ps := []byte("server_version\x0099.0\x00")
	if _, err := conn.Write(frameMessage(msgParameterStat, ps)); err != nil {
		return err
	}
	// BackendKeyData (pid + key)
	bk := make([]byte, 8)
	binary.BigEndian.PutUint32(bk[0:4], 1234)
	binary.BigEndian.PutUint32(bk[4:8], 5678)
	if _, err := conn.Write(frameMessage(msgBackendKeyData, bk)); err != nil {
		return err
	}
	// ReadyForQuery Idle
	if _, err := conn.Write(frameMessage(msgReadyForQuery, []byte{'I'})); err != nil {
		return err
	}
	return nil
}

func assertBringUpSequence(t *testing.T, conn net.Conn) {
	t.Helper()
	// AuthenticationOk
	msg, err := readMessage(conn)
	if err != nil {
		t.Errorf("read auth ok: %v", err)
		return
	}
	if msg[0] != msgAuthRequest {
		t.Errorf("type=%q want R", msg[0])
		return
	}
	if sub := binary.BigEndian.Uint32(messagePayload(msg)[0:4]); sub != authOK {
		t.Errorf("sub=%d want 0", sub)
	}
	// ParameterStatus
	msg, err = readMessage(conn)
	if err != nil {
		t.Errorf("read parameter status: %v", err)
		return
	}
	if msg[0] != msgParameterStat {
		t.Errorf("type=%q want S", msg[0])
	}
	// BackendKeyData
	msg, err = readMessage(conn)
	if err != nil {
		t.Errorf("read backend key: %v", err)
		return
	}
	if msg[0] != msgBackendKeyData {
		t.Errorf("type=%q want K", msg[0])
	}
	// ReadyForQuery
	msg, err = readMessage(conn)
	if err != nil {
		t.Errorf("read ready: %v", err)
		return
	}
	if msg[0] != msgReadyForQuery {
		t.Errorf("type=%q want Z", msg[0])
	}
}

