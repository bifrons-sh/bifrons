package mysql

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	mysqlauth "github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
)

// TestParseInitialHandshake_Roundtrip ensures buildInitialHandshake produces a
// packet that parseInitialHandshake can decode back into the same salt + connID.
func TestParseInitialHandshake_Roundtrip(t *testing.T) {
	salt, err := mysqlauth.NewMySQLSalt()
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := buildInitialHandshake(salt, 4242)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	info, err := parseInitialHandshake(packetPayload(pkt))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if info.connID != 4242 {
		t.Errorf("connID=%d want 4242", info.connID)
	}
	if !bytes.Equal(info.salt, salt) {
		t.Errorf("salt round-trip mismatch:\n got: %x\nwant: %x", info.salt, salt)
	}
}

// TestParseHandshakeResponse41_Roundtrip exercises the secure-connection path
// (1-byte length-prefixed scramble) which is what the proxy advertises.
func TestParseHandshakeResponse41_Roundtrip(t *testing.T) {
	authResp := bytes.Repeat([]byte{0xAB}, mysqlauth.MySQLNativeAuthLen)
	pkt := buildHandshakeResponse41("alice", authResp, "orders")

	got, err := parseHandshakeResponse41(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.username != "alice" {
		t.Errorf("username=%q want alice", got.username)
	}
	if got.database != "orders" {
		t.Errorf("database=%q want orders", got.database)
	}
	if !bytes.Equal(got.authResponse, authResp) {
		t.Errorf("authResponse mismatch")
	}
	if got.authPlugin != mysqlNativePassword {
		t.Errorf("authPlugin=%q want %q", got.authPlugin, mysqlNativePassword)
	}
}

func TestReadLenEncInt(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		used int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0xFC, 0x01, 0x01}, 257, 3},
		{[]byte{0xFD, 0x00, 0x00, 0x01}, 65536, 4},
		{[]byte{0xFE, 1, 0, 0, 0, 0, 0, 0, 0}, 1, 9},
	}
	for _, tc := range cases {
		got, used, err := readLenEncInt(tc.in)
		if err != nil {
			t.Fatalf("readLenEncInt(%x): %v", tc.in, err)
		}
		if got != tc.want || used != tc.used {
			t.Errorf("readLenEncInt(%x)=(%d,%d) want (%d,%d)", tc.in, got, used, tc.want, tc.used)
		}
	}
}

// TestHandleAuth_FullFlow exercises the entire handshake: stub HTTP auth
// server + scripted backend that mimics MySQL initial handshake / OK + scripted
// client that mimics a real driver. End state: client receives an OK packet
// and h.handleAuth returns nil.
func TestHandleAuth_FullFlow(t *testing.T) {
	const (
		portalUser = "alice"
		portalPass = "alicepw"
		backendU   = "app_rw"
		backendP   = "backendpw"
	)

	// Stub auth API.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mysqlauth.LookupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Username != portalUser {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(mysqlauth.AuthResponse{
			Password:    portalPass,
			BackendUser: backendU,
			BackendPass: backendP,
		})
	}))
	defer authSrv.Close()

	cfg := &config.Config{BackendAddr: "127.0.0.1:3306", HandshakeTimeout: 5 * time.Second}
	h := NewFromConfig(slog.New(slog.NewTextHandler(io.Discard, nil)),
		mysqlauth.NewClient(authSrv.URL),
		nil, // no audit shipping in this unit test
		cfg,
	)

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	// Backend role: send Initial Handshake with a known salt, expect HandshakeResponse41,
	// validate that the auth response matches what the proxy *should* compute, then send OK.
	backendSalt, err := mysqlauth.NewMySQLSalt()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		greet, err := buildInitialHandshake(backendSalt, 99)
		if err != nil {
			t.Errorf("build backend handshake: %v", err)
			return
		}
		if err := writePacket(backendSrv, greet); err != nil {
			t.Errorf("backend send handshake: %v", err)
			return
		}
		respPkt, err := readPacket(backendSrv)
		if err != nil {
			t.Errorf("backend read response: %v", err)
			return
		}
		resp, err := parseHandshakeResponse41(packetPayload(respPkt))
		if err != nil {
			t.Errorf("backend parse: %v", err)
			return
		}
		if resp.username != backendU {
			t.Errorf("backend got user %q want %q", resp.username, backendU)
		}
		expected, _ := mysqlauth.MySQLNativeAuthResponse(backendP, backendSalt)
		if !bytes.Equal(resp.authResponse, expected) {
			t.Errorf("backend auth response mismatch")
		}
		// Send OK.
		if err := writePacket(backendSrv, buildOKPacket(2)); err != nil {
			t.Errorf("backend send OK: %v", err)
		}
	}()

	// Client role: read Initial Handshake from proxy, send HandshakeResponse41
	// with the correct scramble for portalPass + proxy salt, then read OK.
	go func() {
		defer wg.Done()
		defer clientApp.Close()
		hs, err := readPacket(clientApp)
		if err != nil {
			t.Errorf("client read handshake: %v", err)
			return
		}
		info, err := parseInitialHandshake(packetPayload(hs))
		if err != nil {
			t.Errorf("client parse handshake: %v", err)
			return
		}
		scramble, _ := mysqlauth.MySQLNativeAuthResponse(portalPass, info.salt)
		hr := buildHandshakeResponse41(portalUser, scramble, "")
		if err := writePacket(clientApp, makePacketRaw(1, hr)); err != nil {
			t.Errorf("client send response: %v", err)
			return
		}
		okPkt, err := readPacket(clientApp)
		if err != nil {
			t.Errorf("client read OK: %v", err)
			return
		}
		if packetPayload(okPkt)[0] != pktHdrOK {
			t.Errorf("client got 0x%02x want OK", packetPayload(okPkt)[0])
		}
	}()

	_, err = h.handleAuth(context.Background(), clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()
	if err != nil {
		t.Fatalf("handleAuth: %v", err)
	}
}

// TestHandleAuth_DeniedByPortal verifies that a 403 from the auth API surfaces
// as an error and an ERR packet to the client.
func TestHandleAuth_DeniedByPortal(t *testing.T) {
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer authSrv.Close()

	cfg := &config.Config{HandshakeTimeout: 5 * time.Second}
	h := NewFromConfig(slog.New(slog.NewTextHandler(io.Discard, nil)),
		mysqlauth.NewClient(authSrv.URL),
		nil, // no audit shipping in this unit test
		cfg,
	)

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		greet, err := buildInitialHandshake(bytes.Repeat([]byte{'A'}, 20), 1)
		if err != nil {
			t.Errorf("build handshake: %v", err)
			return
		}
		_ = writePacket(backendSrv, greet)
	}()

	go func() {
		defer wg.Done()
		defer clientApp.Close()
		hs, _ := readPacket(clientApp)
		info, _ := parseInitialHandshake(packetPayload(hs))
		scramble, _ := mysqlauth.MySQLNativeAuthResponse("anything", info.salt)
		hr := buildHandshakeResponse41("alice", scramble, "")
		_ = writePacket(clientApp, makePacketRaw(1, hr))
		errPkt, err := readPacket(clientApp)
		if err != nil {
			t.Errorf("client read err packet: %v", err)
			return
		}
		if packetPayload(errPkt)[0] != pktHdrErr {
			t.Errorf("client expected ERR, got 0x%02x", packetPayload(errPkt)[0])
		}
	}()

	_, err := h.handleAuth(context.Background(), clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
