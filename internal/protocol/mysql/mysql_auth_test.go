package mysql

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
)

// fakeServer plays a canned server script against a net.Pipe endpoint.
type fakeServer struct {
	conn net.Conn
	t    *testing.T
}

func (f *fakeServer) send(pkt []byte) {
	f.t.Helper()
	if _, err := f.conn.Write(pkt); err != nil {
		f.t.Fatalf("server write: %v", err)
	}
}

func (f *fakeServer) recv() []byte {
	f.t.Helper()
	pkt, err := readPacket(f.conn)
	if err != nil {
		f.t.Fatalf("server read: %v", err)
	}
	return pkt
}

// TestRelayHandshake_CachingSha2FastAuthOK asserts that after server sends
// AuthMoreData {0x01,0x03} the proxy does NOT read from client and correctly
// forwards the subsequent OK packet.
func TestRelayHandshake_CachingSha2FastAuthOK(t *testing.T) {
	h := NewHandler(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	// Client script: expect server handshake, reply with auth, then expect final OK.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer clientApp.Close()
		// read server handshake
		if _, err := readPacket(clientApp); err != nil {
			t.Errorf("client read handshake: %v", err)
			return
		}
		// send auth response
		if _, err := clientApp.Write(makePacket(1, []byte{0x01, 0x02, 0x03})); err != nil {
			t.Errorf("client write auth: %v", err)
			return
		}
		// read AuthMoreData {0x01,0x03}
		if _, err := readPacket(clientApp); err != nil {
			t.Errorf("client read AuthMoreData: %v", err)
			return
		}
		// read OK packet
		okPkt, err := readPacket(clientApp)
		if err != nil {
			t.Errorf("client read OK: %v", err)
			return
		}
		if packetPayload(okPkt)[0] != 0x00 {
			t.Errorf("expected OK, got 0x%02x", packetPayload(okPkt)[0])
		}
	}()

	// Server script
	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		srv := &fakeServer{conn: backendSrv, t: t}
		srv.send(makePacket(0, []byte{0x0a, 'v', '8', 0}))      // handshake
		_ = srv.recv()                                           // client auth
		srv.send(makePacket(2, []byte{0x01, cachingSha2FastAuthOK})) // AuthMoreData fast_auth_ok
		srv.send(makePacket(3, []byte{0x00}))                    // OK
	}()

	err := h.relayHandshake(clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("relayHandshake failed: %v", err)
	}
}

// TestRelayHandshake_CachingSha2FullAuth asserts the full-auth sub-flow:
// server sends {0x01,0x04}; client then exchanges pubkey+password; server ends with OK.
func TestRelayHandshake_CachingSha2FullAuth(t *testing.T) {
	h := NewHandler(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer clientApp.Close()
		_, _ = readPacket(clientApp)                                       // handshake
		_, _ = clientApp.Write(makePacket(1, []byte{0x11, 0x22}))          // auth
		_, _ = readPacket(clientApp)                                       // AuthMoreData full_auth_req
		_, _ = clientApp.Write(makePacket(3, []byte{0x02}))                // pubkey request
		_, _ = readPacket(clientApp)                                       // pubkey
		_, _ = clientApp.Write(makePacket(5, []byte{0xaa, 0xbb, 0xcc}))    // encrypted password
		_, _ = readPacket(clientApp)                                       // OK
	}()

	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		srv := &fakeServer{conn: backendSrv, t: t}
		srv.send(makePacket(0, []byte{0x0a}))                       // handshake
		_ = srv.recv()                                               // client auth
		srv.send(makePacket(2, []byte{0x01, cachingSha2FullAuthReq})) // AuthMoreData full_auth_req
		_ = srv.recv()                                               // pubkey request
		srv.send(makePacket(4, []byte{0x01, 'p', 'u', 'b'}))        // pubkey
		_ = srv.recv()                                               // encrypted password
		srv.send(makePacket(6, []byte{0x00}))                        // OK
	}()

	err := h.relayHandshake(clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("relayHandshake failed: %v", err)
	}
}

// TestRelayHandshake_ErrorPacket propagates ERR from server.
func TestRelayHandshake_ErrorPacket(t *testing.T) {
	h := NewHandler(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	go func() {
		defer clientApp.Close()
		_, _ = readPacket(clientApp)
		_, _ = clientApp.Write(makePacket(1, []byte{0x01}))
		// drain
		buf := make([]byte, 4096)
		_, _ = clientApp.Read(buf)
	}()
	go func() {
		defer backendSrv.Close()
		_, _ = backendSrv.Write(makePacket(0, []byte{0x0a}))
		_, _ = readPacket(backendSrv)
		_, _ = backendSrv.Write(makePacket(2, []byte{0xFF, 0x28, 0x00, 'b', 'a', 'd'}))
	}()

	err := h.relayHandshake(clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	if err == nil {
		t.Fatal("expected error from ERR packet")
	}
}

