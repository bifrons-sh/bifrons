package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
)

// makeCancelRequest builds a PG CancelRequest startup frame.
func makeCancelRequest(pid, key uint32) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint32(buf[0:4], 16)
	binary.BigEndian.PutUint32(buf[4:8], cancelRequestCode)
	binary.BigEndian.PutUint32(buf[8:12], pid)
	binary.BigEndian.PutUint32(buf[12:16], key)
	return buf
}

// TestHandleStartup_CancelRequest asserts that a CancelRequest is forwarded
// to the backend once and then returns errCancelForwarded without entering auth.
func TestHandleStartup_CancelRequest(t *testing.T) {
	h := NewHandler(slog.New(slog.NewJSONHandler(io.Discard, nil)), nil)

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	cancelMsg := makeCancelRequest(12345, 0xDEADBEEF)

	var wg sync.WaitGroup
	wg.Add(2)

	// Client writes the cancel message then closes.
	go func() {
		defer wg.Done()
		defer clientApp.Close()
		_, _ = clientApp.Write(cancelMsg)
	}()

	// Backend receives exactly the cancel bytes.
	var received bytes.Buffer
	go func() {
		defer wg.Done()
		defer backendSrv.Close()
		buf := make([]byte, 64)
		for {
			n, err := backendSrv.Read(buf)
			if n > 0 {
				received.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	_, _, err := h.handleStartup(context.Background(), clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	wg.Wait()

	if !errors.Is(err, errCancelForwarded) {
		t.Fatalf("expected errCancelForwarded, got %v", err)
	}
	if !bytes.Equal(received.Bytes(), cancelMsg) {
		t.Fatalf("backend got %x, want %x", received.Bytes(), cancelMsg)
	}
}

// TestRelayAuth_CapProtectsAgainstLoopingBackend verifies the auth loop cap
// fires if the backend keeps sending messages without ever reaching 'Z' or 'E'.
func TestRelayAuth_CapProtectsAgainstLoopingBackend(t *testing.T) {
	h := NewHandler(slog.New(slog.NewJSONHandler(io.Discard, nil)), nil)

	clientProxy, clientApp := net.Pipe()
	backendProxy, backendSrv := net.Pipe()

	// Backend floods us with harmless ParameterStatus messages ('S').
	go func() {
		defer backendSrv.Close()
		pkt := makePGMessage('S', []byte("app\x00foo\x00"))
		for i := 0; i < maxAuthMessages+5; i++ {
			if _, err := backendSrv.Write(pkt); err != nil {
				return
			}
		}
	}()
	// Client drains forwarded messages.
	go func() {
		defer clientApp.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := clientApp.Read(buf); err != nil {
				return
			}
		}
	}()

	err := h.relayAuth(clientProxy, backendProxy, h.logger)
	clientProxy.Close()
	backendProxy.Close()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("exceeded max auth messages")) {
		t.Fatalf("expected cap error, got %v", err)
	}
}
