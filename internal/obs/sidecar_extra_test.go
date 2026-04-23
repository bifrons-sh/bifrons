package obs

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSidecar_Start_BindsRequestedAddr(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	s := NewServer(addr, slog.New(slog.NewJSONHandler(io.Discard, nil)),
		BuildInfo{Version: "v1", CommitHash: "abc"}, nil)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()
	s.MarkReady()
	if s.Addr().String() != addr {
		t.Errorf("Addr = %s, want %s", s.Addr(), addr)
	}
}

func TestSidecar_Version(t *testing.T) {
	s, base := startSidecar(t, nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()

	resp, err := http.Get(base + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "version=test") {
		t.Errorf("version endpoint body = %q", body)
	}
}

func TestSidecar_AddrNilBeforeStart(t *testing.T) {
	s := NewServer("127.0.0.1:0", slog.New(slog.NewJSONHandler(io.Discard, nil)), BuildInfo{}, nil)
	if s.Addr() != nil {
		t.Errorf("Addr before Start should be nil, got %v", s.Addr())
	}
}

func TestSidecar_ShutdownBeforeStartIsSafe(t *testing.T) {
	s := NewServer(":0", slog.New(slog.NewJSONHandler(io.Discard, nil)), BuildInfo{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown on un-started server returned err: %v", err)
	}
}
