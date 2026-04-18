package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsClosed(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"io.EOF", io.EOF, true},
		{"wrapped io.EOF", fmt.Errorf("wrap: %w", io.EOF), true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"wrapped net.ErrClosed", fmt.Errorf("wrap: %w", net.ErrClosed), true},
		{"legacy string", errors.New("read tcp: use of closed network connection"), true},
		{"real error", errors.New("connection reset by peer"), false},
		{"timeout", errors.New("i/o timeout"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsClosed(tt.err); got != tt.want {
				t.Fatalf("IsClosed(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// closerFn lets us observe Close() invocations.
type closerFn struct{ closed atomic.Int32 }

func (c *closerFn) Close() error {
	c.closed.Add(1)
	return nil
}

func TestCloseOnDone_CtxCancelClosesResource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &closerFn{}
	stop := CloseOnDone(ctx, c)
	defer stop()

	cancel()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.closed.Load() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("resource was not closed on ctx.Done (closed=%d)", c.closed.Load())
}

func TestCloseOnDone_StopPreventsClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &closerFn{}
	stop := CloseOnDone(ctx, c)

	stop()               // stop first
	time.Sleep(20 * time.Millisecond) // let goroutine exit
	cancel()
	time.Sleep(20 * time.Millisecond)

	if c.closed.Load() != 0 {
		t.Fatalf("stop() should prevent Close; got closed=%d", c.closed.Load())
	}
}

func TestCloseOnDone_StopIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := CloseOnDone(ctx, &closerFn{})
	// Calling stop twice must not panic.
	stop()
	stop()
}

func TestSafeGo_SendsErrOnSuccess(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	done := make(chan error, 1)
	SafeGo(log, "test", func() error { return nil }, done)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SafeGo never reported")
	}
}

func TestSafeGo_SendsErrOnError(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	done := make(chan error, 1)
	want := errors.New("boom")
	SafeGo(log, "test", func() error { return want }, done)
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("SafeGo never reported")
	}
}

func TestSafeGo_RecoversFromPanic(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	done := make(chan error, 1)
	SafeGo(log, "crasher", func() error {
		panic("kaboom")
	}, done)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from recovered panic")
		}
		if got := err.Error(); got == "" {
			t.Fatal("empty error string")
		}
	case <-time.After(time.Second):
		t.Fatal("SafeGo panic did not produce done signal")
	}
}

func TestSafeGo_PanicDoesNotTerminateProcess(t *testing.T) {
	// If this test runs to completion, SafeGo's recover worked.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		SafeGo(log, "multi-crash", func() error { panic("boom") }, done)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("goroutine %d hung after panic", i)
		}
	}
}
