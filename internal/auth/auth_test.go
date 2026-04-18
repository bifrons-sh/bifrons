package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func req(name string) LookupRequest {
	return LookupRequest{Username: name, SourceIP: "10.0.0.1", ProxyType: "mongo", BackendServer: "db:27017"}
}

// quickClient returns a client with zero retries + tight timeout for error-path tests.
func quickClient(url string) *Client {
	return NewClient(url, WithMaxRetries(0))
}

func TestLookup_OK(t *testing.T) {
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		var body LookupRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Username != "alice" || body.SourceIP != "10.0.0.1" || body.ProxyType != "mongo" || body.BackendServer != "db:27017" {
			t.Errorf("unexpected request body: %+v", body)
		}
		_ = json.NewEncoder(w).Encode(AuthResponse{Password: "p", BackendUser: "b", BackendPass: "q"})
	})
	defer srv.Close()

	c := NewClient(srv.URL)
	got, err := c.Lookup(context.Background(), req("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if got.BackendUser != "b" {
		t.Fatalf("backend_user = %q, want %q", got.BackendUser, "b")
	}
}

func TestLookup_DeniedStatuses(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := newServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})
			defer srv.Close()

			c := quickClient(srv.URL)
			_, err := c.Lookup(context.Background(), req("alice"))
			if err == nil || !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("expected ErrAccessDenied, got %v", err)
			}
		})
	}
}

func TestLookup_MalformedJSON(t *testing.T) {
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	defer srv.Close()

	c := quickClient(srv.URL)
	_, err := c.Lookup(context.Background(), req("alice"))
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestLookup_MissingFields(t *testing.T) {
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"password":"only"}`))
	})
	defer srv.Close()

	c := quickClient(srv.URL)
	_, err := c.Lookup(context.Background(), req("alice"))
	if err == nil || !strings.Contains(err.Error(), "missing required") {
		t.Fatalf("want missing-fields error, got %v", err)
	}
}

func TestLookup_5xxRetriesAndFails(t *testing.T) {
	var calls atomic.Int32
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})
	defer srv.Close()

	c := NewClient(srv.URL, WithMaxRetries(2))
	_, err := c.Lookup(context.Background(), req("alice"))
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 500 error, got %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts (1 + 2 retries), got %d", got)
	}
}

func TestLookup_5xxRetrySucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(AuthResponse{Password: "p", BackendUser: "b", BackendPass: "q"})
	})
	defer srv.Close()

	c := NewClient(srv.URL, WithMaxRetries(2))
	got, err := c.Lookup(context.Background(), req("alice"))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.BackendUser != "b" {
		t.Fatalf("wrong response: %+v", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("want 2 attempts, got %d", calls.Load())
	}
}

func TestLookup_Denied_NoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	})
	defer srv.Close()

	c := NewClient(srv.URL, WithMaxRetries(5))
	_, err := c.Lookup(context.Background(), req("alice"))
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("want ErrAccessDenied, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("401/403 must not retry; got %d attempts", calls.Load())
	}
}

func TestLookup_CtxCancel(t *testing.T) {
	hit := atomic.Bool{}
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
			_ = json.NewEncoder(w).Encode(AuthResponse{Password: "p", BackendUser: "b", BackendPass: "q"})
		}
	})
	defer srv.Close()

	c := quickClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Lookup(ctx, req("alice"))
	if err == nil {
		t.Fatal("expected ctx cancellation error")
	}
	if !hit.Load() {
		t.Fatal("server never saw the request")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCRAMStoredCredentials_RejectsWeakIters(t *testing.T) {
	if _, err := SCRAMStoredCredentials("pw", 1024); err == nil {
		t.Fatal("want error for iters below minimum")
	}
}

func TestAuthResponse_LogValueRedacts(t *testing.T) {
	a := AuthResponse{Password: "supersecret", BackendUser: "b", BackendPass: "alsosecret"}
	var buf strings.Builder
	log := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) {
		buf.Write(p)
		return len(p), nil
	}), nil))
	log.Info("check", "auth", a)
	out := buf.String()
	if strings.Contains(out, "supersecret") || strings.Contains(out, "alsosecret") {
		t.Fatalf("secrets leaked into log output: %s", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Fatalf("redaction marker missing: %s", out)
	}
	if !strings.Contains(out, `"backend_user":"b"`) {
		t.Fatalf("non-sensitive field missing: %s", out)
	}
}

type writerFunc func(p []byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }
