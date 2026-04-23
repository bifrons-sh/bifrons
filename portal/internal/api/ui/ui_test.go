package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ServesPlaceholderIndex(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(Handler(nil))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/ui/index.html")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandler_SecurityHeaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(Handler(nil))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatalf("get /ui/: %v", err)
	}
	defer resp.Body.Close()

	// Every header here is a hard requirement from the UI security spec.
	// Encoded as a lookup table so a header rename fails *one* assertion
	// with a clear message rather than a cascade.
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"X-Content-Type-Options":  "nosniff",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
}

func TestHandler_SPARewrite(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(Handler(nil))
	t.Cleanup(srv.Close)

	// Unknown extensionless path should fall back to index.html — the
	// client-side router will render the right view.
	resp, err := http.Get(srv.URL + "/ui/grants")
	if err != nil {
		t.Fatalf("get /ui/grants: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "<html") {
		t.Errorf("expected HTML body (SPA fallback), got: %q", string(body[:n]))
	}
}
