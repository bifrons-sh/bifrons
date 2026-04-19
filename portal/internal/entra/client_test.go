package entra

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer spins up an httptest.Server that impersonates both the
// Microsoft login token endpoint and the Graph API. Handlers are provided by
// the caller; token issuance is wired automatically.
func newTestServer(t *testing.T, tokenCount *atomic.Int64, handler http.Handler) (*httptest.Server, *httptest.Server) {
	t.Helper()
	graphSrv := httptest.NewServer(handler)
	t.Cleanup(graphSrv.Close)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokenCount != nil {
			tokenCount.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		// 1h lifetime so ReuseTokenSourceWithExpiry(60s) doesn't trigger a
		// refresh between two back-to-back calls in the same test.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)
	return graphSrv, tokenSrv
}

func newTestClient(t *testing.T, tokenCount *atomic.Int64, handler http.Handler) *graphClient {
	t.Helper()
	graphSrv, tokenSrv := newTestServer(t, tokenCount, handler)
	cfg := Config{
		TenantID:     "tenant-1",
		ClientID:     "client-1",
		ClientSecret: "secret",
		GraphBaseURL: graphSrv.URL,
		TokenURL:     tokenSrv.URL,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	c, err := NewFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	return c
}

func TestManager_Success(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/users/u-1/manager" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer fake-token-123" {
			t.Errorf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(User{ID: "m-1", DisplayName: "Manager", Mail: "boss@example.com"})
	})
	c := newTestClient(t, nil, h)
	u, err := c.Manager(context.Background(), "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "m-1" || u.Mail != "boss@example.com" {
		t.Errorf("bad manager: %+v", u)
	}
}

func TestManager_NotFound(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := newTestClient(t, nil, h)
	_, err := c.Manager(context.Background(), "u-nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestGroups_Pagination(t *testing.T) {
	var calls atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users/u-1/memberOf", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// First page — include a directoryRole that must be filtered out.
			resp := map[string]any{
				"value": []map[string]any{
					{"@odata.type": "#microsoft.graph.group", "id": "g-1", "displayName": "DBA"},
					{"@odata.type": "#microsoft.graph.directoryRole", "id": "r-1", "displayName": "GlobalAdmin"},
				},
			}
			// The nextLink uses the same host; Graph returns absolute URLs.
			resp["@odata.nextLink"] = "http://" + r.Host + "/v1.0/users/u-1/memberOf?page=2"
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"@odata.type": "#microsoft.graph.group", "id": "g-2", "displayName": "Devs"},
			},
		})
	})
	c := newTestClient(t, nil, mux)
	gs, err := c.Groups(context.Background(), "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", len(gs), gs)
	}
	if gs[0].ID != "g-1" || gs[1].ID != "g-2" {
		t.Errorf("unexpected order: %+v", gs)
	}
}

func TestSendMail_PayloadShape(t *testing.T) {
	var captured map[string]any
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/users/noreply@example.com/sendMail" {
			t.Errorf("bad path %q", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		w.WriteHeader(http.StatusAccepted)
	})
	c := newTestClient(t, nil, h)
	err := c.SendMail(context.Background(), "noreply@example.com", MailMessage{
		To: []string{"boss@example.com"}, Subject: "Access request", HTMLBody: "<p>please</p>",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, ok := captured["message"].(map[string]any)
	if !ok {
		t.Fatalf("missing message in payload: %+v", captured)
	}
	if msg["subject"] != "Access request" {
		t.Errorf("subject mismatch: %v", msg["subject"])
	}
	body, _ := msg["body"].(map[string]any)
	if body["contentType"] != "HTML" || body["content"] != "<p>please</p>" {
		t.Errorf("body mismatch: %+v", body)
	}
	recipients, _ := msg["toRecipients"].([]any)
	if len(recipients) != 1 {
		t.Fatalf("want 1 recipient, got %d", len(recipients))
	}
	first, _ := recipients[0].(map[string]any)
	ea, _ := first["emailAddress"].(map[string]any)
	if ea["address"] != "boss@example.com" {
		t.Errorf("recipient mismatch: %+v", ea)
	}
	if captured["saveToSentItems"] != false {
		t.Errorf("saveToSentItems should be false, got %v", captured["saveToSentItems"])
	}
}

func TestSendMail_ValidatesInput(t *testing.T) {
	c := newTestClient(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("sendMail should not be called when input is invalid")
	}))
	if err := c.SendMail(context.Background(), "", MailMessage{To: []string{"a@b"}}); err == nil {
		t.Errorf("expected error on empty From")
	}
	if err := c.SendMail(context.Background(), "a@b", MailMessage{To: nil}); err == nil {
		t.Errorf("expected error on empty recipients")
	}
}

func TestToken_Caching(t *testing.T) {
	var tokens atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(User{ID: "u"})
	})
	c := newTestClient(t, &tokens, h)
	for i := 0; i < 3; i++ {
		_, _ = c.GetUser(context.Background(), "u-1")
	}
	// Three API calls, but the token has 1h lifetime so only one token fetch.
	if tokens.Load() != 1 {
		t.Errorf("expected 1 token fetch, got %d", tokens.Load())
	}
}

func TestToken_RefreshBeforeExpiry(t *testing.T) {
	var tokens atomic.Int64
	// Custom handler: short-lived token that lasts only 30s, inside the 60s
	// early-refresh window → every call triggers a refresh.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(User{ID: "u"})
	})
	graphSrv := httptest.NewServer(mux)
	t.Cleanup(graphSrv.Close)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "short",
			"token_type":   "Bearer",
			"expires_in":   30, // < 60s early-refresh window
		})
	}))
	t.Cleanup(tokenSrv.Close)

	c, err := NewFromConfig(context.Background(), Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		GraphBaseURL: graphSrv.URL, TokenURL: tokenSrv.URL,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two calls → the second should force a refresh because expires_in=30s
	// is inside the 60s early-expiry window.
	_, _ = c.GetUser(context.Background(), "a")
	_, _ = c.GetUser(context.Background(), "b")
	if tokens.Load() < 2 {
		t.Errorf("expected >= 2 token fetches with short-lived tokens, got %d", tokens.Load())
	}
}

func TestGraphError_IsClassified(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"x","message":"boom"}}`))
	})
	c := newTestClient(t, nil, h)
	_, err := c.GetUser(context.Background(), "u")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want a 5xx-classified error, got %v", err)
	}
	// Body must not leak into the error message.
	if strings.Contains(err.Error(), "boom") {
		t.Errorf("error leaked response body: %v", err)
	}
}

func TestNewFromConfig_RejectsEmpty(t *testing.T) {
	_, err := NewFromConfig(context.Background(), Config{})
	if err == nil {
		t.Error("expected error for empty config")
	}
}

func TestContextCancellation(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	c := newTestClient(t, nil, h)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.GetUser(ctx, "u")
	if err == nil {
		t.Fatal("expected ctx error")
	}
}
