package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// discardLogger is a slog.Logger that throws output away — keeps test noise down.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// newProvisioningPortal returns a test portal wired with a real provisioning
// Client over a poll-only (noop) notifier and an in-memory store. There is NO
// worker in-process: tests simulate the worker by pre-seeding intent results
// directly into the store (see seedDoneIntent / seedFailedIntent).
func newProvisioningPortal(t *testing.T, cfg *config.Config) (*httptest.Server, store.Store, *provisioning.Client) {
	t.Helper()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	notifier, err := provisioning.NewNotifier(context.Background(), "sqlite::memory:", discardLogger())
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	client := provisioning.NewClient(s, notifier, discardLogger())
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, discardLogger(), WithProvisioningClient(client))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, s, client
}

func seedEphemeralGrant(t *testing.T, s store.Store) (domain.User, domain.Backend, domain.Grant) {
	t.Helper()
	ctx := context.Background()
	u := domain.User{ID: "u-eph", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// dual_or so a single approve call clears the gate (four-eyes guard in
	// dual_strict rejects same-actor double-approve); these tests focus on
	// /claim semantics, not the workflow modes.
	b := domain.Backend{ID: "b-eph", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017,
		ApprovalMode: domain.ApprovalDualOr}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: "g-eph", UserID: u.ID, BackendID: b.ID, Status: domain.GrantPending,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "p-pw",
		// PolicyMode=ephemeral so /claim takes the outbox path. With no Entra
		// wired, create() leaves PolicyMode empty (defaults permanent), so
		// seeding directly here is the only way to exercise ephemeral.
		PolicyMode:  policy.ModeEphemeral,
		RequestedAt: time.Now(), ExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	return u, b, g
}

// seedDoneIntent simulates a worker that finished provisioning: it emits the
// provision intent (deterministic id — same as the handler would compute),
// claims it, then completes it with the given credential. WaitForResult / the
// status endpoint then observe a terminal done intent.
func seedDoneIntent(t *testing.T, s store.Store, g domain.Grant, user, pass string) domain.Intent {
	t.Helper()
	ctx := context.Background()
	in := provisioning.ProvisionIntent(g, time.Hour)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}
	const worker = "w-test"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("ClaimPendingIntents: %v", err)
	}
	if err := s.CompleteIntent(ctx, in.ID, worker, user, pass); err != nil {
		t.Fatalf("CompleteIntent: %v", err)
	}
	return in
}

// seedFailedIntent simulates a worker that gave up: emits, claims, then fails
// the provision intent with a closed-enum error class.
func seedFailedIntent(t *testing.T, s store.Store, g domain.Grant, class, detail string) domain.Intent {
	t.Helper()
	ctx := context.Background()
	in := provisioning.ProvisionIntent(g, time.Hour)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}
	const worker = "w-test"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("ClaimPendingIntents: %v", err)
	}
	if err := s.FailIntent(ctx, in.ID, worker, class, detail, 1); err != nil {
		t.Fatalf("FailIntent: %v", err)
	}
	return in
}

// approve walks PENDING → APPROVED via a single dual_or approve call as the
// static bearer (tests stay session-free).
func approve(t *testing.T, srv *httptest.Server, id string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+id+"/approve", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d", r.StatusCode)
	}
}

func postClaim(t *testing.T, srv *httptest.Server, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+id+"/claim", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func ephemeralCfg() *config.Config {
	return &config.Config{
		UserToken: "api-tok",
		Windows:   config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour},
	}
}

// TestClaim_Ephemeral_DoneIntent returns 200 with the worker's creds and flips
// the grant ACTIVE when a done provision intent is already present.
func TestClaim_Ephemeral_DoneIntent(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	seedDoneIntent(t, s, g, "portal_grant_test", "hex-pw")

	resp := postClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("claim status=%d body=%s", resp.StatusCode, body)
	}
	var cr claimResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cr.BackendUser != "portal_grant_test" || cr.BackendPass != "hex-pw" {
		t.Errorf("claim creds = %q/%q, want worker-provisioned pair", cr.BackendUser, cr.BackendPass)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantActive {
		t.Errorf("expected ACTIVE after claim, got %s", stored.Status)
	}
	if stored.EphemeralUsername != "portal_grant_test" {
		t.Errorf("expected propagated username, got %q", stored.EphemeralUsername)
	}
}

// TestClaim_Ephemeral_NoResult_Returns202 returns 202 + Location + Retry-After
// when no result is seeded (worker hasn't run); the grant stays APPROVED.
func TestClaim_Ephemeral_NoResult_Returns202(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	// No intent result seeded — the short-circuit wait times out to pending.

	resp := postClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d body=%s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "/api/v1/grants/"+g.ID+"/claim/status" {
		t.Errorf("Location = %q", loc)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
	var pr claimPendingResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pr.IntentID == "" || pr.State != string(domain.IntentPending) {
		t.Errorf("body = %+v, want pending intent id + state", pr)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantApproved {
		t.Errorf("grant must stay APPROVED on 202, got %s", stored.Status)
	}
	// A pending provision intent must now exist for the grant.
	in, err := s.GetLatestIntentForGrant(context.Background(), g.ID, domain.IntentProvision)
	if err != nil {
		t.Errorf("expected a provision intent emitted by claim: %v", err)
	}
	// C1: the emitted intent must carry the effective credential TTL so the
	// worker provisions a time-boxed backend user (VALID UNTIL), not an
	// infinite-lived account. ephemeralCfg sets CredentialTTL=1h.
	if want := int((time.Hour).Seconds()); in.RequestedDurationSec != want {
		t.Errorf("provision intent RequestedDurationSec = %d, want %d (effective credential TTL)",
			in.RequestedDurationSec, want)
	}
}

// TestClaim_Ephemeral_FailedIntent_Returns422 surfaces the worker's terminal
// failure with the error class; the grant stays APPROVED.
func TestClaim_Ephemeral_FailedIntent_Returns422(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	seedFailedIntent(t, s, g, "terminal_permission", "master lacks CREATEROLE")

	resp := postClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 422, got %d body=%s", resp.StatusCode, body)
	}
	var fr claimFailedResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fr.State != string(domain.IntentFailed) || fr.ErrorClass != "terminal_permission" {
		t.Errorf("body = %+v, want failed + terminal_permission", fr)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantApproved {
		t.Errorf("grant must stay APPROVED on failed claim, got %s", stored.Status)
	}
}

// TestClaimStatus_PendingThenDone exercises the poll endpoint: progress while
// pending, then creds + ACTIVE once the worker completes the intent.
func TestClaimStatus_PendingThenDone(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)

	// First /claim returns 202 and emits the intent.
	resp := postClaim(t, srv, g.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("claim status=%d want 202", resp.StatusCode)
	}

	// Status while still pending → 200 progress.
	statusURL := srv.URL + "/api/v1/grants/" + g.ID + "/claim/status"
	sr := getStatus(t, statusURL)
	if sr.StatusCode != http.StatusOK {
		t.Fatalf("status (pending) = %d want 200", sr.StatusCode)
	}
	var pr claimProgressResponse
	json.NewDecoder(sr.Body).Decode(&pr)
	sr.Body.Close()
	if pr.State != string(domain.IntentInFlight) && pr.State != string(domain.IntentPending) {
		t.Errorf("progress state = %q", pr.State)
	}

	// Worker completes the already-emitted intent (claim it, then complete).
	ctx := context.Background()
	in, err := s.GetLatestIntentForGrant(ctx, g.ID, domain.IntentProvision)
	if err != nil {
		t.Fatalf("GetLatestIntentForGrant: %v", err)
	}
	const worker = "w-test"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("ClaimPendingIntents: %v", err)
	}
	if err := s.CompleteIntent(ctx, in.ID, worker, "portal_grant_test", "hex-pw"); err != nil {
		t.Fatalf("CompleteIntent: %v", err)
	}

	// Status now → 200 creds + grant ACTIVE.
	sr2 := getStatus(t, statusURL)
	defer sr2.Body.Close()
	if sr2.StatusCode != http.StatusOK {
		t.Fatalf("status (done) = %d want 200", sr2.StatusCode)
	}
	var cr claimResponse
	json.NewDecoder(sr2.Body).Decode(&cr)
	if cr.BackendUser != "portal_grant_test" {
		t.Errorf("status creds user = %q", cr.BackendUser)
	}
	stored, _ := s.GetGrant(ctx, g.ID)
	if stored.Status != domain.GrantActive {
		t.Errorf("expected ACTIVE after status propagation, got %s", stored.Status)
	}
}

// TestClaimStatus_NoIntent_Returns409 when the grant is claimable but no claim
// was ever POSTed.
func TestClaimStatus_NoIntent_Returns409(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)

	sr := getStatus(t, srv.URL+"/api/v1/grants/"+g.ID+"/claim/status")
	defer sr.Body.Close()
	if sr.StatusCode != http.StatusConflict {
		t.Fatalf("status (no intent) = %d want 409", sr.StatusCode)
	}
}

func getStatus(t *testing.T, url string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestRevoke_EmitsRevokeIntent: DELETE on an ACTIVE ephemeral grant emits a
// revoke intent (the worker drops the user; the portal doesn't block).
func TestRevoke_EmitsRevokeIntent(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	seedDoneIntent(t, s, g, "portal_grant_test", "hex-pw")

	// Claim to ACTIVE so the grant carries an ephemeral username.
	cresp := postClaim(t, srv, g.ID)
	cresp.Body.Close()
	if cresp.StatusCode != http.StatusOK {
		t.Fatalf("claim status=%d want 200", cresp.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/grants/"+g.ID, nil)
	del.Header.Set("Authorization", "Bearer api-tok")
	delResp, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", delResp.StatusCode)
	}
	// A revoke intent row must now exist for the grant.
	rin, err := s.GetLatestIntentForGrant(context.Background(), g.ID, domain.IntentRevoke)
	if err != nil {
		t.Fatalf("expected a revoke intent emitted by DELETE: %v", err)
	}
	if rin.TargetUsername != "portal_grant_test" {
		t.Errorf("revoke intent target = %q, want the provisioned username", rin.TargetUsername)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantRevoked {
		t.Errorf("expected REVOKED, got %s", stored.Status)
	}
}

// TestRevoke_NoCreds_StillEmitsRevokeIntent covers HIGH-1: revoking an ephemeral
// grant whose provision intent is still pending/in_flight (no EphemeralUsername
// recorded yet) MUST still emit a revoke intent, with an empty TargetUsername so
// the worker derives + drops the sibling provision username. Otherwise the
// in-flight provision could create ap_<hmac> with no record → permanent orphan.
func TestRevoke_NoCreds_StillEmitsRevokeIntent(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)

	// Emit a provision intent (POST /claim → 202) but never complete it: the
	// grant is APPROVED with no creds, exactly the in-flight-then-revoked window.
	cresp := postClaim(t, srv, g.ID)
	cresp.Body.Close()
	if cresp.StatusCode != http.StatusAccepted {
		t.Fatalf("claim status=%d want 202", cresp.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/grants/"+g.ID, nil)
	del.Header.Set("Authorization", "Bearer api-tok")
	delResp, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", delResp.StatusCode)
	}

	rin, err := s.GetLatestIntentForGrant(context.Background(), g.ID, domain.IntentRevoke)
	if err != nil {
		t.Fatalf("expected a revoke intent even with no creds: %v", err)
	}
	if rin.TargetUsername != "" {
		t.Errorf("revoke target = %q, want empty so the worker derives the sibling name", rin.TargetUsername)
	}
}

// TestClaim_TransientFailure_ResetsAndRedrives covers HIGH-2: a failed provision
// intent with a TRANSIENT class is auto-reset to pending on re-claim (not bricked
// at 422 forever), and once the worker completes the re-armed intent the claim
// succeeds.
func TestClaim_TransientFailure_ResetsAndRedrives(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	in := seedFailedIntent(t, s, g, "transient_network", "i/o timeout")

	// Re-claim: the transient failure must be reset (not 422). With no worker to
	// complete it within the wait, the handshake degrades to 202 pending.
	resp := postClaim(t, srv, g.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("transient re-claim status=%d want 202 (reset+pending) body=%s", resp.StatusCode, body)
	}
	got, _ := s.GetIntent(context.Background(), in.ID)
	if got.Status != domain.IntentPending || got.RetryCount != 0 || got.ErrorClass != "" {
		t.Fatalf("transient intent not re-armed: %+v", got)
	}

	// Worker completes the re-armed intent → next claim succeeds with creds.
	ctx := context.Background()
	if _, err := s.ClaimPendingIntents(ctx, "w-test", nil, time.Minute, 10); err != nil {
		t.Fatalf("ClaimPendingIntents: %v", err)
	}
	if err := s.CompleteIntent(ctx, in.ID, "w-test", "portal_grant_test", "hex-pw"); err != nil {
		t.Fatalf("CompleteIntent: %v", err)
	}
	resp2 := postClaim(t, srv, g.ID)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("post-retry claim status=%d want 200 body=%s", resp2.StatusCode, body)
	}
	var cr claimResponse
	json.NewDecoder(resp2.Body).Decode(&cr)
	if cr.BackendUser != "portal_grant_test" {
		t.Errorf("creds user = %q, want re-driven worker creds", cr.BackendUser)
	}
}

// seedFailedIntentWithRetries is seedFailedIntent with an explicit
// worker-reported retry_count, so a test can stage an intent that has already
// burned N transient attempts (M3 cap boundary).
func seedFailedIntentWithRetries(t *testing.T, s store.Store, g domain.Grant, class, detail string, retries int) domain.Intent {
	t.Helper()
	ctx := context.Background()
	in := provisioning.ProvisionIntent(g, time.Hour)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}
	const worker = "w-test"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("ClaimPendingIntents: %v", err)
	}
	if err := s.FailIntent(ctx, in.ID, worker, class, detail, retries); err != nil {
		t.Fatalf("FailIntent: %v", err)
	}
	return in
}

// TestClaimStatus_TransientPastCap_StaysFailed covers M3: a TRANSIENT failure
// whose worker-reported retry_count has reached the auto-retry ceiling must NOT
// be re-armed by /claim/status — it surfaces as 422 (terminal) so a hard
// failure that keeps classifying transient can't oscillate failed↔pending
// forever. The intent row must stay failed (never reset to pending).
func TestClaimStatus_TransientPastCap_StaysFailed(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	in := seedFailedIntentWithRetries(t, s, g, "transient_network", "i/o timeout", maxClaimAutoRetries)

	sr := getStatus(t, srv.URL+"/api/v1/grants/"+g.ID+"/claim/status")
	defer sr.Body.Close()
	if sr.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(sr.Body)
		t.Fatalf("transient-past-cap status=%d want 422 body=%s", sr.StatusCode, body)
	}
	var fr claimFailedResponse
	if err := json.NewDecoder(sr.Body).Decode(&fr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fr.State != string(domain.IntentFailed) || fr.ErrorClass != "transient_network" {
		t.Errorf("body = %+v, want failed + transient_network", fr)
	}
	// The row must NOT have been reset to pending.
	got, _ := s.GetIntent(context.Background(), in.ID)
	if got.Status != domain.IntentFailed {
		t.Errorf("intent past cap was re-armed: %+v", got)
	}
}

// TestClaim_TransientPastCap_StaysFailed: the same M3 cap on the POST /claim
// path — a transient failure at the ceiling returns 422 instead of re-arming.
func TestClaim_TransientPastCap_StaysFailed(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	in := seedFailedIntentWithRetries(t, s, g, "transient_exhausted", "pool drained", maxClaimAutoRetries)

	resp := postClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("transient-past-cap claim status=%d want 422 body=%s", resp.StatusCode, body)
	}
	got, _ := s.GetIntent(context.Background(), in.ID)
	if got.Status != domain.IntentFailed {
		t.Errorf("intent past cap was re-armed: %+v", got)
	}
}

// TestClaim_TerminalFailure_StaysFailed covers the HIGH-2 boundary: a TERMINAL
// class is a real misconfig and must keep returning 422 on re-claim (never reset).
func TestClaim_TerminalFailure_StaysFailed(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	in := seedFailedIntent(t, s, g, "terminal_permission", "master lacks CREATEROLE")

	resp := postClaim(t, srv, g.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("terminal re-claim status=%d want 422", resp.StatusCode)
	}
	// The row must remain failed — not reset.
	got, _ := s.GetIntent(context.Background(), in.ID)
	if got.Status != domain.IntentFailed {
		t.Errorf("terminal intent was reset: %+v", got)
	}
}

// TestFinishEphemeralClaim_ActiveRace_ReturnsCredsNot500 covers MEDIUM-1: when
// the snapshot g handed to finishEphemeralClaim is stale-APPROVED but the store
// row has already been flipped ACTIVE by a concurrent claim/reconciler, the
// APPROVED→ACTIVE CAS returns ErrConflict. That must be treated as benign — the
// handler re-reads and returns the already-active creds, NOT a 500. We call the
// handler method directly so the snapshot is provably stale (the HTTP front door
// re-reads at entry and never exposes this window).
func TestFinishEphemeralClaim_ActiveRace_ReturnsCredsNot500(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	_, _, g := seedEphemeralGrant(t, s)
	ctx := context.Background()

	// Bring the grant to APPROVED and seed a done intent (the snapshot the
	// handler will act on).
	g.Status = domain.GrantApproved
	if err := s.UpdateGrant(ctx, g); err != nil {
		t.Fatalf("UpdateGrant: %v", err)
	}
	seedDoneIntent(t, s, g, "portal_grant_test", "hex-pw")
	// Re-read the COMPLETED intent (seedDoneIntent returns the pre-completion
	// value with empty result columns).
	in, err := s.GetLatestIntentForGrant(ctx, g.ID, domain.IntentProvision)
	if err != nil {
		t.Fatalf("GetLatestIntentForGrant: %v", err)
	}

	// Concurrent winner: flip the store row ACTIVE with the same creds. The
	// handler's snapshot g is still APPROVED, so its CAS will ErrConflict.
	exp := time.Now().Add(time.Hour)
	active := g
	active.Status = domain.GrantActive
	active.EphemeralUsername = "portal_grant_test"
	active.EphemeralPassword = "hex-pw"
	active.ExpiresAt = &exp
	if err := s.UpdateGrantIfStatus(ctx, active, domain.GrantApproved); err != nil {
		t.Fatalf("force ACTIVE: %v", err)
	}

	h := &grantsHandler{store: s, logger: discardLogger()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grants/"+g.ID+"/claim", nil)
	// g is the STALE APPROVED snapshot — this is the race the fix handles.
	h.finishEphemeralClaim(rec, req, g, in, false, true)

	if rec.Code != http.StatusOK {
		t.Fatalf("active-race finish status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var cr claimResponse
	if err := json.NewDecoder(rec.Body).Decode(&cr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cr.BackendUser != "portal_grant_test" {
		t.Errorf("creds user = %q, want the already-active creds", cr.BackendUser)
	}
}

// TestGrantJSON_DoesNotLeakEphemeralPassword asserts the JSON encoding never
// serializes the password (json:"-") even when we specifically request the grant.
func TestGrantJSON_DoesNotLeakEphemeralPassword(t *testing.T) {
	g := domain.Grant{
		ID: "g-1", EphemeralUsername: "portal_grant_abc", EphemeralPassword: "secret-pw",
	}
	raw, _ := json.Marshal(g)
	if bytes.Contains(raw, []byte("secret-pw")) {
		t.Errorf("Grant JSON leaks ephemeral password: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"ephemeral_username":"portal_grant_abc"`)) {
		t.Errorf("expected username in JSON, got %s", raw)
	}
}

// TestClaim_AdminOnBehalf_EmitsAuditRow: an admin (static-bearer) claiming a
// grant they don't own must leave exactly one AuditEntry with the portal
// lifecycle sentinel, and a re-claim must not append another.
func TestClaim_AdminOnBehalf_EmitsAuditRow(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	approve(t, srv, g.ID)
	seedDoneIntent(t, s, g, "portal_grant_test", "hex-pw")

	resp := postClaim(t, srv, g.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim status=%d", resp.StatusCode)
	}

	countOnBehalf := func() int {
		entries, _ := s.ListAudit(context.Background(), store.AuditFilter{GrantID: g.ID, Limit: 10})
		n := 0
		for _, e := range entries {
			if e.ProxyType == "portal" && bytes.Contains([]byte(e.Query), []byte("admin_on_behalf_claim")) {
				n++
			}
		}
		return n
	}
	if got := countOnBehalf(); got != 1 {
		t.Fatalf("want 1 admin_on_behalf_claim audit row, got %d", got)
	}

	// Idempotent re-claim on an already-ACTIVE grant must NOT append another row.
	resp2 := postClaim(t, srv, g.ID)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-claim status=%d want 200", resp2.StatusCode)
	}
	if got := countOnBehalf(); got != 1 {
		t.Errorf("re-claim appended audit rows; want still 1, got %d", got)
	}
}

// TestClaim_FailedValidation_SkipsAudit: an admin claim rejected by status
// validation (PENDING grant) must NOT persist an admin_on_behalf_claim row.
func TestClaim_FailedValidation_SkipsAudit(t *testing.T) {
	srv, s, _ := newProvisioningPortal(t, ephemeralCfg())
	_, _, g := seedEphemeralGrant(t, s)
	// No approve — grant stays PENDING. Claim must 409.

	resp := postClaim(t, srv, g.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 on PENDING claim, got %d", resp.StatusCode)
	}
	entries, _ := s.ListAudit(context.Background(), store.AuditFilter{GrantID: g.ID, Limit: 10})
	for _, e := range entries {
		if e.ProxyType == "portal" && bytes.Contains([]byte(e.Query), []byte("admin_on_behalf_claim")) {
			t.Errorf("failed claim leaked audit row: %+v", e)
		}
	}
}
