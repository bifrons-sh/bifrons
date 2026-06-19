package lifecycle

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// seedApprovedWithDoneIntent stages the sad path: an APPROVED ephemeral grant
// whose provision intent the worker already completed, but which nobody polled.
func seedApprovedWithDoneIntent(t *testing.T, s store.Store, grantID, user, pass string) {
	t.Helper()
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: grantID, UserID: "u-1", BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.GrantApproved, PolicyMode: "ephemeral",
		RequestedAt: time.Now(), ClaimExpiresAt: &exp,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	in := domain.Intent{ID: domain.IntentID(grantID, domain.IntentProvision), GrantID: grantID,
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp, Status: domain.IntentPending}
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	const worker = "w-test"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteIntent(ctx, in.ID, worker, user, pass); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileProvisionedGrants_FlipsApprovedDoneToActive: the reconciler
// propagates the worker's credential and transitions APPROVED→ACTIVE.
func TestReconcileProvisionedGrants_FlipsApprovedDoneToActive(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	seedApprovedWithDoneIntent(t, s, "g-sad", "portal_grant_sad", "sad-pw")

	n := ReconcileProvisionedGrants(ctx, s, time.Hour, quietLogger())
	if n != 1 {
		t.Fatalf("reconciled count = %d, want 1", n)
	}
	g, _ := s.GetGrant(ctx, "g-sad")
	if g.Status != domain.GrantActive {
		t.Errorf("status = %s, want ACTIVE", g.Status)
	}
	if g.EphemeralUsername != "portal_grant_sad" || g.EphemeralPassword != "sad-pw" {
		t.Errorf("creds = %q/%q, want propagated worker creds", g.EphemeralUsername, g.EphemeralPassword)
	}
	if g.ExpiresAt == nil {
		t.Error("ExpiresAt must be stamped so the sweeper can reap the grant")
	}
}

// TestReconcileProvisionedGrants_SkipsPendingIntent: an APPROVED grant whose
// intent is still pending must NOT be flipped.
func TestReconcileProvisionedGrants_SkipsPendingIntent(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: "g-pending", UserID: "u-1", BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.GrantApproved, PolicyMode: "ephemeral",
		RequestedAt: time.Now(), ClaimExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	_ = s.CreateGrant(ctx, g)
	in := domain.Intent{ID: domain.IntentID("g-pending", domain.IntentProvision), GrantID: "g-pending",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp, Status: domain.IntentPending}
	_ = s.InsertIntent(ctx, in)

	if n := ReconcileProvisionedGrants(ctx, s, time.Hour, quietLogger()); n != 0 {
		t.Fatalf("reconciled count = %d, want 0 for a pending intent", n)
	}
	got, _ := s.GetGrant(ctx, "g-pending")
	if got.Status != domain.GrantApproved {
		t.Errorf("status = %s, want still APPROVED", got.Status)
	}
}

// seedRevokedWithRevokeIntent stages the H2 orphan-loop scenario: a terminal
// (REVOKED) grant that still carries an ephemeral_username, whose revoke intent
// the worker completed (status=done) — the backend user is actually gone but
// nothing cleared the columns, so ListEphemeralOrphans keeps re-listing it.
// revokeDone toggles whether the revoke intent is completed (done) or left
// pending.
func seedRevokedWithRevokeIntent(t *testing.T, s store.Store, grantID, user string, revokeDone bool) {
	t.Helper()
	ctx := context.Background()
	g := domain.Grant{
		ID: grantID, UserID: "u-1", BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.GrantRevoked, PolicyMode: "ephemeral",
		EphemeralUsername: user, EphemeralPassword: "pw",
		RequestedAt: time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	in := domain.Intent{ID: domain.IntentID(grantID, domain.IntentRevoke), GrantID: grantID,
		Kind: domain.IntentRevoke, BackendID: "b-1", Role: domain.RoleApp,
		TargetUsername: user, Status: domain.IntentPending}
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatal(err)
	}
	if !revokeDone {
		return
	}
	const worker = "w-test"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatal(err)
	}
	// A revoke completes with no credential payload — empty result columns.
	if err := s.CompleteIntent(ctx, in.ID, worker, "", ""); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileRevokedEphemeral_ClearsOnDoneRevoke covers H2: a terminal grant
// whose revoke intent is done has its ephemeral columns cleared, dropping it out
// of the orphan list so the orphan sweep stops re-emitting revoke intents.
func TestReconcileRevokedEphemeral_ClearsOnDoneRevoke(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	seedRevokedWithRevokeIntent(t, s, "g-revoked", "portal_grant_rev", true)

	// Sanity: it's an orphan before the pass.
	pre, _ := s.ListEphemeralOrphans(ctx)
	if len(pre) != 1 {
		t.Fatalf("want 1 orphan before reconcile, got %d", len(pre))
	}

	if n := ReconcileRevokedEphemeral(ctx, s, quietLogger()); n != 1 {
		t.Fatalf("cleared count = %d, want 1", n)
	}
	g, _ := s.GetGrant(ctx, "g-revoked")
	if g.EphemeralUsername != "" || g.EphemeralPassword != "" {
		t.Errorf("ephemeral columns not cleared: %q/%q", g.EphemeralUsername, g.EphemeralPassword)
	}
	// The grant must now be gone from the orphan list — the loop is closed.
	post, _ := s.ListEphemeralOrphans(ctx)
	if len(post) != 0 {
		t.Errorf("grant still listed as orphan after clear: %d", len(post))
	}
}

// TestReconcileRevokedEphemeral_SkipsPendingRevoke: a terminal grant whose
// revoke intent is still pending (user not yet dropped) must keep its columns
// so the orphan sweep keeps it in the re-emit set.
func TestReconcileRevokedEphemeral_SkipsPendingRevoke(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	seedRevokedWithRevokeIntent(t, s, "g-pending-rev", "portal_grant_rev", false)

	if n := ReconcileRevokedEphemeral(ctx, s, quietLogger()); n != 0 {
		t.Fatalf("cleared count = %d, want 0 for a pending revoke", n)
	}
	g, _ := s.GetGrant(ctx, "g-pending-rev")
	if g.EphemeralUsername == "" {
		t.Error("ephemeral columns cleared on a pending revoke; must wait for done")
	}
}

// TestReconcileProvisionedGrants_NoIntent: an APPROVED grant with no provision
// intent (never claimed) is left untouched.
func TestReconcileProvisionedGrants_NoIntent(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: "g-noclaim", UserID: "u-1", BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.GrantApproved, RequestedAt: time.Now(), ClaimExpiresAt: &exp,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	_ = s.CreateGrant(ctx, g)

	if n := ReconcileProvisionedGrants(ctx, s, time.Hour, quietLogger()); n != 0 {
		t.Fatalf("reconciled count = %d, want 0", n)
	}
}
