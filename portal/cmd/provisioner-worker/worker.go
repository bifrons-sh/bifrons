package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// error_class closed enum (spec §8.4.2). Surfaced to the requester via the
// outbox so the UI can offer "retry later" vs "contact admin" without parsing
// free text. Verbose driver output never reaches these columns — it goes to the
// structured log keyed by intent_id.
const (
	classTransientNetwork    = "transient_network"
	classTransientExhausted  = "transient_exhausted"
	classTerminalPermission  = "terminal_permission"
	classTerminalSyntax      = "terminal_syntax"
	classTargetUnreachable   = "terminal_target_unreachable"
	classTerminalIntentInval = "terminal_intent_invalid"
)

// maxTransientAttempts bounds in-worker retry on a transient error before the
// intent is failed as transient_exhausted. Kept small: DDL on a healthy backend
// is sub-second, so a few jittered attempts cover a brief network blip without
// holding the lease for minutes.
const maxTransientAttempts = 3

// provisionerFactory builds a Provisioner for a backend type, wired to the
// worker's config-backed DBA lookup. Injected so tests substitute a fake.
type provisionerFactory func(bt ephemeral.BackendType) (ephemeral.Provisioner, bool)

// keyFn derives the deterministic ephemeral credential for an intent id.
type keyFn func(intentID string) (user, pass string)

// Worker is the engine: claim intents from the outbox, run DDL via the
// ephemeral provisioners, write encrypted results back, and signal the portal.
// All collaborators are injected so processIntent is unit-testable without a
// real backend.
type Worker struct {
	cfg      Config
	store    store.Store
	notifier provisioning.Notifier
	factory  provisionerFactory
	derive   keyFn
	logger   *slog.Logger

	// metrics is the optional Workstream F (spec §8.8) consumer-side counter
	// handle. nil is a safe no-op so the unit tests construct a Worker without
	// it and the loop stays unchanged.
	metrics *workerMetrics

	// version is the build-time Version, threaded from main, stamped on each
	// liveness heartbeat. Empty is fine — the column is omitempty.
	version string
	// prober pings a backend's reachability for the liveness heartbeat. nil
	// disables probing (a beat then ships an empty Health slice); tests inject a
	// fake so the loop never dials a real DB.
	prober prober
}

// NewWorker wires the engine. store MUST be the encrypting wrapper so results
// land encrypted under the shared key.
func NewWorker(cfg Config, st store.Store, n provisioning.Notifier, f provisionerFactory, derive keyFn, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{cfg: cfg, store: st, notifier: n, factory: f, derive: derive, logger: logger}
}

// WithMetrics attaches the Workstream F consumer-side metrics handle and
// returns the Worker for chaining. Kept off NewWorker so the unit tests build a
// metric-free Worker unchanged.
func (w *Worker) WithMetrics(m *workerMetrics) *Worker {
	w.metrics = m
	return w
}

// WithVersion stamps the build-time Version onto each liveness heartbeat.
// Chainable; kept off NewWorker so existing unit-test construction is unchanged.
func (w *Worker) WithVersion(v string) *Worker {
	w.version = v
	return w
}

// WithProber injects the reachability prober the liveness heartbeat uses.
// Chainable; nil leaves probing disabled so a metric/probe-free Worker is valid.
func (w *Worker) WithProber(p prober) *Worker {
	w.prober = p
	return w
}

// deriveCreds implements the HMAC-SHA256 derivation from spec §8.4:
//
//	seed = HMAC-SHA256(workerKey, intentID) // 32 bytes
//	user = "ap_" + hex(seed[:8])            // 16 hex chars, fits every engine
//	pass = base64url(seed[8:32])            // 24 bytes, RFC 4648 §5
//
// Pure and deterministic: the same (workerKey, intentID) always yields the same
// credential. That is what makes a lease-takeover converge — worker B re-derives
// exactly what worker A would have, then the idempotent DDL repairs the backend
// to match the outbox.
func deriveCreds(workerKey []byte, intentID string) (user, pass string) {
	mac := hmac.New(sha256.New, workerKey)
	mac.Write([]byte(intentID))
	seed := mac.Sum(nil) // 32 bytes
	user = "ap_" + hex.EncodeToString(seed[:8])
	// base64url without padding keeps the password to a clean token with no
	// characters needing SQL-literal escaping beyond what the quoters handle.
	pass = base64.RawURLEncoding.EncodeToString(seed[8:32])
	return user, pass
}

// processIntent runs a single outbox row to a terminal state. It resolves the
// backend's non-secret host/port/type from the store, builds the
// ProvisionRequest, dispatches Provision/Revoke, and writes the result back:
//   - success → CompleteIntent (creds for provision, empty for revoke) + NOTIFY
//   - terminal error → FailIntent with the classified error_class
//   - transient error → bounded retry, then FailIntent transient_exhausted
//
// It returns the error it last saw (nil on success) for logging; the outbox row
// is already updated by the time it returns.
func (w *Worker) processIntent(ctx context.Context, in domain.Intent) error {
	log := w.logger.With(slog.String("intent_id", in.ID), slog.String("kind", string(in.Kind)))

	// H4/H5: keep the lease alive for the whole life of this intent. The
	// store-side drain claims a batch under a single lease and processes
	// serially, so without a per-intent heartbeat the tail rows sit
	// leased-but-untouched and a sibling worker could reclaim a row we're still
	// (slowly) executing → two workers running the same DDL. A background ticker
	// at leaseTTL/3 covers a slow-but-progressing op; it stops when this
	// function returns. withRetry's between-attempt heartbeat stays as a belt-
	// and-braces signal but is no longer the only one.
	stopHB := w.startLeaseHeartbeat(ctx, in.ID, log)
	defer stopHB()

	backend, err := w.store.GetBackend(ctx, in.BackendID)
	if err != nil {
		// The intent points at a backend that no longer exists — terminal,
		// no retry. The grant referenced something we can't act on.
		return w.fail(ctx, in, classTerminalIntentInval, "", log, err)
	}

	bt := ephemeral.MapBackendType(backend.Type)
	prov, ok := w.factory(bt)
	if !ok {
		return w.fail(ctx, in, classTerminalIntentInval, "", log, fmt.Errorf("no provisioner for backend type %q", backend.Type))
	}

	switch in.Kind {
	case domain.IntentProvision:
		return w.runProvision(ctx, in, backend, prov, log)
	case domain.IntentRevoke:
		return w.runRevoke(ctx, in, backend, prov, log)
	default:
		return w.fail(ctx, in, classTerminalIntentInval, "", log, fmt.Errorf("unknown intent kind %q", in.Kind))
	}
}

// runProvision derives the deterministic credential, runs the idempotent
// Provision DDL (with bounded transient retry), and persists the encrypted
// result.
func (w *Worker) runProvision(ctx context.Context, in domain.Intent, backend domain.Backend, prov ephemeral.Provisioner, log *slog.Logger) error {
	// H3 (spec §8.6 "revoke wins"): a revoke that races an in-flight provision
	// must win. Re-read the grant immediately before the CREATE; if it already
	// reached a terminal state (REVOKED/DENIED/EXPIRED) the operator decision
	// has superseded this provision — skip the DDL and complete the intent with
	// EMPTY result creds so no orphan ap_<hmac> account is left behind. The
	// sibling revoke intent (ordered ahead of provision in the claim batch) drops
	// anything that did slip through.
	if g, gerr := w.store.GetGrant(ctx, in.GrantID); gerr == nil && grantTerminal(g.Status) {
		log.Info("provision_skipped_grant_terminal", slog.String("grant_status", string(g.Status)))
		if cerr := w.store.CompleteIntent(ctx, in.ID, w.cfg.WorkerID, "", ""); cerr != nil {
			return fmt.Errorf("complete superseded provision intent: %w", cerr)
		}
		w.metrics.IncProcessed(string(in.Kind), "done")
		w.signalResult(ctx, in.ID, log)
		return nil
	}

	user, pass := w.derive(in.ID)
	req := ephemeral.ProvisionRequest{
		BackendType: ephemeral.MapBackendType(backend.Type),
		BackendID:   in.BackendID,
		Host:        backend.Host,
		Port:        backend.Port,
		Database:    in.Database,
		Role:        in.Role,
		GrantID:     in.GrantID,
		TTL:         time.Duration(in.RequestedDurationSec) * time.Second,
		// Explicit deterministic creds → idempotent provisioning path (spec §8.4).
		Username: user,
		Password: pass,
	}

	err := w.withRetry(ctx, in, log, func(c context.Context) error {
		_, perr := prov.Provision(c, req)
		return perr
	})
	if err != nil {
		return err
	}

	// CompleteIntent writes through the encrypting store so the portal can
	// decrypt the deterministic creds on /claim under the shared key.
	if cerr := w.store.CompleteIntent(ctx, in.ID, w.cfg.WorkerID, user, pass); cerr != nil {
		return fmt.Errorf("complete provision intent: %w", cerr)
	}
	w.metrics.IncProcessed(string(in.Kind), "done")
	w.signalResult(ctx, in.ID, log)
	log.Info("provision_done")
	return nil
}

// runRevoke drops the target user. Revoke is idempotent at the engine level, so
// a missing user is success. Result columns stay empty on revoke.
//
// When TargetUsername is empty the grant was revoked/denied before any creds
// were recorded (HIGH-1): the sibling provision intent may still have run and
// created ap_<hmac>. We re-derive that exact name from the deterministic sibling
// provision intent id — the same derivation runProvision would use — and DROP
// USER IF EXISTS it. A no-op if the user was never created.
func (w *Worker) runRevoke(ctx context.Context, in domain.Intent, backend domain.Backend, prov ephemeral.Provisioner, log *slog.Logger) error {
	target := in.TargetUsername
	if target == "" {
		target, _ = w.derive(domain.IntentID(in.GrantID, domain.IntentProvision))
		log.Info("revoke_derived_sibling_username")
	}
	acct := ephemeral.ProvisionedAccount{
		Username:    target,
		BackendID:   in.BackendID,
		BackendType: ephemeral.MapBackendType(backend.Type),
		Host:        backend.Host,
		Port:        backend.Port,
		Database:    in.Database,
		GrantID:     in.GrantID,
	}
	err := w.withRetry(ctx, in, log, func(c context.Context) error {
		return prov.Revoke(c, acct)
	})
	if err != nil {
		return err
	}
	if cerr := w.store.CompleteIntent(ctx, in.ID, w.cfg.WorkerID, "", ""); cerr != nil {
		return fmt.Errorf("complete revoke intent: %w", cerr)
	}
	w.metrics.IncProcessed(string(in.Kind), "done")
	w.signalResult(ctx, in.ID, log)
	log.Info("revoke_done")
	return nil
}

// withRetry runs op, retrying transient failures up to maxTransientAttempts
// with a jittered backoff and a lease heartbeat between attempts (so the work
// isn't reclaimed mid-retry). On a terminal error it fails the intent
// immediately; on exhausting transient retries it fails as transient_exhausted.
// On success it returns nil and the row is NOT yet completed (the caller does
// that). On any failure the row is already marked failed and the error returned.
func (w *Worker) withRetry(ctx context.Context, in domain.Intent, log *slog.Logger, op func(context.Context) error) error {
	var lastErr error
	for attempt := 0; attempt < maxTransientAttempts; attempt++ {
		if attempt > 0 {
			// Heartbeat so a slow-but-progressing retry keeps its lease.
			if herr := w.store.HeartbeatIntentLease(ctx, in.ID, w.cfg.WorkerID, w.cfg.LeaseTTL); herr != nil {
				log.Warn("lease_heartbeat_failed", slog.Any("error", herr))
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		ddlStart := time.Now()
		err := w.runWithDeadline(ctx, op)
		// Observe every DDL round-trip, success or fail — the latency of a
		// rejected CREATE is as interesting for §8.8 dashboards as a slow one.
		w.metrics.ObserveDDL(time.Since(ddlStart))
		if err == nil {
			return nil
		}
		lastErr = err
		class := classify(err)
		if class != classTransientNetwork {
			// Terminal — no retry.
			return w.fail(ctx, in, class, redactDetail(err), log, err)
		}
		log.Warn("transient_error", slog.Int("attempt", attempt+1), slog.String("error_class", class))
	}
	return w.fail(ctx, in, classTransientExhausted, redactDetail(lastErr), log, lastErr)
}

// fail records the terminal outcome on the outbox row and logs the verbose
// error under intent_id (never into the row). It always returns origErr so the
// caller can propagate it for top-level logging.
func (w *Worker) fail(ctx context.Context, in domain.Intent, class, detail string, log *slog.Logger, origErr error) error {
	if ferr := w.store.FailIntent(ctx, in.ID, w.cfg.WorkerID, class, detail, in.RetryCount+1); ferr != nil {
		log.Error("fail_intent_persist_failed", slog.Any("error", ferr))
	}
	w.metrics.IncProcessed(string(in.Kind), "failed")
	w.signalResult(ctx, in.ID, log)
	log.Warn("intent_failed", slog.String("error_class", class), slog.Any("error", origErr))
	return origErr
}

// signalResult notifies the portal that a terminal result is available. Best
// effort: on poll-only stores Notify is a no-op and the portal's catch-up
// reconciler still finds the row.
func (w *Worker) signalResult(ctx context.Context, intentID string, log *slog.Logger) {
	if err := w.notifier.Notify(ctx, provisioning.ChannelProvisionResult, intentID); err != nil {
		log.Warn("notify_result_failed", slog.Any("error", err))
	}
}

// grantTerminal reports whether a grant has reached a state in which no
// provision should proceed (operator revoked/denied it, or it expired).
func grantTerminal(s domain.GrantStatus) bool {
	switch s {
	case domain.GrantRevoked, domain.GrantDenied, domain.GrantExpired:
		return true
	default:
		return false
	}
}

// startLeaseHeartbeat extends this intent's lease on a background ticker for the
// duration of processIntent, returning a stop func the caller defers. The cadence
// is leaseTTL/3 so two heartbeats are missed before the lease lapses — enough
// slack for a transient store blip without letting a dead worker hold the row.
// A zero/short TTL falls back to a 1s floor so the ticker is always valid.
func (w *Worker) startLeaseHeartbeat(ctx context.Context, intentID string, log *slog.Logger) func() {
	interval := w.cfg.LeaseTTL / 3
	if interval < time.Second {
		interval = time.Second
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				if herr := w.store.HeartbeatIntentLease(ctx, intentID, w.cfg.WorkerID, w.cfg.LeaseTTL); herr != nil {
					log.Warn("lease_heartbeat_failed", slog.Any("error", herr))
				}
			}
		}
	}()
	return func() { close(done) }
}

// runWithDeadline runs a single DDL op under a per-op timeout (C2) so a wedged
// backend fails fast as transient_network instead of stalling the serial drain
// indefinitely. The deadline is the smaller of the configured ddl-timeout and
// the remaining lease budget (leaseTTL minus a margin), so the op can never
// outlive the lease that protects the row from a concurrent worker.
func (w *Worker) runWithDeadline(ctx context.Context, op func(context.Context) error) error {
	d := w.ddlDeadline()
	if d <= 0 {
		return op(ctx)
	}
	opCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return op(opCtx)
}

// ddlDeadline returns the per-DDL timeout: min(ddl-timeout, leaseTTL-margin).
// Keeping it under the lease guarantees a hung op is abandoned before the lease
// could be reclaimed by a peer. A non-positive result disables the bound.
func (w *Worker) ddlDeadline() time.Duration {
	const leaseMargin = 5 * time.Second
	d := w.cfg.DDLTimeout
	if w.cfg.LeaseTTL > 0 {
		if budget := w.cfg.LeaseTTL - leaseMargin; budget > 0 && (d <= 0 || budget < d) {
			d = budget
		}
	}
	return d
}

// classify maps a driver error to the closed error_class enum (spec §8.4.2).
// Conservative: anything not recognised as terminal is treated as transient so
// the bounded retry gets a chance — a misclassified terminal error just costs a
// few wasted attempts, whereas a misclassified transient error would strand the
// grant on the first blip.
//
// NOTE: matching is brittle substring matching against lower-cased driver text,
// which is locale/driver-version sensitive. It is intentionally kept simple
// (no per-driver SQLSTATE table) for the PoC; revisit if a backend's wording
// drifts and a terminal error starts being retried as transient.
func classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ephemeral.ErrNoDBACredential) {
		// This worker isn't authorised for the backend / cred is missing — the
		// operator must fix config; retrying won't help.
		return classTerminalPermission
	}
	msg := strings.ToLower(err.Error())
	switch {
	case containsAny(msg, "permission denied", "must be superuser", "access denied", "not allowed", "privilege"):
		return classTerminalPermission
	case containsAny(msg, "syntax", "invalid", "unsupported", "password policy"):
		return classTerminalSyntax
	case containsAny(msg, "no such host", "name resolution", "unknown host", "certificate", "tls", "x509"):
		return classTargetUnreachable
	case containsAny(msg, "timeout", "i/o timeout", "connection refused", "reset by peer", "broken pipe", "dial ", "eof"):
		return classTransientNetwork
	default:
		// Unknown — assume transient and let the bounded retry decide.
		return classTransientNetwork
	}
}

// hostishRE matches the network locators a driver error commonly carries —
// IPv4 (optionally :port), host:port pairs, and dotted hostnames — so they can
// be scrubbed from error_detail (spec §8.4.2 forbids leaking the target host).
var hostishRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+(?::\d+)?\b`)

// redactDetail produces a single-line, ≤120-char, hostname-free, DDL-keyword-
// free summary safe for the error_detail column (spec §8.4.2 hygiene rule).
// Verbose output belongs in the structured log, not the row.
func redactDetail(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// Collapse to a single line.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	// Strip DDL/DML keywords so a leaked SQL fragment can't ride along.
	for _, kw := range []string{"CREATE", "DROP", "GRANT", "REVOKE", "ALTER", "REASSIGN"} {
		s = caseInsensitiveStrip(s, kw)
	}
	// Scrub host/IP locators — the column must not reveal which backend or
	// network endpoint produced the error.
	s = hostishRE.ReplaceAllString(s, "[host]")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// caseInsensitiveStrip removes every case-insensitive occurrence of kw from s.
func caseInsensitiveStrip(s, kw string) string {
	for {
		idx := strings.Index(strings.ToUpper(s), kw)
		if idx < 0 {
			return s
		}
		s = s[:idx] + s[idx+len(kw):]
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// backoff returns an exponential-ish delay for retry attempt n (1-indexed-ish).
// Small caps keep a held lease short.
func backoff(attempt int) time.Duration {
	d := time.Duration(attempt) * 250 * time.Millisecond
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}
