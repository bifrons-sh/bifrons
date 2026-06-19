package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
)

// EntraMetrics is a lock-free counter bundle the router surfaces through the
// obs sidecar. Keeping counters here lets the notifier own its own
// observability and the HTTP layer stay oblivious beyond two Inc* calls for
// flow events (policy-rejected / validator-lookup-failed).
type EntraMetrics struct {
	emailSent             atomic.Uint64
	emailFailed           atomic.Uint64
	emailSentValidator    atomic.Uint64
	emailSentAdmin        atomic.Uint64
	emailSentOutcome      atomic.Uint64
	validatorLookupFailed atomic.Uint64
	policyRejected        atomic.Uint64
}

// NewEntraMetrics returns a zero-valued counter bundle.
func NewEntraMetrics() *EntraMetrics { return &EntraMetrics{} }

// Snapshot returns (emailSent, emailFailed, policyRejected, validatorLookupFailed).
// Order matches the obs.EntraStatsFn signature the obs sidecar expects.
func (m *EntraMetrics) Snapshot() (sent, failed, rejected, valFail uint64) {
	if m == nil {
		return 0, 0, 0, 0
	}
	return m.emailSent.Load(), m.emailFailed.Load(), m.policyRejected.Load(), m.validatorLookupFailed.Load()
}

// SnapshotByKind returns per-kind email counters: validator_request, admin_request, outcome.
func (m *EntraMetrics) SnapshotByKind() (validator, admin, outcome uint64) {
	if m == nil {
		return 0, 0, 0
	}
	return m.emailSentValidator.Load(), m.emailSentAdmin.Load(), m.emailSentOutcome.Load()
}

// IncValidatorLookupFailed — called by the handler when validator resolution fails.
func (m *EntraMetrics) IncValidatorLookupFailed() {
	if m != nil {
		m.validatorLookupFailed.Add(1)
	}
}

// IncPolicyRejected — called by the handler when the trio policy denies a request.
func (m *EntraMetrics) IncPolicyRejected() {
	if m != nil {
		m.policyRejected.Add(1)
	}
}

// T2Lookup resolves the recipients notified when gate2 (the admin tier /
// second dual-gate phase) fires for a given backend. Injected by the
// router — usually backed by the portal store
// (store.ListGroupMembers on the backend's T2 group). Returning an empty
// slice is fine; the notifier just skips the send. Per-backend rather
// than global because each backend has its own admin tier
// (specs/phase-7-validation-ui.md §7.8.1).
type T2Lookup func(ctx context.Context, backend domain.Backend) ([]string, error)

// EntraMailNotifier sends mail via the Microsoft Graph /sendMail endpoint on
// each lifecycle transition, with per-kind metrics. Async + best-effort:
// delivery failures are logged, never raised.
type EntraMailNotifier struct {
	client    entra.Client
	sender    string
	publicURL string
	// t2Mailbox is a single mailbox appended to every gate2 notification
	// regardless of backend — a last-resort reachability safety net.
	t2Mailbox string
	// t2Lookup resolves per-backend T2 recipients (members of the
	// backend's T2 group). Nil ⇒ skip the lookup, rely on t2Mailbox only.
	t2Lookup T2Lookup
	metrics  *EntraMetrics
	logger   *slog.Logger
	wg       sync.WaitGroup
}

// EntraConfig bundles the Entra mailer wiring.
type EntraConfig struct {
	Client    entra.Client
	Sender    string
	PublicURL string
	// T2Mailbox is a single mailbox appended to every gate2 notification.
	// Intended as a last-resort reachability fallback; the per-backend
	// T2Lookup is the primary recipient source.
	T2Mailbox string
	// T2Lookup resolves per-backend gate2 recipients on demand (usually
	// members of the backend's T2 group). Nil ⇒ skip.
	T2Lookup T2Lookup
	Metrics  *EntraMetrics
	Logger   *slog.Logger
}

// NewEntraMailNotifier builds a notifier if both client and sender are set;
// otherwise returns nil so the router can skip wiring it without branching.
func NewEntraMailNotifier(cfg EntraConfig) *EntraMailNotifier {
	if cfg.Client == nil || cfg.Sender == "" {
		return nil
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &EntraMailNotifier{
		client:    cfg.Client,
		sender:    cfg.Sender,
		publicURL: cfg.PublicURL,
		t2Mailbox: cfg.T2Mailbox,
		t2Lookup:  cfg.T2Lookup,
		metrics:   cfg.Metrics,
		logger:    logger,
	}
}

// OnGrantCreated emails the approver (typically the requester's validator).
// Skipped when ApproverHint is empty — the handler resolves the validator
// address before the notify call, so a missing hint is a deliberate "no
// validator configured" signal.
func (n *EntraMailNotifier) OnGrantCreated(_ context.Context, e Event) error {
	if e.Grant.ApproverHint == "" {
		return nil
	}
	subject := fmt.Sprintf("Access request: %s on %s", e.Grant.Role, e.Backend.Name)
	body := fmt.Sprintf("User %s requested %s access on %s (%s).\nReason: %s\nGrant ID: %s\n%s",
		displayOr(e.User), e.Grant.Role, e.Backend.Name, e.Backend.Address(), e.Grant.Reason, e.Grant.ID,
		n.reviewLink("validator", "PENDING"))
	n.send(e.Grant.ID, []string{e.Grant.ApproverHint}, subject, body, kindValidatorRequest)
	return nil
}

// OnValidatorApproved notifies admin reachability target(s) that the second
// gate is open. Resolves the group-member list synchronously (one Graph call)
// before dispatching the mail goroutine — failures to resolve just log and
// fall back to the single-mailbox address.
func (n *EntraMailNotifier) OnValidatorApproved(ctx context.Context, e Event) error {
	recipients := n.t2Recipients(ctx, e.Backend)
	if len(recipients) == 0 {
		n.logger.Warn("entra_t2_recipients_empty", "grant_id", e.Grant.ID, "backend_id", e.Grant.BackendID)
		return nil
	}
	// Prefer the human-readable backend name when the handler populated the
	// Event; fall back to the id if upstream didn't stamp it (e.g. webhook
	// path that bypasses the create handler).
	backendLabel := e.Backend.Name
	if backendLabel == "" {
		backendLabel = e.Grant.BackendID
	}
	subject := fmt.Sprintf("Admin approval needed: %s on backend %s", e.Grant.Role, backendLabel)
	body := fmt.Sprintf("Grant %s is awaiting admin approval (validator %s already approved).\nReason: %s\n%s",
		e.Grant.ID, e.Grant.T1ApprovedBy, e.Grant.Reason,
		// Operator default scope is "all" (no scope param), which is exactly
		// the right landing for the admin gate — they want the full
		// VALIDATOR_APPROVED queue, not just their own requests.
		n.reviewLink("", "VALIDATOR_APPROVED"))
	n.send(e.Grant.ID, recipients, subject, body, kindAdminRequest)
	return nil
}

// OnApproved emails the requester that the claim window is open.
func (n *EntraMailNotifier) OnApproved(_ context.Context, e Event) error {
	return n.sendOutcome(e, true)
}

// OnDenied emails the requester that the grant was denied.
func (n *EntraMailNotifier) OnDenied(_ context.Context, e Event) error {
	return n.sendOutcome(e, false)
}

// Wait blocks until in-flight mail goroutines finish.
func (n *EntraMailNotifier) Wait() { n.wg.Wait() }

// Stop is a no-op: mail deliveries have no cancellable retry backoff (each send
// is bounded by the entra.Client's own HTTP timeout), so there is nothing to
// interrupt — shutdown relies on Wait plus those per-call timeouts.
func (n *EntraMailNotifier) Stop() {}

func (n *EntraMailNotifier) sendOutcome(e Event, approved bool) error {
	// We address the requester via their session subject — to lazily resolve
	// the email without a Graph round-trip, look up the portal user by
	// requested-by string when it looks like a subject; absent that we skip.
	to := e.Grant.RequestedBy
	if to == "" || !strings.Contains(to, "@") {
		if e.Grant.RequestedBy != "" {
			if u, err := n.client.GetUser(context.Background(), e.Grant.RequestedBy); err == nil {
				to = firstNonEmpty(u.Mail, u.UserPrincipalName)
			}
		}
	}
	if to == "" {
		n.logger.Info("entra_outcome_skipped", "grant_id", e.Grant.ID, "reason", "no_recipient")
		return nil
	}
	verdict := "approved"
	if !approved {
		verdict = "denied"
	}
	subject := fmt.Sprintf("Access request %s: %s", verdict, e.Grant.ID)
	// Outcome mails go to the requester — landing on their own grants view
	// (default scope) is correct, no scope param needed.
	body := fmt.Sprintf("Your access request %s was %s.\n%s", e.Grant.ID, verdict,
		n.reviewLink("", ""))
	n.send(e.Grant.ID, []string{to}, subject, body, kindOutcome)
	return nil
}

// reviewLink returns a "Review: <url>" footer line pointing the recipient at
// the appropriate SPA grants view. Empty when publicURL isn't configured so
// self-hosted / dev setups don't emit dangling URLs.
//
// scope selects the SPA tab the recipient lands on:
//   - "validator" — "Awaiting me" tab, for the T1 validator who needs to act.
//   - ""          — default tab (operators see all, requesters see their own).
//
// statusHint pre-filters the list when non-empty.
func (n *EntraMailNotifier) reviewLink(scope, statusHint string) string {
	if n.publicURL == "" {
		return ""
	}
	base := strings.TrimRight(n.publicURL, "/") + "/ui/#/grants"
	params := []string{}
	if scope != "" {
		params = append(params, "scope="+scope)
	}
	if statusHint != "" {
		params = append(params, "status="+statusHint)
	}
	if len(params) > 0 {
		base += "?" + strings.Join(params, "&")
	}
	return "\nReview: " + base + "\n"
}

// t2Recipients honours the mailbox flag and any T2Lookup wired; returns
// the dedup'd union for the given backend. Lookup failures are logged,
// never fatal — the single mailbox (when set) keeps the notification
// reachable.
func (n *EntraMailNotifier) t2Recipients(ctx context.Context, backend domain.Backend) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(addr string) {
		if addr == "" {
			return
		}
		k := strings.ToLower(addr)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, addr)
	}
	if n.t2Mailbox != "" {
		add(n.t2Mailbox)
	}
	if n.t2Lookup != nil {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		recips, err := n.t2Lookup(lctx, backend)
		cancel()
		if err != nil {
			n.logger.Warn("t2_lookup_failed", "backend_id", backend.ID, "err_class", err.Error())
		}
		for _, r := range recips {
			add(r)
		}
	}
	return out
}

// kind tags a send for per-kind metrics.
type kind string

const (
	kindValidatorRequest kind = "validator_request"
	kindAdminRequest     kind = "admin_request"
	kindOutcome          kind = "outcome"
)

// send dispatches the mail on a background goroutine with a 10s deadline.
// All error handling is internal — the lifecycle doesn't depend on delivery.
func (n *EntraMailNotifier) send(grantID string, to []string, subject, textBody string, k kind) {
	if len(to) == 0 {
		return
	}
	link := ""
	if n.publicURL != "" {
		link = strings.TrimRight(n.publicURL, "/") + "/ui/grants/" + grantID
	}
	text := textBody
	if link != "" {
		text += link + "\n"
	}
	var html string
	if link != "" {
		html = fmt.Sprintf(
			`<p>%s</p><p><a href="%s">Open in portal</a></p>`,
			escapeHTML(textBody), escapeHTML(link),
		)
	}
	msg := entra.MailMessage{To: to, Subject: subject, TextBody: text, HTMLBody: html}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.client.SendMail(ctx, n.sender, msg); err != nil {
			if n.metrics != nil {
				n.metrics.emailFailed.Add(1)
			}
			n.logger.Warn("entra_email_failed", "grant_id", grantID, "kind", string(k), "to_domain", domainPart(to[0]))
			return
		}
		if n.metrics != nil {
			n.metrics.emailSent.Add(1)
			switch k {
			case kindValidatorRequest:
				n.metrics.emailSentValidator.Add(1)
			case kindAdminRequest:
				n.metrics.emailSentAdmin.Add(1)
			case kindOutcome:
				n.metrics.emailSentOutcome.Add(1)
			}
		}
		n.logger.Info("entra_email_sent", "grant_id", grantID, "kind", string(k), "to_count", len(to))
	}()
}

var _ Notifier = (*EntraMailNotifier)(nil)
