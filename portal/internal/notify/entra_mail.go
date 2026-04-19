package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/portal/internal/entra"
)

// EntraMetrics is a lock-free counter bundle the router surfaces through the
// obs sidecar. Keeping counters here lets the notifier own its own
// observability and the HTTP layer stay oblivious beyond two Inc* calls for
// flow events (policy-rejected / manager-lookup-failed).
type EntraMetrics struct {
	emailSent           atomic.Uint64
	emailFailed         atomic.Uint64
	emailSentManager    atomic.Uint64
	emailSentAdmin      atomic.Uint64
	emailSentOutcome    atomic.Uint64
	managerLookupFailed atomic.Uint64
	policyRejected      atomic.Uint64
}

// NewEntraMetrics returns a zero-valued counter bundle.
func NewEntraMetrics() *EntraMetrics { return &EntraMetrics{} }

// Snapshot returns the aggregate counters (sent, failed, policyRejected, managerLookupFailed).
// Order matches the legacy obs sidecar contract so callers don't need to change.
func (m *EntraMetrics) Snapshot() (sent, failed, rejected, mgrFail uint64) {
	if m == nil {
		return 0, 0, 0, 0
	}
	return m.emailSent.Load(), m.emailFailed.Load(), m.policyRejected.Load(), m.managerLookupFailed.Load()
}

// SnapshotByKind returns per-kind email counters: manager_request, admin_request, outcome.
func (m *EntraMetrics) SnapshotByKind() (manager, admin, outcome uint64) {
	if m == nil {
		return 0, 0, 0
	}
	return m.emailSentManager.Load(), m.emailSentAdmin.Load(), m.emailSentOutcome.Load()
}

// IncManagerLookupFailed — called by the handler when manager resolution fails.
func (m *EntraMetrics) IncManagerLookupFailed() {
	if m != nil {
		m.managerLookupFailed.Add(1)
	}
}

// IncPolicyRejected — called by the handler when the trio policy denies a request.
func (m *EntraMetrics) IncPolicyRejected() {
	if m != nil {
		m.policyRejected.Add(1)
	}
}

// EntraMailNotifier sends mail via the Microsoft Graph /sendMail endpoint on
// each lifecycle transition, with per-kind metrics. Async + best-effort:
// delivery failures are logged, never raised.
type EntraMailNotifier struct {
	client            entra.Client
	sender            string
	publicURL         string
	adminMailbox      string
	adminGroupID      string
	metrics           *EntraMetrics
	logger            *slog.Logger
	wg                sync.WaitGroup
}

// EntraConfig bundles the Entra mailer wiring.
type EntraConfig struct {
	Client       entra.Client
	Sender       string
	PublicURL    string
	AdminMailbox string
	AdminGroupID string
	Metrics      *EntraMetrics
	Logger       *slog.Logger
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
		client:       cfg.Client,
		sender:       cfg.Sender,
		publicURL:    cfg.PublicURL,
		adminMailbox: cfg.AdminMailbox,
		adminGroupID: cfg.AdminGroupID,
		metrics:      cfg.Metrics,
		logger:       logger,
	}
}

// OnGrantCreated emails the approver (typically the requester's manager).
// Skipped when ApproverHint is empty — the handler resolves the manager
// address before the notify call, so a missing hint is a deliberate "no
// manager configured" signal.
func (n *EntraMailNotifier) OnGrantCreated(_ context.Context, e Event) error {
	if e.Grant.ApproverHint == "" {
		return nil
	}
	subject := fmt.Sprintf("Access request: %s on %s", e.Grant.Role, e.Backend.Name)
	body := fmt.Sprintf("User %s requested %s access on %s (%s).\nReason: %s\nGrant ID: %s\n",
		displayOr(e.User), e.Grant.Role, e.Backend.Name, e.Backend.Address(), e.Grant.Reason, e.Grant.ID)
	n.send(e.Grant.ID, []string{e.Grant.ApproverHint}, subject, body, kindManagerRequest)
	return nil
}

// OnManagerApproved notifies admin reachability target(s) that the second
// gate is open. Resolves the group-member list synchronously (one Graph call)
// before dispatching the mail goroutine — failures to resolve just log and
// fall back to the single-mailbox address.
func (n *EntraMailNotifier) OnManagerApproved(ctx context.Context, e Event) error {
	recipients := n.adminRecipients(ctx)
	if len(recipients) == 0 {
		n.logger.Warn("entra_admin_recipients_empty", "grant_id", e.Grant.ID)
		return nil
	}
	subject := fmt.Sprintf("Admin approval needed: %s on backend %s", e.Grant.Role, e.Grant.BackendID)
	body := fmt.Sprintf("Grant %s is awaiting admin approval (manager %s already approved).\nReason: %s\n",
		e.Grant.ID, e.Grant.ManagerApprovedBy, e.Grant.Reason)
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
	body := fmt.Sprintf("Your access request %s was %s.\n", e.Grant.ID, verdict)
	n.send(e.Grant.ID, []string{to}, subject, body, kindOutcome)
	return nil
}

// adminRecipients honours the single-mailbox flag and the group-id flag;
// returns the dedup'd union. Group-resolution failures are logged, never fatal.
func (n *EntraMailNotifier) adminRecipients(ctx context.Context) []string {
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
	if n.adminMailbox != "" {
		add(n.adminMailbox)
	}
	if n.adminGroupID != "" {
		gctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		members, err := n.client.GroupMembers(gctx, n.adminGroupID)
		cancel()
		if err != nil {
			n.logger.Warn("entra_admin_group_resolve_failed", "group_id", n.adminGroupID, "err_class", err.Error())
		}
		for _, m := range members {
			add(firstNonEmpty(m.Mail, m.UserPrincipalName))
		}
	}
	return out
}

// kind tags a send for per-kind metrics.
type kind string

const (
	kindManagerRequest kind = "manager_request"
	kindAdminRequest   kind = "admin_request"
	kindOutcome        kind = "outcome"
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
			case kindManagerRequest:
				n.metrics.emailSentManager.Add(1)
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
