// Package notify abstracts "tell somebody a grant moved" so the handler
// doesn't carry mail/webhook/HMAC plumbing alongside its HTTP and state-machine
// concerns. A Notifier is called inline at each lifecycle transition; actual
// delivery (mail, webhook, …) happens asynchronously inside the impl.
//
// A nil Notifier is NOT valid — callers should use Noop when no notifications
// are configured. Keeping a non-nil contract lets handlers skip `if n != nil`
// guards at every call site.
package notify

import (
	"context"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// Event bundles a grant with the adjacent context a notifier needs to render
// a human-readable message. User / Backend are advisory — impls may log or
// skip when missing (e.g. webhook delivery uses the raw grant fields).
type Event struct {
	Grant   domain.Grant
	User    domain.User
	Backend domain.Backend
}

// Notifier is the single fan-out seam for grant-lifecycle notifications.
// Every method is fire-and-forget from the handler's perspective: impls do
// their own timeouts, retries, and error handling. Returning an error from
// any method is advisory — handlers log it but never propagate to the HTTP
// response (grant state must not depend on notification delivery).
type Notifier interface {
	// OnGrantCreated is invoked after a PENDING grant lands in the store.
	// Typical use: notify the validator that a request needs their attention.
	OnGrantCreated(ctx context.Context, e Event) error
	// OnValidatorApproved fires after the first gate flips PENDING → VALIDATOR_APPROVED.
	// Typical use: notify admins that the second gate is open.
	OnValidatorApproved(ctx context.Context, e Event) error
	// OnApproved fires after the second gate flips VALIDATOR_APPROVED → APPROVED.
	// Typical use: tell the requester their claim window is open.
	OnApproved(ctx context.Context, e Event) error
	// OnDenied fires after the grant lands in the DENIED terminal state.
	// Typical use: tell the requester the decision.
	OnDenied(ctx context.Context, e Event) error
	// Wait blocks until any in-flight background deliveries complete.
	// Tests call this before assertions; production shutdown calls it before exit.
	Wait()
}

// Noop is the zero-behaviour Notifier — safe default when no channel is wired.
type Noop struct{}

func (Noop) OnGrantCreated(context.Context, Event) error    { return nil }
func (Noop) OnValidatorApproved(context.Context, Event) error { return nil }
func (Noop) OnApproved(context.Context, Event) error        { return nil }
func (Noop) OnDenied(context.Context, Event) error          { return nil }
func (Noop) Wait()                                          {}
