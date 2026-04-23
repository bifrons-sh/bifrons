package notify

import (
	"context"
	"errors"
	"strings"
)

// Multi fans each event out to every wrapped Notifier. Errors from impls are
// collected and joined so the handler sees a single error per call — but
// impls should return nil in practice (delivery failures are logged, not
// propagated).
type Multi struct {
	notifiers []Notifier
}

// NewMulti builds a Multi skipping nil entries so callers can pass optional
// builders without guarding each one.
func NewMulti(ns ...Notifier) *Multi {
	out := make([]Notifier, 0, len(ns))
	for _, n := range ns {
		if n == nil {
			continue
		}
		out = append(out, n)
	}
	return &Multi{notifiers: out}
}

func (m *Multi) OnGrantCreated(ctx context.Context, e Event) error {
	return m.fan(func(n Notifier) error { return n.OnGrantCreated(ctx, e) })
}
func (m *Multi) OnValidatorApproved(ctx context.Context, e Event) error {
	return m.fan(func(n Notifier) error { return n.OnValidatorApproved(ctx, e) })
}
func (m *Multi) OnApproved(ctx context.Context, e Event) error {
	return m.fan(func(n Notifier) error { return n.OnApproved(ctx, e) })
}
func (m *Multi) OnDenied(ctx context.Context, e Event) error {
	return m.fan(func(n Notifier) error { return n.OnDenied(ctx, e) })
}
func (m *Multi) Wait() {
	for _, n := range m.notifiers {
		n.Wait()
	}
}

func (m *Multi) fan(f func(Notifier) error) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := f(n); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	// errors.Join is the standard-library way; keep a compact message with
	// just the count + first cause so we don't blow up logs on a fan-out
	// outage across many backends.
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return errors.New("notify: " + strings.Join(msgs, "; "))
}
