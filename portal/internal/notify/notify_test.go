package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

func silentLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func TestNoop_AllMethodsReturnNil(t *testing.T) {
	n := Noop{}
	e := Event{Grant: domain.Grant{ID: "g"}}
	for _, call := range []func() error{
		func() error { return n.OnGrantCreated(context.Background(), e) },
		func() error { return n.OnValidatorApproved(context.Background(), e) },
		func() error { return n.OnApproved(context.Background(), e) },
		func() error { return n.OnDenied(context.Background(), e) },
	} {
		if err := call(); err != nil {
			t.Errorf("noop returned err=%v", err)
		}
	}
	n.Wait() // must not block
}

// --- Multi ---

// countingNotifier tracks per-method invocation counts so Multi fan-out and
// error aggregation are observable from tests.
type countingNotifier struct {
	created, mgr, approved, denied int
	waitCalls                      int
	err                            error
}

func (c *countingNotifier) OnGrantCreated(context.Context, Event) error {
	c.created++
	return c.err
}
func (c *countingNotifier) OnValidatorApproved(context.Context, Event) error {
	c.mgr++
	return c.err
}
func (c *countingNotifier) OnApproved(context.Context, Event) error {
	c.approved++
	return c.err
}
func (c *countingNotifier) OnDenied(context.Context, Event) error {
	c.denied++
	return c.err
}
func (c *countingNotifier) Wait() { c.waitCalls++ }

func TestMulti_FanOut(t *testing.T) {
	a := &countingNotifier{}
	b := &countingNotifier{}
	m := NewMulti(a, nil, b) // nil entries drop out
	ctx := context.Background()
	e := Event{Grant: domain.Grant{ID: "g"}}

	_ = m.OnGrantCreated(ctx, e)
	_ = m.OnValidatorApproved(ctx, e)
	_ = m.OnApproved(ctx, e)
	_ = m.OnDenied(ctx, e)
	m.Wait()

	for _, n := range []*countingNotifier{a, b} {
		if n.created != 1 || n.mgr != 1 || n.approved != 1 || n.denied != 1 || n.waitCalls != 1 {
			t.Errorf("notifier counts: %+v", n)
		}
	}
}

// TestMulti_AggregatesErrors: every notifier that returns an error must show
// up in the joined error Multi returns, but one failure must not short-circuit
// delivery to subsequent notifiers.
func TestMulti_AggregatesErrors(t *testing.T) {
	bad := &countingNotifier{err: errors.New("boom")}
	good := &countingNotifier{}
	m := NewMulti(bad, good)
	err := m.OnGrantCreated(context.Background(), Event{Grant: domain.Grant{ID: "g"}})
	if err == nil {
		t.Fatal("expected joined error")
	}
	if good.created != 1 {
		t.Error("good notifier must still fire even after bad one errors")
	}
}

// --- helpers ---

func TestHelpers_DisplayOrAndDomainPart(t *testing.T) {
	if got := displayOr(domain.User{Username: "alice"}); got != "alice" {
		t.Errorf("displayOr(username-only)=%q", got)
	}
	if got := displayOr(domain.User{DisplayName: "Alice Smith", Username: "alice"}); got != "Alice Smith" {
		t.Errorf("displayOr(display set)=%q", got)
	}
	if got := firstNonEmpty("", "", "x"); got != "x" {
		t.Errorf("firstNonEmpty=%q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty(all empty)=%q", got)
	}
	if got := domainPart("alice@example.com"); got != "example.com" {
		t.Errorf("domainPart=%q", got)
	}
	if got := domainPart("no-at-sign"); got != "<unknown>" {
		t.Errorf("domainPart(no @)=%q", got)
	}
	if got := domainPart("trailing@"); got != "<unknown>" {
		t.Errorf("domainPart(trailing @)=%q", got)
	}
}

func TestHelpers_EscapeHTML(t *testing.T) {
	cases := map[string]string{
		`<script>`: "&lt;script&gt;",
		`a & b`:    "a &amp; b",
		`"quoted"`: "&quot;quoted&quot;",
		`plain`:    "plain",
	}
	for in, want := range cases {
		if got := escapeHTML(in); got != want {
			t.Errorf("escapeHTML(%q)=%q want %q", in, got, want)
		}
	}
}
