package provisioning

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// newNotifierTestDSN spins up a disposable Postgres and returns its DSN. It
// t.Skip's when docker isn't reachable so the unit suite still passes on a
// docker-less CI box — mirrors store/postgres_test.go's harness.
func newNotifierTestDSN(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	c, err := tcpostgres.Run(ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("portal"),
		tcpostgres.WithUsername("portal"),
		tcpostgres.WithPassword("portal"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainer unavailable: %v", err)
	}
	t.Cleanup(func() {
		cctx, cc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cc()
		_ = testcontainers.TerminateContainer(c, testcontainers.StopContext(cctx))
	})

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return dsn
}

// TestPostgresNotifier_RoundTrip covers M8(b): a live publish→WaitForNotification
// round-trip, stream close on Listen-ctx cancel (the conn-loss signal), and a
// clean Close of the publish conn. It also indirectly exercises the HIGH-1 fix —
// Notify (publish conn) runs concurrently with a blocking Listen (its own conn)
// without sharing a connection.
func TestPostgresNotifier_RoundTrip(t *testing.T) {
	dsn := newNotifierTestDSN(t)
	ctx := context.Background()

	n, err := NewNotifier(ctx, dsn, nil)
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })

	lctx, cancel := context.WithCancel(ctx)
	stream, err := n.Listen(lctx, ChannelProvisionResult)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Publish concurrently with the blocking WaitForNotification inside Listen.
	// On the old single-conn design this is the racing Exec-vs-WaitForNotification
	// path; with separate conns it's safe. Retry briefly to absorb the small
	// window before the listener's LISTEN is registered server-side.
	const payload = "intent-xyz"
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if err := n.Notify(ctx, ChannelProvisionResult, payload); err != nil {
				t.Errorf("Notify: %v", err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case got, ok := <-stream:
		if !ok {
			t.Fatal("stream closed before delivering the notification")
		}
		if got != payload {
			t.Errorf("payload = %q, want %q", got, payload)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("notification not delivered over the live round-trip")
	}

	// Cancelling the Listen ctx must close the stream (the documented conn-loss /
	// re-establish signal) and let the dedicated subscription conn close itself.
	cancel()
	select {
	case _, ok := <-stream:
		if ok {
			// Drain any in-flight duplicate notification, then expect close.
			select {
			case _, ok2 := <-stream:
				if ok2 {
					t.Error("stream did not close after Listen ctx cancel")
				}
			case <-time.After(2 * time.Second):
				t.Error("stream did not close after Listen ctx cancel")
			}
		}
	case <-time.After(2 * time.Second):
		t.Error("stream did not close after Listen ctx cancel")
	}
	<-done

	// Close must release the publish conn cleanly.
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
