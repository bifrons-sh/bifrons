package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
)

// Notification channels shared by producer (portal) and consumer (worker).
// ChannelProvisionIntent wakes the worker on a fresh intent; Channel
// ProvisionResult wakes the portal's WaitForResult on a terminal intent.
const (
	ChannelProvisionIntent = "provision_intent"
	ChannelProvisionResult = "provision_result"
)

// Notifier is a store-aware wakeup abstraction over postgres LISTEN/NOTIFY.
//
// On postgres it is a real sub-ms wakeup channel; on every other store
// (sqlite, memory) it degrades to a no-op so the system runs in poll-only
// mode — same correctness, just higher idle→wake latency (see spec §8.3).
type Notifier interface {
	// Notify publishes payload on channel. No-op (returns nil) on stores
	// without a real pub/sub transport.
	Notify(ctx context.Context, channel, payload string) error
	// Listen subscribes to channel and returns a stream of payloads. The
	// channel is closed on ctx cancellation OR on fatal connection loss —
	// a closed channel is the signal for the caller to re-establish (the
	// Notifier does NOT reconnect itself; reconnect/backoff is the worker's
	// concern). On no-op stores the returned channel never delivers and
	// closes only on ctx cancellation.
	Listen(ctx context.Context, channel string) (<-chan string, error)
	// Close releases the underlying connection.
	Close() error
}

// channelIdentRE restricts channel names to a safe SQL identifier subset.
// LISTEN cannot be parameterized, so the channel name is interpolated into the
// statement — this whitelist is the injection guard. Postgres folds unquoted
// identifiers to lower-case, so we only ever accept already-lower-case names.
var channelIdentRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// validateChannel rejects any name that isn't a plain lower-case SQL
// identifier, so it can be safely interpolated into LISTEN.
func validateChannel(channel string) error {
	if !channelIdentRE.MatchString(channel) {
		return fmt.Errorf("provisioning: invalid notification channel %q (want [a-z_][a-z0-9_]*)", channel)
	}
	return nil
}

// NewNotifier builds a Notifier appropriate for the store backing storeURL.
// Postgres URLs get a real LISTEN/NOTIFY notifier on a dedicated connection;
// everything else gets the poll-only no-op notifier.
func NewNotifier(ctx context.Context, storeURL string, logger *slog.Logger) (Notifier, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if isPostgresURL(storeURL) {
		// Dedicated PUBLISH connection for Notify. Listen does NOT share it — it
		// dials its own conn per call (see postgresNotifier doc) — so a blocking
		// WaitForNotification never collides with a concurrent pg_notify Exec.
		conn, err := pgx.Connect(ctx, storeURL)
		if err != nil {
			return nil, fmt.Errorf("provisioning: connect notifier: %w", err)
		}
		return &postgresNotifier{pubConn: conn, storeURL: storeURL, logger: logger}, nil
	}
	return &noopNotifier{logger: logger}, nil
}

// isPostgresURL reports whether url targets postgres (the only store with a
// real pub/sub transport). Mirrors the scheme detection in the store factory.
func isPostgresURL(url string) bool {
	return strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://")
}

// postgresNotifier drives LISTEN/NOTIFY with SEPARATE connections per direction
// because pgx.Conn is NOT safe for concurrent use, and the same notifier
// instance serves both directions concurrently: the portal Client publishes
// (Notify) from request goroutines while its shared result-listener blocks in
// WaitForNotification (Listen), and the worker does the symmetric thing.
//
// Connection model:
//   - pubConn: one dedicated PUBLISH conn, reused across Notify calls and
//     guarded by pubMu so concurrent publishers serialise on it (a pg_notify
//     Exec is sub-ms, so the mutex is uncontended in practice).
//   - Listen: dials its OWN fresh conn per call and owns it for the
//     subscription's lifetime (WaitForNotification blocks on it the whole time),
//     closing it when the stream ends. Never touches pubConn.
//
// No connection is ever shared between a blocking WaitForNotification and a
// concurrent Exec, which was the data race (HIGH-1).
type postgresNotifier struct {
	pubMu   sync.Mutex // serialises Notify's Exec on the shared pubConn
	pubConn *pgx.Conn

	storeURL string // dialed fresh per Listen for its dedicated subscription conn
	logger   *slog.Logger
}

// Notify publishes via pg_notify with the payload bound as a parameter — the
// payload is untrusted (an intent id today, but never interpolate regardless),
// so it must never be string-concatenated into a NOTIFY statement. The mutex
// guards the shared pubConn against concurrent publishers (pgx.Conn is not
// concurrency-safe).
func (n *postgresNotifier) Notify(ctx context.Context, channel, payload string) error {
	if err := validateChannel(channel); err != nil {
		return err
	}
	n.pubMu.Lock()
	defer n.pubMu.Unlock()
	if _, err := n.pubConn.Exec(ctx, "SELECT pg_notify($1, $2)", channel, payload); err != nil {
		return fmt.Errorf("provisioning: pg_notify %q: %w", channel, err)
	}
	return nil
}

// Listen dials a fresh dedicated connection, issues LISTEN, then streams
// payloads from a background goroutine. The channel name is validated + quoted
// because LISTEN cannot bind parameters. The per-call conn is owned by this
// subscription (WaitForNotification blocks on it for the subscription's whole
// lifetime) and closed when the stream ends — so it never collides with Notify's
// pubConn.
func (n *postgresNotifier) Listen(ctx context.Context, channel string) (<-chan string, error) {
	if err := validateChannel(channel); err != nil {
		return nil, err
	}
	// Dedicated subscription connection: WaitForNotification monopolises it, so
	// it must be this Listen's own conn, never the shared pubConn.
	conn, err := pgx.Connect(ctx, n.storeURL)
	if err != nil {
		return nil, fmt.Errorf("provisioning: connect listener conn: %w", err)
	}
	// Safe: channel passed validateChannel, so it's a bare identifier. Double
	// quotes preserve it verbatim and close off any residual injection vector.
	if _, err := conn.Exec(ctx, fmt.Sprintf("LISTEN %q", channel)); err != nil {
		_ = conn.Close(context.Background())
		return nil, fmt.Errorf("provisioning: LISTEN %q: %w", channel, err)
	}

	out := make(chan string)
	go func() {
		// Closing out is the documented "connection lost / cancelled, please
		// re-establish" signal to the caller. This goroutine solely owns conn, so
		// it also closes it on the way out — no other goroutine touches it.
		defer close(out)
		defer conn.Close(context.Background())
		for {
			notif, err := conn.WaitForNotification(ctx)
			if err != nil {
				// ctx cancellation is the normal stop path, not an error worth
				// shouting about; anything else is a real connection fault.
				if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					n.logger.Warn("provision_notify_listen_lost",
						slog.String("channel", channel), slog.Any("error", err))
				}
				return
			}
			select {
			case out <- notif.Payload:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// Close closes the shared PUBLISH connection. Each Listen goroutine owns and
// closes its own subscription conn independently (on ctx cancel / stream end),
// so Close only has the publish conn to release.
func (n *postgresNotifier) Close() error {
	// Background context: Close is a teardown path and the caller's ctx may
	// already be cancelled, which would otherwise abort the protocol-level
	// connection close mid-flight.
	n.pubMu.Lock()
	defer n.pubMu.Unlock()
	if err := n.pubConn.Close(context.Background()); err != nil {
		return fmt.Errorf("provisioning: close notifier pub conn: %w", err)
	}
	return nil
}

// noopNotifier is the poll-only fallback for stores without LISTEN/NOTIFY
// (sqlite, memory). Notify silently succeeds; Listen returns a channel that
// never delivers and closes only when ctx is cancelled — so callers that
// select on it transparently fall back to their catch-up poll loop.
type noopNotifier struct {
	logger *slog.Logger
}

func (n *noopNotifier) Notify(context.Context, string, string) error { return nil }

func (n *noopNotifier) Listen(ctx context.Context, channel string) (<-chan string, error) {
	out := make(chan string)
	go func() {
		defer close(out)
		<-ctx.Done()
	}()
	return out, nil
}

func (n *noopNotifier) Close() error { return nil }
