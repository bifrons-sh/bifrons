// Command provisioner-worker is the privileged half of the phase-8 split: the
// only component that holds master DB credentials and runs CREATE/ALTER/DROP
// against managed backends. It pulls intents from the shared portal store
// (postgres LISTEN/NOTIFY + catch-up poll, or poll-only on sqlite), provisions
// or revokes per-grant ephemeral accounts, and writes the result back encrypted
// under the shared SecretBox key so the portal can serve it on /claim.
//
// It has NO HTTP surface toward users / proxies — the store is the only ingress
// (spec §8.2). Master creds live exclusively in this process's address space,
// resolved from its own -worker-config via secret references; the portal never
// loads them.
//
// The one exception is an OPTIONAL Prometheus /metrics + /healthz sidecar
// (Workstream F, spec §8.8), enabled via -metrics-addr. That listener is infra
// observability only and serves no user/proxy-facing API — it never exposes
// intents, credentials, or store data.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/secrets"
	"github.com/babs/poc-proxies/portal/internal/store"

	"github.com/prometheus/client_golang/prometheus"

	// Register the store drivers so NewFromURL resolves postgres:// / sqlite://.
	_ "github.com/babs/poc-proxies/portal/internal/store/postgres"
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

// Build-time vars injected via -ldflags -X (see Makefile / Dockerfile).
var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
	BuildTimestamp = "1970-01-01T00:00:00"
	Builder        = "unknown"
)

// Flags is the raw CLI/env surface, resolved into a Config by LoadConfig.
type Flags struct {
	StoreURL        string
	SecretboxEnv    string
	ConfigPath      string
	Whitelist       string
	CatchUpInterval time.Duration
	LeaseTTL        time.Duration
	DDLTimeout      time.Duration
	ClaimBatch      int
	WorkerID        string
	MetricsAddr     string

	HeartbeatInterval time.Duration
	HeartbeatProbe    bool
}

func main() {
	var f Flags
	flag.StringVar(&f.StoreURL, "store", config.GetEnv("PORTAL_STORE", ""), "Shared portal store URL (env: PORTAL_STORE)")
	flag.StringVar(&f.SecretboxEnv, "secretbox-env", config.GetEnv("SECRETBOX_KEY_ENV", "SECRETBOX_KEY"), "Env var holding the base64 SecretBox key shared with the portal")
	flag.StringVar(&f.ConfigPath, "worker-config", config.GetEnv("WORKER_CONFIG", ""), "Path to the worker config JSON (env: WORKER_CONFIG)")
	flag.StringVar(&f.Whitelist, "whitelist", config.GetEnv("WORKER_INSTANCE_WHITELIST", ""), "Comma-separated backend ids this worker claims (empty = all)")
	flag.DurationVar(&f.CatchUpInterval, "catch-up", time.Duration(config.GetEnvInt("WORKER_CATCH_UP_SECONDS", 30))*time.Second, "Catch-up poll interval (floor 5s)")
	flag.DurationVar(&f.LeaseTTL, "lease-ttl", time.Duration(config.GetEnvInt("WORKER_LEASE_TTL_SECONDS", 60))*time.Second, "Intent lease TTL")
	flag.DurationVar(&f.DDLTimeout, "ddl-timeout", time.Duration(config.GetEnvInt("WORKER_DDL_TIMEOUT", 20))*time.Second, "Per-DDL round-trip timeout (capped to lease-ttl minus margin)")
	flag.IntVar(&f.ClaimBatch, "claim-batch", config.GetEnvInt("WORKER_CLAIM_BATCH", 16), "Max intents claimed per wake")
	flag.StringVar(&f.WorkerID, "worker-id", config.GetEnv("WORKER_ID", ""), "Worker identity (default hostname-pid)")
	flag.StringVar(&f.MetricsAddr, "metrics-addr", config.GetEnv("WORKER_METRICS_ADDR", ""), "Prometheus /metrics + /healthz listen addr (empty disables; e.g. :9090)")
	flag.DurationVar(&f.HeartbeatInterval, "heartbeat-interval", time.Duration(config.GetEnvInt("WORKER_HEARTBEAT_INTERVAL", 10))*time.Second, "Process-level liveness heartbeat cadence (floor 2s)")
	flag.BoolVar(&f.HeartbeatProbe, "heartbeat-probe", envBool("WORKER_HEARTBEAT_PROBE", true), "Probe each owned backend's reachability on every heartbeat")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	logger := logging.New()
	defer logging.Sync()

	if *showVersion {
		logger.Info("provisioner-worker", "version", Version, "commit", CommitHash, "built", BuildTimestamp, "builder", Builder)
		return
	}

	logger.Info("provisioner_worker_boot", "version", Version, "commit", CommitHash, "built", BuildTimestamp)

	cfg, err := LoadConfig(f)
	if err != nil {
		logger.Error("config_load_failed", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, Version, logger); err != nil {
		logger.Error("worker_run_failed", "err", err)
		os.Exit(1)
	}
}

// envBool reads a boolean env var (1/t/T/true/0/f/false, strconv.ParseBool
// shape), falling back when unset or unparseable. config.GetEnvBool doesn't
// exist and that package is out of scope to edit, so the worker carries its own
// minimal parser rather than reaching across the package boundary.
func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// run opens the store (wrapped in the shared encrypting decorator), builds the
// notifier + provisioner factory, and drives the engine. Teardown closes the
// notifier on exit. version is the build-time Version threaded into each
// liveness heartbeat so operators can see which build a worker is running.
func run(ctx context.Context, cfg Config, version string, logger *slog.Logger) error {
	raw, err := store.NewFromURL(cfg.StoreURL)
	if err != nil {
		return err
	}
	cipher, err := secrets.NewSecretboxCipher(cfg.SecretboxKey)
	if err != nil {
		return err
	}
	// Same encrypting wrapper + key as the portal: results MUST round-trip
	// through the identical cipher or the portal can't decrypt them on /claim.
	st := store.NewEncrypting(raw, cipher, logger)

	notifier, err := provisioning.NewNotifier(ctx, cfg.StoreURL, logger)
	if err != nil {
		return err
	}
	defer func() { _ = notifier.Close() }()

	// Config-backed DBA lookup — the worker resolves master creds from its own
	// config, never from the store (spec §8.2).
	lookup := ephemeral.NewConfigDBALookup(cfg.DBACreds)
	factory := func(bt ephemeral.BackendType) (ephemeral.Provisioner, bool) {
		switch bt {
		case ephemeral.BackendPostgres:
			return ephemeral.NewPostgresProvisioner(lookup, nil), true
		case ephemeral.BackendMySQL:
			return ephemeral.NewMySQLProvisioner(lookup, nil), true
		case ephemeral.BackendMongo:
			return ephemeral.NewMongoProvisioner(lookup, nil), true
		default:
			return nil, false
		}
	}

	derive := func(intentID string) (string, string) { return deriveCreds(cfg.WorkerKey, intentID) }

	// Workstream F (spec §8.8): consumer-side metrics. The handle is wired onto
	// the Worker so the loop records worker_provision_* series, and surfaced on
	// an optional obs sidecar mirroring how the proxies expose theirs.
	wm := newWorkerMetrics()
	if cfg.MetricsAddr != "" {
		sidecar := obs.NewServer(cfg.MetricsAddr, logger,
			obs.BuildInfo{Version: Version, CommitHash: CommitHash, BuildTimestamp: BuildTimestamp, Builder: Builder},
			func() (uint64, uint64, uint64) { return 0, 0, 0 }) // worker has no conn counters
		// Own the registry so we can register the worker_* collectors on it; the
		// sidecar serves whatever SetRegistry attaches.
		mreg := metrics.New(time.Now())
		sidecar.SetRegistry(mreg)
		registerWorkerMetrics(mreg, wm)
		if err := sidecar.Start(); err != nil {
			return fmt.Errorf("start metrics sidecar: %w", err)
		}
		sidecar.MarkReady()
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = sidecar.Shutdown(shutCtx)
			cancel()
		}()
	}

	w := NewWorker(cfg, st, notifier, factory, derive, logger).
		WithMetrics(wm).
		WithVersion(version).
		WithProber(defaultProber(cfg.DBACreds))
	return w.Run(ctx)
}

// registerWorkerMetrics attaches the Workstream F consumer-side collectors
// (spec §8.8) to the sidecar's registry, pulling values from the snapshot on
// each scrape — the same CounterFunc/GaugeFunc pull idiom obs uses internally.
// DDL latency is exposed as a summary's {_count,_sum} pair (the sidecar has no
// histogram-observe hook). MustRegister panics on dup names — fine at boot.
func registerWorkerMetrics(reg *metrics.Registry, m *workerMetrics) {
	prom := reg.Prom()
	// processed{kind,result} is dynamic, so register a single Collector that
	// emits one series per observed (kind,result) pair at scrape time rather
	// than pre-declaring every combination.
	prom.MustRegister(newProcessedCollector(m))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "worker_stale_leases_reclaimed_total",
		Help: "Intents reclaimed from a stale (lease-expired) in_flight row.",
	}, func() float64 { return float64(m.StaleReclaimedSnapshot()) }))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "worker_notify_missed_total",
		Help: "Intents found via catch-up poll, not NOTIFY (LISTEN health indicator).",
	}, func() float64 { return float64(m.NotifyMissedSnapshot()) }))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "worker_provision_ddl_latency_seconds_count",
		Help: "Count of DDL round-trip latency observations.",
	}, func() float64 { c, _ := m.DDLSnapshot(); return float64(c) }))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "worker_provision_ddl_latency_seconds_sum",
		Help: "Summed DDL round-trip latency in seconds.",
	}, func() float64 { _, s := m.DDLSnapshot(); return s }))
}
