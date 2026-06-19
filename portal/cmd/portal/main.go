package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/portal/internal/api"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/lifecycle"
	"github.com/babs/poc-proxies/portal/internal/notify"
	portaloidc "github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/secrets"
	"github.com/babs/poc-proxies/portal/internal/store"

	"github.com/prometheus/client_golang/prometheus"

	// Register persistent store drivers so the -store flag can resolve
	// `sqlite:///path`, `sqlite::memory:`, and `postgres://…` URLs.
	_ "github.com/babs/poc-proxies/portal/internal/store/postgres"
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
	BuildTimestamp = "unknown"
	Builder        = "unknown"
)

// registerProvisionMetrics attaches the Workstream F producer-side collectors
// (spec §8.8) to the shared registry the obs sidecar serves. The values are
// pulled from the provisioning.Metrics snapshot on every scrape, mirroring the
// CounterFunc/GaugeFunc pull idiom the rest of the sidecar uses.
//
// Latency is exposed as the {_count,_sum} pair of a Prometheus summary: the obs
// sidecar offers no histogram-observe hook, and a count+sum is enough for the
// rate-of-mean queries §8.8 dashboards need. MustRegister panics on duplicate
// names — fine, this runs once at boot.
func registerProvisionMetrics(reg *metrics.Registry, m *provisioning.Metrics) {
	prom := reg.Prom()
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "portal_provision_intents_emitted_total",
		Help:        "Provision/revoke intents durably emitted to the outbox.",
		ConstLabels: prometheus.Labels{"kind": "provision"},
	}, func() float64 { p, _ := m.EmittedSnapshot(); return float64(p) }))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "portal_provision_intents_emitted_total",
		Help:        "Provision/revoke intents durably emitted to the outbox.",
		ConstLabels: prometheus.Labels{"kind": "revoke"},
	}, func() float64 { _, r := m.EmittedSnapshot(); return float64(r) }))
	prom.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "portal_provision_intents_pending",
		Help: "Best-effort queue depth: intents emitted but not yet observed terminal.",
	}, m.PendingSnapshot))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "portal_provision_claim_timeout_total",
		Help: "WaitForResult gave up waiting for the worker (portal answered 202).",
	}, func() float64 { return float64(m.ClaimTimeoutSnapshot()) }))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "portal_provision_intent_latency_seconds_count",
		Help: "Count of emit->result latency observations.",
	}, func() float64 { c, _ := m.LatencySnapshot(); return float64(c) }))
	prom.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "portal_provision_intent_latency_seconds_sum",
		Help: "Summed emit->result latency in seconds.",
	}, func() float64 { _, s := m.LatencySnapshot(); return s }))
}

// workerStaleThreshold is the liveness window the portal_provision_workers gauge
// uses to bucket heartbeat rows alive vs stale. Kept in lock-step with the api
// handler's threshold (3x the worker's 10s beat) — both answer "is this worker
// presumed dead?" so they must agree, or the gauge and the /workers endpoint
// would disagree on the same row.
const workerStaleThreshold = 30 * time.Second

// registerWorkerMetrics attaches the worker-liveness gauge to the shared
// registry. portal_provision_workers{state="alive"|"stale"} reflects the
// heartbeat table at scrape time: the GaugeFuncs read ListWorkerHeartbeats and
// classify rows via provisioning.CountWorkerStates. The table is small and
// bounded by the worker fleet size, so a per-scrape read is cheap and avoids a
// cached-counter staleness window. The store read is bounded by a short context
// so a stalled DB can't wedge the scrape. Both series register so a worker-less
// deployment reports 0/0 rather than absent series (no alert-on-missing gaps).
func registerWorkerMetrics(reg *metrics.Registry, s store.Store) {
	prom := reg.Prom()
	count := func() (alive, stale int) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		hbs, err := s.ListWorkerHeartbeats(ctx)
		if err != nil {
			return 0, 0
		}
		return provisioning.CountWorkerStates(hbs, time.Now(), workerStaleThreshold)
	}
	prom.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "portal_provision_workers",
		Help:        "Provisioner-worker heartbeat rows by liveness state at scrape time.",
		ConstLabels: prometheus.Labels{"state": "alive"},
	}, func() float64 { a, _ := count(); return float64(a) }))
	prom.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "portal_provision_workers",
		Help:        "Provisioner-worker heartbeat rows by liveness state at scrape time.",
		ConstLabels: prometheus.Labels{"state": "stale"},
	}, func() float64 { _, s := count(); return float64(s) }))
}

func main() {
	cfg := config.RegisterFlags(flag.CommandLine)
	flag.Parse()

	logger := logging.New()
	defer logging.Sync()

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid portal config", "err", err)
		logging.Sync()
		os.Exit(2)
	}

	otelCtx, otelCancel := context.WithTimeout(context.Background(), 10*time.Second)
	tracerShutdown, err := obs.InitTracerWith(otelCtx, "portal", Version, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	otelCancel()
	if err != nil {
		logger.Error("otel init failed", "err", err)
		os.Exit(1)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tracerShutdown(shutCtx)
		cancel()
	}()

	raw, err := store.NewFromURL(cfg.Store.URL)
	if err != nil {
		logger.Error("store init failed", "url", cfg.Store.URL, "err", err)
		logging.Sync()
		os.Exit(2)
	}
	defer func() { _ = raw.Close() }()

	// At-rest secret cipher: wrap the store so every backend-account password,
	// portal password, and ephemeral password is SecretBox-encrypted before
	// persistence. A key is required unless the operator explicitly opts out
	// via -secretbox-key-env="" (local-dev escape hatch).
	var cipher secrets.Cipher = secrets.Noop{}
	switch {
	case cfg.Store.SecretboxKeyEnv == "":
		logger.Warn("at_rest_encryption_disabled",
			"reason", "-secretbox-key-env empty",
			"impact", "backend-account passwords and grant portal/ephemeral passwords stored in plaintext")
	default:
		key, kerr := secrets.LoadKeyFromEnv(cfg.Store.SecretboxKeyEnv)
		if kerr != nil {
			logger.Error("secretbox key load failed", "env", cfg.Store.SecretboxKeyEnv, "err", kerr)
			logging.Sync()
			os.Exit(2)
		}
		c, cerr := secrets.NewSecretboxCipher(key)
		if cerr != nil {
			logger.Error("secretbox init failed", "err", cerr)
			logging.Sync()
			os.Exit(2)
		}
		cipher = c
		logger.Info("at_rest_encryption_enabled", "env", cfg.Store.SecretboxKeyEnv)
	}
	s := store.Store(store.NewEncrypting(raw, cipher, logger))
	engine := policy.New(s)

	// Ephemeral provisioning — off by default. When enabled, the portal does
	// NOT provision DB users itself: it emits provision/revoke intents to the
	// shared outbox for a dedicated provisioner-worker, which is the only
	// component that holds master/DBA credentials and runs DDL (spec §8.2).
	// The portal therefore loads no DBA creds at boot.
	var provisioner *provisioning.Client
	var provisionMetrics *provisioning.Metrics
	if cfg.EphemeralAccounts {
		notifierCtx, notifierCancel := context.WithTimeout(context.Background(), 10*time.Second)
		notifier, nerr := provisioning.NewNotifier(notifierCtx, cfg.Store.URL, logger)
		notifierCancel()
		if nerr != nil {
			logger.Error("provisioning notifier init failed", "err", nerr)
			logging.Sync()
			os.Exit(2)
		}
		defer func() { _ = notifier.Close() }()
		// Workstream F (spec §8.8): the producer-side metrics handle is wired
		// onto the Client so EmitProvision/EmitRevoke/WaitForResult record the
		// portal_provision_* series. It's surfaced on the obs sidecar below.
		provisionMetrics = provisioning.NewMetrics()
		provisioner = provisioning.NewClient(s, notifier, logger).WithMetrics(provisionMetrics)
		// Stop the shared result-listener goroutine (+ its connection) on shutdown
		// (MEDIUM-2). Registered after notifier.Close so it runs FIRST (LIFO): the
		// listener must release the stream before the notifier conn is torn down.
		defer func() { _ = provisioner.Close() }()
		logger.Info("ephemeral_provisioning_enabled", "mode", "outbox_intents")
	}

	auditMetrics := lifecycle.NewAuditMetrics()
	sweeperCtx, stopSweeper := context.WithCancel(context.Background())
	defer stopSweeper()
	sweeperDone := make(chan struct{})
	var orphanHook func(context.Context, store.Store)
	if provisioner != nil {
		orphanHook = ephemeral.OrphanSweepHook(provisioner, logger)
	}
	go func() {
		lifecycle.Run(sweeperCtx, s, lifecycle.SweeperConfig{
			RetentionDays:        cfg.Audit.RetentionDays,
			MaxEntries:           cfg.Audit.MaxEntries,
			Interval:             cfg.Audit.SweepInterval,
			OrphanEphemeralSweep: orphanHook,
			ReconcileProvisioned: provisioner != nil,
			CredentialTTL:        cfg.Windows.CredentialTTL,
			// Reap heartbeat rows of workers dead for an hour. Long vs the 30s
			// obs stale-threshold so a brief stall shows as stale=true without
			// dropping the row from under a watching operator.
			PruneWorkerAge: time.Hour,
		}, auditMetrics, logger)
		close(sweeperDone)
	}()

	// Build OIDC provider if the issuer is configured. Discovery hits the
	// network, so we give it a bounded deadline — an unreachable IdP at boot
	// should surface fast rather than hanging on flag.Parse().
	var oidcProvider *portaloidc.Provider
	oidcCfg := &portaloidc.Config{
		IssuerURL:    cfg.OIDC.IssuerURL,
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL:  cfg.OIDC.RedirectURL,
		AdminClaim:   cfg.OIDC.AdminClaim,
		AdminValue:   cfg.OIDC.AdminValue,
		CookieSecure: cfg.OIDC.CookieSecure,
	}
	if oidcCfg.Enabled() {
		// Cluster-safe sessions: when the portal runs against a persistent
		// store, sessions live there too so any replica can validate the
		// cookie set by another. The in-memory store keeps using the
		// in-memory SessionStore — there's no DB to share with anyway.
		var sessionStore portaloidc.SessionStore
		if _, isMemory := s.(*store.Memory); isMemory {
			sessionStore = portaloidc.NewMemoryStore()
		} else {
			sessionStore = portaloidc.NewSQLStore(s)
			logger.Info("oidc_sessions_persistent", "store", cfg.Store.URL)
		}
		discCtx, discCancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := portaloidc.New(discCtx, oidcCfg, sessionStore, logger)
		discCancel()
		if err != nil {
			logger.Error("oidc init failed", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		// Wire first-login provisioning: on callback the provider materialises
		// or resolves a portal user for the IdP subject so grants handlers can
		// scope non-admin requests to their own user_id.
		oidcProvider = p.WithProvisioner(api.StoreUserProvisioner{Store: s})
		logger.Info("oidc enabled", "issuer", cfg.OIDC.IssuerURL)
	}

	mreg := metrics.New(time.Now())
	rlMetrics := api.NewRateLimitMetrics()

	// Entra integration — wire only when credentials are set. Policy-file
	// load is fail-closed: a broken file aborts boot.
	var entraClient entra.Client
	var requestPol *policy.RequestPolicy
	entraMetrics := notify.NewEntraMetrics()
	if cfg.Entra.Enabled() {
		c, err := entra.NewFromConfig(context.Background(), entra.Config{
			TenantID:     cfg.Entra.TenantID,
			ClientID:     cfg.Entra.ClientID,
			ClientSecret: cfg.Entra.ClientSecret,
			Logger:       logger,
		})
		if err != nil {
			logger.Error("entra init failed", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		entraClient = c
		logger.Info("entra enabled", "tenant", cfg.Entra.TenantID, "sender", cfg.Entra.SenderUPN)
	}
	if cfg.Entra.PolicyFile != "" {
		p, err := policy.LoadRequestPolicy(cfg.Entra.PolicyFile)
		if err != nil {
			logger.Error("entra policy load failed", "err", err, "path", cfg.Entra.PolicyFile)
			logging.Sync()
			os.Exit(2)
		}
		requestPol = p
		logger.Info("entra policy loaded", "path", cfg.Entra.PolicyFile, "groups", len(p.Groups()))
	}

	// Server-lifecycle context: drives the router's background goroutines
	// (rate-limit bucket sweeper) and is cancelled on shutdown.
	srvCtx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()
	// notifier is captured from the router so graceful shutdown can drain
	// in-flight webhook/email deliveries (they run in detached goroutines).
	var notifier notify.Notifier
	handler := api.NewRouter(cfg, s, engine, logger,
		api.WithOIDC(oidcProvider),
		api.WithPromRegistry(mreg),
		api.WithRateLimitMetrics(rlMetrics),
		api.WithProvisioningClient(provisioner),
		api.WithEntra(entraClient),
		api.WithRequestPolicy(requestPol),
		api.WithEntraMail(cfg.Entra.SenderUPN, entraMetrics),
		api.WithPublicURL(cfg.HTTP.PublicURL),
		api.WithT2Mailbox(cfg.Entra.T2Mailbox),
		api.WithLifecycleContext(srvCtx),
		api.WithNotifierSink(&notifier),
	)

	srv := &http.Server{
		Addr:              cfg.HTTP.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       60 * time.Second,
	}

	var sidecar *obs.Server
	if cfg.HTTP.MetricsAddr != "" {
		sidecar = obs.NewServer(cfg.HTTP.MetricsAddr, logger,
			obs.BuildInfo{Version: Version, CommitHash: CommitHash, BuildTimestamp: BuildTimestamp, Builder: Builder},
			func() (uint64, uint64, uint64) { return 0, 0, 0 }) // portal has no conn counters today
		sidecar.SetAuditStats(auditMetrics.Snapshot)
		sidecar.SetGrantStats(auditMetrics.GrantsExpired)
		sidecar.SetRegistry(mreg)
		sidecar.SetRateLimitStats(rlMetrics.Snapshot)
		sidecar.SetEntraStats(entraMetrics.Snapshot)
		// Workstream F producer-side series (spec §8.8). Registered directly on
		// the shared registry the sidecar serves — the obs package has no typed
		// provisioning hook, so we use the same CounterFunc/GaugeFunc idiom its
		// SetRateLimitStats/SetEphemeralStats helpers use under the hood. Only
		// wired when ephemeral provisioning is on (provisionMetrics != nil).
		if provisionMetrics != nil {
			registerProvisionMetrics(mreg, provisionMetrics)
		}
		// Worker-liveness gauge is wired unconditionally: a heartbeat table may
		// be populated by a worker running against the same store even when this
		// portal process doesn't emit intents (provisionMetrics == nil).
		registerWorkerMetrics(mreg, s)
		if err := sidecar.Start(); err != nil {
			logger.Error("failed to start obs sidecar", "err", err)
			os.Exit(1)
		}
		sidecar.MarkReady()
	}

	logger.Info("portal starting",
		"listen", cfg.HTTP.ListenAddr,
		"version", Version,
		"proxy_token_enabled", cfg.ProxyToken != "",
		"user_token_enabled", cfg.UserToken != "",
		"auto_approve", cfg.Approval.AutoApprove,
		"approval_webhook_enabled", cfg.Approval.WebhookURL != "",
	)

	apiDone := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			apiDone <- err
			return
		}
		apiDone <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-apiDone:
		if err != nil {
			logger.Error("api exited", "err", err)
			os.Exit(1)
		}
	}

	apiCtx, apiCancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownGrace)
	defer apiCancel()
	if err := srv.Shutdown(apiCtx); err != nil {
		logger.Error("api shutdown error", "err", err)
	}
	// Stop the router's background goroutines (rate-limit sweeper).
	stopSrv()
	// Drain in-flight notification deliveries AFTER the listener is closed: no
	// new events arrive past srv.Shutdown, so Wait() converges. Bound it so a
	// stuck webhook endpoint can't hang shutdown indefinitely.
	if notifier != nil {
		drainDone := make(chan struct{})
		go func() {
			notifier.Wait()
			close(drainDone)
		}()
		select {
		case <-drainDone:
		case <-time.After(5 * time.Second):
			// Drain window exhausted — actively cancel in-flight deliveries so a
			// wedged endpoint's retry backoff can't outlive shutdown, then let
			// the Wait goroutine unblock.
			logger.Warn("notifier_drain_timeout", "impact", "cancelling in-flight deliveries")
			notifier.Stop()
		}
	}
	stopSweeper()
	<-sweeperDone
	if sidecar != nil {
		// Dedicated deadline so the sidecar still gets time even if the API
		// drain consumed the full ShutdownGrace window.
		sideCtx, sideCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = sidecar.Shutdown(sideCtx)
		sideCancel()
	}
	logger.Info("portal stopped")
}
