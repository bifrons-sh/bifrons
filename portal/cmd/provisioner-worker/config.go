package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/secrets"
)

// Config is the resolved runtime configuration for the provisioner-worker.
//
// Master DB credentials live here and ONLY here (spec §8.2): the portal process
// never loads them. Everything sensitive is resolved through secrets.Resolve so
// the on-disk / env form is a reference (env://, file://) rather than the raw
// secret — keeping plaintext out of the worker-config file itself.
type Config struct {
	// StoreURL is the shared portal store (postgres://… | sqlite:///…). The
	// worker reads intents and writes results here; it MUST be the same store
	// the portal uses, with result columns encrypted under the shared key below.
	StoreURL string
	// SecretboxKey is the raw 32-byte key shared with the portal. The worker
	// encrypts result_username/result_password with it so the portal can decrypt
	// on /claim (spec §8.4.1). Loaded from SECRETBOX_KEY (base64) via the same
	// loader the portal uses.
	SecretboxKey []byte
	// WorkerKey is the 32-byte HMAC seed for deriving deterministic ephemeral
	// credentials (spec §8.4). Worker-only — distinct from SecretboxKey.
	WorkerKey []byte
	// DBACreds maps backendID → master credential. Resolved at boot (and on a
	// re-resolve timer, future work) from the per-backend refs in the config
	// file. Drives ephemeral.NewConfigDBALookup.
	DBACreds map[string]ephemeral.DBACredential
	// InstanceWhitelist filters which backends this worker claims intents for
	// (spec §8.10). Empty ⇒ claim all (the store treats nil/empty as "no filter").
	InstanceWhitelist []string
	// CatchUpInterval is the poll cadence for the self-healing catch-up loop.
	// Default 30s, floored at 5s (spec §8.5).
	CatchUpInterval time.Duration
	// LeaseTTL is how long a claim is held before another worker may reclaim a
	// stale in_flight row. Default 60s (spec §8.5).
	LeaseTTL time.Duration
	// DDLTimeout bounds a single CREATE/ALTER/DROP round-trip so a wedged
	// backend fails fast (transient_network) instead of stalling the serial
	// drain. Default 20s, further capped to leaseTTL minus a margin at runtime.
	DDLTimeout time.Duration
	// ClaimBatch caps how many intents a single wake claims at once.
	ClaimBatch int
	// WorkerID identifies this worker in lease ownership + logs. Defaults to
	// hostname+pid so two workers on one host don't collide.
	WorkerID string
	// MetricsAddr is the listen address for the Prometheus /metrics + /healthz
	// sidecar (spec §8.8, Workstream F). Empty disables it. This is infra
	// observability only — NOT a user/proxy-facing API (the worker's only
	// ingress remains the store, spec §8.2).
	MetricsAddr string
	// HeartbeatInterval is the cadence of the process-level liveness heartbeat
	// (one row per worker_id, distinct from the per-intent lease heartbeat). It
	// proves the worker is alive even when idle. Default 10s, floored at 2s so a
	// misconfigured tiny interval can't hammer the store.
	HeartbeatInterval time.Duration
	// HeartbeatProbe toggles the per-backend reachability probe carried in each
	// heartbeat. When false the beat still advances LastSeenAt but ships an empty
	// Health slice — useful to disable connection churn against backends that
	// rate-limit logins. Default true.
	HeartbeatProbe bool
}

// OwnedInstances returns the backend_ids this worker is responsible for: the
// configured whitelist when non-empty, else every backend in the resolved
// DBACreds map. This is the Instances field of the liveness heartbeat and the
// set the probe walks — it mirrors ClaimPendingIntents' "empty whitelist = all"
// semantics by expanding "all" to the concrete backend list the worker holds
// creds for, so the heartbeat row is self-describing rather than an opaque "[]".
func (c Config) OwnedInstances() []string {
	if len(c.InstanceWhitelist) > 0 {
		out := make([]string, len(c.InstanceWhitelist))
		copy(out, c.InstanceWhitelist)
		return out
	}
	out := make([]string, 0, len(c.DBACreds))
	for id := range c.DBACreds {
		out = append(out, id)
	}
	// Deterministic order so the heartbeat row and logs are stable across beats.
	sort.Strings(out)
	return out
}

// fileConfig is the on-disk shape of the -worker-config file. JSON is chosen
// over YAML to avoid a new dep — gopkg.in/yaml.v3 is already vendored, but JSON
// keeps the worker's dependency surface minimal and the file unambiguous.
//
// Secret-bearing fields are references (env://NAME, file:///path) resolved via
// secrets.Resolve, never inline plaintext.
type fileConfig struct {
	// WorkerKeyRef resolves to the 32-byte HMAC seed (raw or base64; see
	// decodeKey). Worker-only.
	WorkerKeyRef string `json:"worker_key_ref"`
	// Backends carries one entry per managed backend.
	Backends []fileBackend `json:"backends"`
}

type fileBackend struct {
	// BackendID matches domain.Backend.ID — the key the store/grant reference.
	BackendID string `json:"backend_id"`
	// DBAUser is the master username (not secret on its own).
	DBAUser string `json:"dba_user"`
	// DBAPassRef resolves to the master password (env://, file://).
	DBAPassRef string `json:"dba_pass_ref"`
}

// LoadConfig assembles the worker config from CLI flags, environment, and the
// -worker-config file, resolving every secret reference through secrets.Resolve.
// It is the single fail-closed boot gate: any unresolved secret aborts startup
// rather than letting the worker run half-credentialed.
func LoadConfig(flags Flags) (Config, error) {
	cfg := Config{
		StoreURL:          flags.StoreURL,
		InstanceWhitelist: parseWhitelist(flags.Whitelist),
		CatchUpInterval:   floorDuration(flags.CatchUpInterval, 5*time.Second),
		LeaseTTL:          flags.LeaseTTL,
		DDLTimeout:        flags.DDLTimeout,
		ClaimBatch:        flags.ClaimBatch,
		WorkerID:          flags.WorkerID,
		MetricsAddr:       flags.MetricsAddr,
		HeartbeatProbe:    flags.HeartbeatProbe,
	}
	// floorDuration applies a 30s default on a non-positive value, which is the
	// catch-up default — not ours. Substitute the heartbeat's 10s default first,
	// then reuse the same 2s floor helper so an explicit tiny value is clamped.
	hbInterval := flags.HeartbeatInterval
	if hbInterval <= 0 {
		hbInterval = 10 * time.Second
	}
	cfg.HeartbeatInterval = floorDuration(hbInterval, 2*time.Second)
	if cfg.StoreURL == "" {
		return Config{}, fmt.Errorf("worker config: store URL is required (PORTAL_STORE / -store)")
	}
	if cfg.WorkerID == "" {
		cfg.WorkerID = defaultWorkerID()
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 60 * time.Second
	}
	if cfg.ClaimBatch <= 0 {
		cfg.ClaimBatch = 16
	}
	if cfg.DDLTimeout <= 0 {
		cfg.DDLTimeout = 20 * time.Second
	}

	// Shared SecretBox key — same env var + loader as the portal so the result
	// columns round-trip through the identical cipher.
	key, err := secrets.LoadKeyFromEnv(flags.SecretboxEnv)
	if err != nil {
		return Config{}, fmt.Errorf("worker config: load secretbox key: %w", err)
	}
	cfg.SecretboxKey = key

	fc, err := loadFile(flags.ConfigPath)
	if err != nil {
		return Config{}, err
	}

	workerKey, err := secrets.Resolve(fc.WorkerKeyRef)
	if err != nil {
		return Config{}, fmt.Errorf("worker config: resolve worker key: %w", err)
	}
	wk, err := decodeKey(workerKey)
	if err != nil {
		return Config{}, fmt.Errorf("worker config: worker key: %w", err)
	}
	cfg.WorkerKey = wk

	cfg.DBACreds = make(map[string]ephemeral.DBACredential, len(fc.Backends))
	for _, b := range fc.Backends {
		if b.BackendID == "" {
			return Config{}, fmt.Errorf("worker config: backend entry missing backend_id")
		}
		pass, rerr := secrets.Resolve(b.DBAPassRef)
		if rerr != nil {
			return Config{}, fmt.Errorf("worker config: resolve dba password for %q: %w", b.BackendID, rerr)
		}
		cfg.DBACreds[b.BackendID] = ephemeral.DBACredential{Username: b.DBAUser, Password: pass}
	}

	return cfg, nil
}

// loadFile reads and parses the -worker-config JSON file. A missing path is a
// hard error: a worker with no backend creds has nothing to do and silently
// idling would mask a misconfiguration.
func loadFile(path string) (fileConfig, error) {
	if path == "" {
		return fileConfig{}, fmt.Errorf("worker config: -worker-config path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("worker config: read %s: %w", path, err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return fileConfig{}, fmt.Errorf("worker config: parse %s: %w", path, err)
	}
	if fc.WorkerKeyRef == "" {
		return fileConfig{}, fmt.Errorf("worker config: worker_key_ref is required")
	}
	return fc, nil
}

// decodeKey resolves a 32-byte HMAC seed from its env/secret-store form.
//
// M2: base64 is tried FIRST. The previous order short-circuited on len(s)==32,
// which silently mis-decoded a 32-character base64 key (e.g. an exactly-padded
// "…=" string) as 32 raw bytes — a different, wrong key. Since crypto seeds are
// conventionally stored base64 (same as the SecretBox key loader), we decode
// base64 in the standard variants and only fall back to raw bytes when none of
// them parse, so an accidental 32-char base64 string can no longer be taken as
// raw material. The raw path therefore requires exactly 32 bytes that are NOT
// valid base64 — document the seed as 32 random bytes if you use it.
func decodeKey(s string) ([]byte, error) {
	trimmed := strings.TrimSpace(s)
	// Try the common base64 alphabets/paddings first; the SecretBox key uses
	// StdEncoding, but URL-safe and unpadded seeds are common in secret stores.
	// A value that PARSES as base64 is treated as base64 even if it decodes to
	// the wrong length — falling back to the raw branch in that case is exactly
	// the M2 ambiguity (a 32-char base64 string mis-used as 32 raw bytes), so we
	// require the base64 to be exactly 32 bytes rather than silently reinterpret.
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(trimmed); err == nil {
			if len(b) == 32 {
				return b, nil
			}
			return nil, fmt.Errorf("worker key: base64-decoded to %d bytes, want 32", len(b))
		}
	}
	// Fall back to raw bytes only when the value did NOT parse as base64 at all
	// and is exactly 32 bytes — e.g. a binary 32-byte key file.
	if len(s) == 32 {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("worker key: not 32 raw bytes and not a base64-encoded 32-byte key")
}

// parseWhitelist splits a comma-separated backend-id list, trimming blanks.
func parseWhitelist(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// floorDuration clamps d to at least min. A zero/negative d (flag/env unset)
// becomes the 30s catch-up default; an explicit value below min is raised to
// min. Note the 30s default is applied HERE, not by the caller.
func floorDuration(d, min time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	if d < min {
		return min
	}
	return d
}

// defaultWorkerID returns hostname-pid so co-located workers stay distinct.
func defaultWorkerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "worker"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}
