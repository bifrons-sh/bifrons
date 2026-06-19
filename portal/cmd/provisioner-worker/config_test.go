package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// b64Key returns a base64-StdEncoding string of n random bytes.
func b64Key(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestDecodeKey(t *testing.T) {
	raw32 := strings.Repeat("a", 32) // 32 raw bytes, not valid base64 (len%4==0 but 'a' decodes fine…)
	std := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	rawStd := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("m", 32)))
	rawURL := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))

	cases := []struct {
		name    string
		in      string
		wantErr bool
		wantLen int
	}{
		{"std base64 32-byte", std, false, 32},
		{"raw-std base64 32-byte", rawStd, false, 32},
		{"raw-url base64 32-byte", rawURL, false, 32},
		// M2: a 32-char value that is ALSO valid base64 must decode as base64
		// (24 bytes here), NOT be taken as 32 raw bytes — so it is rejected for
		// not yielding 32 bytes, rather than silently mis-used as a raw key.
		{"32-char base64 string is not raw", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=", true, 0},
		{"too short", "deadbeef", true, 0},
		{"empty", "", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeKey(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("decodeKey(%q) = %v, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeKey(%q): %v", c.in, err)
			}
			if len(got) != c.wantLen {
				t.Errorf("decodeKey(%q) len = %d, want %d", c.in, len(got), c.wantLen)
			}
		})
	}

	// A 32-byte raw value that is NOT decodable to 32 base64 bytes falls back to
	// the raw path. "aaaa…" (32 'a') base64-decodes to 24 bytes, so it would be
	// rejected; use bytes that fail base64 entirely to exercise the raw branch.
	t.Run("raw 32 bytes fallback", func(t *testing.T) {
		raw := strings.Repeat("\xff", 32) // 0xff is not in any base64 alphabet
		got, err := decodeKey(raw)
		if err != nil {
			t.Fatalf("raw fallback: %v", err)
		}
		if len(got) != 32 {
			t.Errorf("raw fallback len = %d, want 32", len(got))
		}
	})
	_ = raw32
}

// writeConfig writes a worker-config JSON file referencing the given worker-key
// env var and returns its path.
func writeConfig(t *testing.T, dir, workerKeyRef string) string {
	t.Helper()
	p := filepath.Join(dir, "worker.json")
	body := `{"worker_key_ref":"` + workerKeyRef + `","backends":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestOwnedInstances(t *testing.T) {
	// Non-empty whitelist wins verbatim, regardless of DBACreds.
	cfg := Config{
		InstanceWhitelist: []string{"b-2", "b-1"},
		DBACreds:          dbaMap("b-1", "b-2", "b-3"),
	}
	if got := cfg.OwnedInstances(); len(got) != 2 || got[0] != "b-2" || got[1] != "b-1" {
		t.Errorf("with whitelist: OwnedInstances = %v, want [b-2 b-1]", got)
	}

	// Empty whitelist expands to the sorted DBACreds keys ("all").
	cfg.InstanceWhitelist = nil
	got := cfg.OwnedInstances()
	want := []string{"b-1", "b-2", "b-3"}
	if len(got) != len(want) {
		t.Fatalf("no whitelist: OwnedInstances = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("OwnedInstances[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()

	// Shared SecretBox key env (base64, 32 bytes) used by every happy-path case.
	sbEnv := "TEST_SECRETBOX_KEY"
	t.Setenv(sbEnv, b64Key(t, 32))

	// Worker key delivered via env:// ref, base64 32 bytes.
	wkEnv := "TEST_WORKER_KEY"
	t.Setenv(wkEnv, b64Key(t, 32))
	cfgPath := writeConfig(t, dir, "env://"+wkEnv)

	base := func() Flags {
		return Flags{
			StoreURL:     "sqlite:///x.db",
			SecretboxEnv: sbEnv,
			ConfigPath:   cfgPath,
		}
	}

	t.Run("defaults applied", func(t *testing.T) {
		cfg, err := LoadConfig(base())
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.LeaseTTL != 60*time.Second {
			t.Errorf("LeaseTTL = %v, want 60s default", cfg.LeaseTTL)
		}
		if cfg.ClaimBatch != 16 {
			t.Errorf("ClaimBatch = %d, want 16 default", cfg.ClaimBatch)
		}
		if cfg.DDLTimeout != 20*time.Second {
			t.Errorf("DDLTimeout = %v, want 20s default", cfg.DDLTimeout)
		}
		if cfg.CatchUpInterval != 30*time.Second {
			t.Errorf("CatchUpInterval = %v, want 30s default", cfg.CatchUpInterval)
		}
		if cfg.HeartbeatInterval != 10*time.Second {
			t.Errorf("HeartbeatInterval = %v, want 10s default", cfg.HeartbeatInterval)
		}
		if cfg.WorkerID == "" {
			t.Error("WorkerID should default to hostname-pid")
		}
		if len(cfg.WorkerKey) != 32 || len(cfg.SecretboxKey) != 32 {
			t.Errorf("key lengths: worker=%d secretbox=%d", len(cfg.WorkerKey), len(cfg.SecretboxKey))
		}
	})

	t.Run("explicit flags override defaults", func(t *testing.T) {
		f := base()
		f.LeaseTTL = 90 * time.Second
		f.DDLTimeout = 7 * time.Second
		f.ClaimBatch = 4
		f.CatchUpInterval = 12 * time.Second
		f.WorkerID = "fixed-id"
		f.Whitelist = "b-1, b-2 ,, b-3"
		cfg, err := LoadConfig(f)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.LeaseTTL != 90*time.Second || cfg.DDLTimeout != 7*time.Second || cfg.ClaimBatch != 4 {
			t.Errorf("flags not honoured: %+v", cfg)
		}
		if cfg.WorkerID != "fixed-id" {
			t.Errorf("WorkerID = %q", cfg.WorkerID)
		}
		want := []string{"b-1", "b-2", "b-3"}
		if len(cfg.InstanceWhitelist) != len(want) {
			t.Fatalf("whitelist = %v, want %v", cfg.InstanceWhitelist, want)
		}
		for i := range want {
			if cfg.InstanceWhitelist[i] != want[i] {
				t.Errorf("whitelist[%d] = %q, want %q", i, cfg.InstanceWhitelist[i], want[i])
			}
		}
	})

	t.Run("catch-up floored to 5s", func(t *testing.T) {
		f := base()
		f.CatchUpInterval = time.Second // below the 5s floor
		cfg, err := LoadConfig(f)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.CatchUpInterval != 5*time.Second {
			t.Errorf("CatchUpInterval = %v, want floored to 5s", cfg.CatchUpInterval)
		}
	})

	t.Run("heartbeat interval floored to 2s", func(t *testing.T) {
		f := base()
		f.HeartbeatInterval = 500 * time.Millisecond // below the 2s floor
		cfg, err := LoadConfig(f)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.HeartbeatInterval != 2*time.Second {
			t.Errorf("HeartbeatInterval = %v, want floored to 2s", cfg.HeartbeatInterval)
		}
	})

	t.Run("missing store URL is fatal", func(t *testing.T) {
		f := base()
		f.StoreURL = ""
		if _, err := LoadConfig(f); err == nil {
			t.Fatal("expected error for missing store URL")
		}
	})

	t.Run("missing config path is fatal", func(t *testing.T) {
		f := base()
		f.ConfigPath = ""
		if _, err := LoadConfig(f); err == nil {
			t.Fatal("expected error for missing worker-config path")
		}
	})

	t.Run("non-32-byte worker key rejected", func(t *testing.T) {
		shortEnv := "TEST_WORKER_KEY_SHORT"
		t.Setenv(shortEnv, b64Key(t, 16)) // 16 bytes, not 32
		f := base()
		f.ConfigPath = writeConfig(t, t.TempDir(), "env://"+shortEnv)
		if _, err := LoadConfig(f); err == nil {
			t.Fatal("expected error for 16-byte worker key")
		}
	})

	t.Run("unresolvable worker key ref is fatal", func(t *testing.T) {
		f := base()
		f.ConfigPath = writeConfig(t, t.TempDir(), "env://DEFINITELY_UNSET_VAR_XYZ")
		if _, err := LoadConfig(f); err == nil {
			t.Fatal("expected error for unresolvable worker key ref")
		}
	})
}
