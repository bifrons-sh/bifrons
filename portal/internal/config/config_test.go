package config

import (
	"strings"
	"testing"
	"time"
)

// baseValid returns a Config that should pass Validate; individual tests
// mutate one field and re-check.
func baseValid() *Config {
	return &Config{
		HTTP: HTTP{
			ListenAddr:        "127.0.0.1:8080",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			ShutdownGrace:     10 * time.Second,
		},
		Windows: Windows{
			Validation:    24 * time.Hour,
			Claim:         time.Hour,
			CredentialTTL: time.Hour,
		},
	}
}

func TestValidate_Happy(t *testing.T) {
	if err := baseValid().Validate(); err != nil {
		t.Errorf("baseline should validate, got %v", err)
	}
}

func TestValidate_RequiresListen(t *testing.T) {
	c := baseValid()
	c.HTTP.ListenAddr = ""
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("empty HTTP.ListenAddr should fail with 'listen…', got %v", err)
	}
}

func TestValidate_RejectsNegativeTimeouts(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"ReadHeaderTimeout": func(c *Config) { c.HTTP.ReadHeaderTimeout = -1 },
		"ReadTimeout":       func(c *Config) { c.HTTP.ReadTimeout = -1 },
		"WriteTimeout":      func(c *Config) { c.HTTP.WriteTimeout = -1 },
		"ShutdownGrace":     func(c *Config) { c.HTTP.ShutdownGrace = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := baseValid()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s < 0 should fail", name)
			}
		})
	}
}

func TestValidate_RejectsNegativeWindows(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"Validation":    func(c *Config) { c.Windows.Validation = -1 },
		"Claim":         func(c *Config) { c.Windows.Claim = -1 },
		"CredentialTTL": func(c *Config) { c.Windows.CredentialTTL = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := baseValid()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s < 0 should fail", name)
			}
		})
	}
}

// TestValidate_RejectsZeroCredentialTTL: a credential TTL of exactly 0 must be
// rejected (H6). Negative is covered by TestValidate_RejectsNegativeWindows;
// this guards the boundary that would otherwise mint a non-expiring credential.
func TestValidate_RejectsZeroCredentialTTL(t *testing.T) {
	c := baseValid()
	c.Windows.CredentialTTL = 0
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "credential-ttl") {
		t.Errorf("CredentialTTL == 0 should fail with 'credential-ttl…', got %v", err)
	}
}

// TestValidate_NoAuthOnNonLoopback: with no auth path configured (empty tokens,
// OIDC disabled), boot must fail on a non-loopback listener (L1) but succeed on
// loopback (local dev). Configuring any single auth path lifts the gate.
func TestValidate_NoAuthOnNonLoopback(t *testing.T) {
	// Non-loopback + no auth → reject.
	c := baseValid()
	c.HTTP.ListenAddr = "0.0.0.0:8080"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "no authentication") {
		t.Errorf("no-auth on non-loopback should fail, got %v", err)
	}
	// Bare ":port" binds all interfaces → also non-loopback → reject.
	c = baseValid()
	c.HTTP.ListenAddr = ":8080"
	if err := c.Validate(); err == nil {
		t.Errorf("no-auth on bare :port should fail, got nil")
	}
	// Loopback is the local-dev escape hatch → allowed.
	c = baseValid()
	c.HTTP.ListenAddr = "127.0.0.1:8080"
	if err := c.Validate(); err != nil {
		t.Errorf("no-auth on loopback should be allowed, got %v", err)
	}
	// Any single auth path lifts the gate even on a public listener.
	for name, set := range map[string]func(*Config){
		"ProxyToken": func(c *Config) { c.ProxyToken = "p" },
		"UserToken":  func(c *Config) { c.UserToken = "u" },
		"OIDC":       func(c *Config) { c.OIDC.IssuerURL = "https://idp.example.com" },
	} {
		t.Run(name, func(t *testing.T) {
			c := baseValid()
			c.HTTP.ListenAddr = "0.0.0.0:8080"
			set(c)
			if err := c.Validate(); err != nil {
				t.Errorf("%s set should allow non-loopback boot, got %v", name, err)
			}
		})
	}
}

// TestValidate_EntraRequiresAdminReachability: when Entra is enabled AND no
// mailbox / group is set, boot must fail — otherwise every dual-gate grant
// strands at VALIDATOR_APPROVED with no way to surface the admin half.
func TestValidate_EntraRequiresAdminReachability(t *testing.T) {
	c := baseValid()
	c.Entra.TenantID = "t"
	c.Entra.ClientID = "c"
	c.Entra.ClientSecret = "s"
	c.Entra.SenderUPN = "x@y"
	if !c.Entra.Enabled() {
		t.Fatal("test setup: Entra.Enabled should be true")
	}
	if err := c.Validate(); err == nil {
		t.Error("Entra without T2 reachability fallback should fail")
	}
	// T2 mailbox satisfies the reachability requirement. Per-backend T2
	// group is the primary source — the mailbox is the safety net.
	c.Entra.T2Mailbox = "admins@example.com"
	if err := c.Validate(); err != nil {
		t.Errorf("T2 mailbox alone should satisfy, got %v", err)
	}
}

// TestEntra_Enabled_NeedsAuthTrio: Entra is considered enabled only when the
// three auth fields (tenant + client id + client secret) are all populated.
// SenderUPN is independent — the mail notifier gates itself on its own
// sender string.
func TestEntra_Enabled_NeedsAuthTrio(t *testing.T) {
	full := Entra{TenantID: "t", ClientID: "c", ClientSecret: "s"}
	if !full.Enabled() {
		t.Error("populated auth trio should be enabled")
	}
	for name, drop := range map[string]func(*Entra){
		"TenantID":     func(e *Entra) { e.TenantID = "" },
		"ClientID":     func(e *Entra) { e.ClientID = "" },
		"ClientSecret": func(e *Entra) { e.ClientSecret = "" },
	} {
		t.Run(name, func(t *testing.T) {
			e := full
			drop(&e)
			if e.Enabled() {
				t.Errorf("Entra.Enabled should return false when %s is empty", name)
			}
		})
	}
}
