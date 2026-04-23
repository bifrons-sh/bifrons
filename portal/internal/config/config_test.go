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
		t.Error("Entra without admin reachability should fail")
	}
	// Either setting is enough.
	c.Entra.AdminMailbox = "admins@example.com"
	if err := c.Validate(); err != nil {
		t.Errorf("mailbox alone should satisfy, got %v", err)
	}
	c.Entra.AdminMailbox = ""
	c.Entra.AdminGroupID = "grp-admins"
	if err := c.Validate(); err != nil {
		t.Errorf("group-id alone should satisfy, got %v", err)
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
