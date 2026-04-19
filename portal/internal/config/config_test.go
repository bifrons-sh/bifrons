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
		ListenAddr:        "127.0.0.1:8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ShutdownGrace:     10 * time.Second,
		ValidationWindow:  24 * time.Hour,
		ClaimWindow:       time.Hour,
		CredentialTTL:     time.Hour,
	}
}

func TestValidate_Happy(t *testing.T) {
	if err := baseValid().Validate(); err != nil {
		t.Errorf("baseline should validate, got %v", err)
	}
}

func TestValidate_RequiresListen(t *testing.T) {
	c := baseValid()
	c.ListenAddr = ""
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("empty ListenAddr should fail with 'listen…', got %v", err)
	}
}

func TestValidate_RejectsNegativeTimeouts(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"ReadHeaderTimeout": func(c *Config) { c.ReadHeaderTimeout = -1 },
		"ReadTimeout":       func(c *Config) { c.ReadTimeout = -1 },
		"WriteTimeout":      func(c *Config) { c.WriteTimeout = -1 },
		"ShutdownGrace":     func(c *Config) { c.ShutdownGrace = -1 },
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
		"ValidationWindow": func(c *Config) { c.ValidationWindow = -1 },
		"ClaimWindow":      func(c *Config) { c.ClaimWindow = -1 },
		"CredentialTTL":    func(c *Config) { c.CredentialTTL = -1 },
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
// strands at MANAGER_APPROVED with no way to surface the admin half.
func TestValidate_EntraRequiresAdminReachability(t *testing.T) {
	c := baseValid()
	c.EntraTenantID = "t"
	c.EntraClientID = "c"
	c.EntraClientSecret = "s"
	c.EntraSenderUPN = "x@y"
	if !c.EntraEnabled() {
		t.Fatal("test setup: EntraEnabled should be true")
	}
	if err := c.Validate(); err == nil {
		t.Error("Entra without admin reachability should fail")
	}
	// Either setting is enough.
	c.EntraAdminMailbox = "admins@example.com"
	if err := c.Validate(); err != nil {
		t.Errorf("mailbox alone should satisfy, got %v", err)
	}
	c.EntraAdminMailbox = ""
	c.EntraAdminGroupID = "grp-admins"
	if err := c.Validate(); err != nil {
		t.Errorf("group-id alone should satisfy, got %v", err)
	}
}

// TestEntraEnabled_NeedsAuthTrio: Entra is considered enabled only when the
// three auth fields (tenant + client id + client secret) are all populated.
// SenderUPN is independent — the mail notifier gates itself on its own
// sender string.
func TestEntraEnabled_NeedsAuthTrio(t *testing.T) {
	full := &Config{EntraTenantID: "t", EntraClientID: "c", EntraClientSecret: "s"}
	if !full.EntraEnabled() {
		t.Error("populated auth trio should be enabled")
	}
	for name, drop := range map[string]func(*Config){
		"TenantID":     func(c *Config) { c.EntraTenantID = "" },
		"ClientID":     func(c *Config) { c.EntraClientID = "" },
		"ClientSecret": func(c *Config) { c.EntraClientSecret = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := *full // copy
			drop(&c)
			if c.EntraEnabled() {
				t.Errorf("EntraEnabled should return false when %s is empty", name)
			}
		})
	}
}
