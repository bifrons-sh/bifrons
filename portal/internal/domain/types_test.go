package domain

import (
	"strings"
	"testing"
	"time"
)

func TestGrant_IsActive(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		g    Grant
		want bool
	}{
		{"active within TTL", Grant{Status: GrantActive, ExpiresAt: &future}, true},
		{"active past TTL", Grant{Status: GrantActive, ExpiresAt: &past}, false},
		{"active no expiry", Grant{Status: GrantActive}, true},
		{"active but revoked", Grant{Status: GrantActive, ExpiresAt: &future, RevokedAt: &past}, false},
		{"pending", Grant{Status: GrantPending, ExpiresAt: &future}, false},
		{"approved (not yet claimed)", Grant{Status: GrantApproved, ExpiresAt: &future}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.g.IsActive(now); got != c.want {
				t.Errorf("IsActive=%v want %v", got, c.want)
			}
		})
	}
}

func TestGrant_IsEphemeral(t *testing.T) {
	if (Grant{PolicyMode: ModeEphemeral}).IsEphemeral() != true {
		t.Error("ModeEphemeral should be ephemeral")
	}
	if (Grant{PolicyMode: ModePermanent}).IsEphemeral() != false {
		t.Error("ModePermanent should not be ephemeral")
	}
	if (Grant{}).IsEphemeral() != false {
		t.Error("empty (unset) mode should default to non-ephemeral")
	}
}

func TestGrant_PhasePredicates(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// Nil deadline → never past; consistent with "feature disabled" semantics.
	g := Grant{}
	if g.IsPastValidationWindow(now) || g.IsPastClaimWindow(now) || g.IsPastCredentialTTL(now) {
		t.Error("zero Grant should not be past any window")
	}

	// Explicit past.
	gPast := Grant{RequestExpiresAt: &past, ClaimExpiresAt: &past, ExpiresAt: &past}
	if !gPast.IsPastValidationWindow(now) {
		t.Error("IsPastValidationWindow false for past deadline")
	}
	if !gPast.IsPastClaimWindow(now) {
		t.Error("IsPastClaimWindow false for past deadline")
	}
	if !gPast.IsPastCredentialTTL(now) {
		t.Error("IsPastCredentialTTL false for past deadline")
	}

	// Explicit future.
	gFuture := Grant{RequestExpiresAt: &future, ClaimExpiresAt: &future, ExpiresAt: &future}
	if gFuture.IsPastValidationWindow(now) || gFuture.IsPastClaimWindow(now) || gFuture.IsPastCredentialTTL(now) {
		t.Error("future deadlines should not be past")
	}
}

func TestNewID_HexAndUnique(t *testing.T) {
	a := NewID("g")
	b := NewID("g")
	if a == b {
		t.Error("NewID must be unique across calls")
	}
	if !strings.HasPrefix(a, "g-") {
		t.Errorf("NewID prefix lost: %q", a)
	}
	if len(a) != 2+16 { // "g-" + 8 bytes hex
		t.Errorf("NewID shape: %q len=%d", a, len(a))
	}
	for _, c := range strings.TrimPrefix(a, "g-") {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex char %q in %q", c, a)
		}
	}
}

func TestNewSecret_Entropy(t *testing.T) {
	a := NewSecret()
	b := NewSecret()
	if a == b {
		t.Error("NewSecret must be unique")
	}
	if len(a) != 64 {
		t.Errorf("NewSecret len=%d want 64 (256-bit hex)", len(a))
	}
	for _, c := range a {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex char %q in %q", c, a)
		}
	}
}

func TestAccessMode_ScanValue(t *testing.T) {
	// Value: empty maps to "" string (NOT NULL) to satisfy the schema default.
	v, err := ModePermanent.Value()
	if err != nil || v != "permanent" {
		t.Errorf("Value(permanent) = (%v, %v)", v, err)
	}
	v, err = AccessMode("").Value()
	if err != nil || v != "" {
		t.Errorf("Value(empty) = (%v, %v), want (\"\", nil)", v, err)
	}

	// Scan: accept string, []byte, nil; reject anything else.
	var m AccessMode
	if err := m.Scan("ephemeral"); err != nil || m != ModeEphemeral {
		t.Errorf("Scan(string) = (%v, %v)", m, err)
	}
	m = ""
	if err := m.Scan([]byte("permanent")); err != nil || m != ModePermanent {
		t.Errorf("Scan([]byte) = (%v, %v)", m, err)
	}
	m = ModePermanent
	if err := m.Scan(nil); err != nil || m != "" {
		t.Errorf("Scan(nil) = (%v, %v), want empty", m, err)
	}
	if err := m.Scan(42); err == nil {
		t.Error("Scan(int) should error")
	}
}

func TestBackend_Address(t *testing.T) {
	b := Backend{Host: "10.0.0.1", Port: 5432}
	if got := b.Address(); got != "10.0.0.1:5432" {
		t.Errorf("Address=%q", got)
	}
}

func TestBackendAccount_LogValue_Redacts(t *testing.T) {
	a := BackendAccount{ID: "ba-1", Username: "app", Password: "s3cret", PasswordRef: "env://X"}
	attrs := map[string]string{}
	for _, a := range a.LogValue().Group() {
		attrs[a.Key] = a.Value.String()
	}
	for _, k := range []string{"password", "password_ref"} {
		if attrs[k] != "<redacted>" {
			t.Errorf("%s=%q want <redacted>", k, attrs[k])
		}
	}
	if strings.Contains(attrs["password"], "s3cret") {
		t.Error("plaintext leaked through LogValue")
	}
}

func TestGrant_LogValue_Redacts(t *testing.T) {
	g := Grant{ID: "g-1", PortalPassword: "p", EphemeralPassword: "e"}
	attrs := map[string]string{}
	for _, a := range g.LogValue().Group() {
		attrs[a.Key] = a.Value.String()
	}
	for _, k := range []string{"portal_password", "ephemeral_password"} {
		if attrs[k] != "<redacted>" {
			t.Errorf("%s=%q want <redacted>", k, attrs[k])
		}
	}
}
