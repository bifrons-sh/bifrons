package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRequestPolicy_Success(t *testing.T) {
	path := writeTemp(t, `
groups:
  - id: "guid-dba"
    name: "DBA Admins"
    allow:
      - backend: "b-prod-pg"
        roles: ["app", "dba"]
      - backend: "b-prod-mysql"
        roles: ["app"]
  - id: "guid-dev"
    allow:
      - backend: "b-prod-pg"
        roles: ["app"]
`)
	p, err := LoadRequestPolicy(path)
	if err != nil {
		t.Fatal(err)
	}

	// allow matrix:
	cases := []struct {
		groups    []string
		backend   string
		role      string
		wantAllow bool
	}{
		{[]string{"guid-dba"}, "b-prod-pg", "dba", true},
		{[]string{"guid-dba"}, "b-prod-pg", "app", true},
		{[]string{"guid-dba"}, "b-prod-mysql", "dba", false}, // role not listed
		{[]string{"guid-dev"}, "b-prod-pg", "app", true},
		{[]string{"guid-dev"}, "b-prod-pg", "dba", false},
		{[]string{"guid-none"}, "b-prod-pg", "app", false}, // unknown group
		{nil, "b-prod-pg", "app", false},
		{[]string{"guid-dev", "guid-dba"}, "b-prod-pg", "dba", true}, // union across groups
	}
	for _, c := range cases {
		err := p.Authorize(c.groups, c.backend, c.role)
		got := err == nil
		if got != c.wantAllow {
			t.Errorf("groups=%v backend=%s role=%s: got allow=%v err=%v want=%v",
				c.groups, c.backend, c.role, got, err, c.wantAllow)
		}
		if !got && !errors.Is(err, ErrRequestNotAllowed) {
			t.Errorf("non-allow should return ErrRequestNotAllowed, got %v", err)
		}
	}
}

func TestLoadRequestPolicy_Errors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadRequestPolicy("/nope/nope.yaml"); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("malformed yaml", func(t *testing.T) {
		path := writeTemp(t, "groups: [::::")
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected parse error")
		}
	})
	t.Run("missing group id", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - name: "no id"
    allow:
      - backend: "b"
        roles: ["app"]
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-id error")
		}
	})
	t.Run("missing backend", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - roles: ["app"]
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-backend error")
		}
	})
	t.Run("missing roles", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - backend: "b"
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-roles error")
		}
	})
	t.Run("empty role string", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - backend: "b"
        roles: [""]
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected empty-role error")
		}
	})
}

func TestAuthorize_NilPolicyDenies(t *testing.T) {
	var p *RequestPolicy
	if err := p.Authorize([]string{"g"}, "b", "app"); !errors.Is(err, ErrRequestNotAllowed) {
		t.Errorf("nil policy should deny, got %v", err)
	}
}

func TestNewRequestPolicy_Programmatic(t *testing.T) {
	p := NewRequestPolicy(map[string]map[string][]string{
		"g1": {"b1": {"app"}},
	})
	if err := p.Authorize([]string{"g1"}, "b1", "app"); err != nil {
		t.Errorf("want allow, got %v", err)
	}
	if err := p.Authorize([]string{"g1"}, "b1", "dba"); err == nil {
		t.Error("want deny")
	}
	if gs := p.Groups(); len(gs) != 1 || gs[0] != "g1" {
		t.Errorf("Groups(): %+v", gs)
	}
}
