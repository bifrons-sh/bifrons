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
      - instance: "prod-pg"
        database: "orders"
        level: "dba"
        mode: "ephemeral"
      - instance: "prod-pg"
        database: "orders"
        level: "app"
        # mode omitted → defaults to permanent
  - id: "guid-dev"
    allow:
      - instance: "prod-pg"
        database: "orders"
        level: "ro"
        mode: "permanent"
`)
	p, err := LoadRequestPolicy(path)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		groups   []string
		instance string
		database string
		level    string
		wantMode AccessMode
		wantErr  bool
	}{
		{[]string{"guid-dba"}, "prod-pg", "orders", "dba", ModeEphemeral, false},
		{[]string{"guid-dba"}, "prod-pg", "orders", "app", ModePermanent, false},
		{[]string{"guid-dba"}, "prod-pg", "orders", "ro", "", true}, // level not listed
		{[]string{"guid-dev"}, "prod-pg", "orders", "ro", ModePermanent, false},
		{[]string{"guid-dev"}, "prod-pg", "orders", "dba", "", true},
		{[]string{"guid-none"}, "prod-pg", "orders", "ro", "", true},
		{nil, "prod-pg", "orders", "ro", "", true},
		{[]string{"guid-dev", "guid-dba"}, "prod-pg", "orders", "dba", ModeEphemeral, false}, // union
		{[]string{"guid-dba"}, "prod-pg", "other-db", "app", "", true},                       // db doesn't match
	}
	for _, c := range cases {
		mode, err := p.Authorize(c.groups, c.instance, c.database, c.level)
		gotErr := err != nil
		if gotErr != c.wantErr {
			t.Errorf("groups=%v %s/%s/%s: err=%v want_err=%v",
				c.groups, c.instance, c.database, c.level, err, c.wantErr)
		}
		if !gotErr && mode != c.wantMode {
			t.Errorf("groups=%v %s/%s/%s: mode=%q want %q",
				c.groups, c.instance, c.database, c.level, mode, c.wantMode)
		}
		if gotErr && !errors.Is(err, ErrRequestNotAllowed) {
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
      - instance: "i"
        database: "d"
        level: "ro"
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-id error")
		}
	})
	t.Run("missing instance", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - database: "d"
        level: "ro"
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-instance error")
		}
	})
	t.Run("missing database", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - instance: "i"
        level: "ro"
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-database error")
		}
	})
	t.Run("missing level", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - instance: "i"
        database: "d"
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected missing-level error")
		}
	})
	t.Run("invalid mode", func(t *testing.T) {
		path := writeTemp(t, `
groups:
  - id: "g"
    allow:
      - instance: "i"
        database: "d"
        level: "ro"
        mode: "lol"
`)
		if _, err := LoadRequestPolicy(path); err == nil {
			t.Error("expected invalid-mode error")
		}
	})
}

func TestAuthorize_NilPolicyDenies(t *testing.T) {
	var p *RequestPolicy
	if _, err := p.Authorize([]string{"g"}, "i", "d", "ro"); !errors.Is(err, ErrRequestNotAllowed) {
		t.Errorf("nil policy should deny, got %v", err)
	}
}

func TestNewRequestPolicy_Programmatic(t *testing.T) {
	p := NewRequestPolicy(map[string]map[Trio]AccessMode{
		"g1": {{Instance: "i1", Database: "d1", Level: "app"}: ModePermanent},
	})
	if mode, err := p.Authorize([]string{"g1"}, "i1", "d1", "app"); err != nil || mode != ModePermanent {
		t.Errorf("want allow permanent, got %q err=%v", mode, err)
	}
	if _, err := p.Authorize([]string{"g1"}, "i1", "d1", "dba"); err == nil {
		t.Error("want deny")
	}
	if gs := p.Groups(); len(gs) != 1 || gs[0] != "g1" {
		t.Errorf("Groups(): %+v", gs)
	}
}
