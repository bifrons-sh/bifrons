package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	// file:// fixtures: one with strict 0600 perms, one world-readable.
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok.secret")
	if err := os.WriteFile(okPath, []byte("file-value\n"), 0o600); err != nil {
		t.Fatalf("write ok secret: %v", err)
	}
	looseP := filepath.Join(dir, "loose.secret")
	if err := os.WriteFile(looseP, []byte("nope"), 0o644); err != nil {
		t.Fatalf("write loose secret: %v", err)
	}
	missingP := filepath.Join(dir, "does-not-exist")

	tests := []struct {
		name    string
		ref     string
		setup   func(t *testing.T)
		want    string
		wantErr bool
		errSub  string
	}{
		{
			name: "env scheme reads env var",
			ref:  "env://TEST_SECRET_PW",
			setup: func(t *testing.T) {
				t.Setenv("TEST_SECRET_PW", "env-value")
			},
			want: "env-value",
		},
		{
			name:    "env missing var",
			ref:     "env://NOT_SET_VAR_XYZ",
			wantErr: true,
			errSub:  "not set",
		},
		{
			name:    "env empty key",
			ref:     "env://",
			wantErr: true,
			errSub:  "empty key",
		},
		{
			name: "file 0600 reads and trims trailing newline",
			ref:  "file://" + okPath,
			want: "file-value",
		},
		{
			name:    "file world-readable rejected",
			ref:     "file://" + looseP,
			wantErr: true,
			errSub:  "permissions",
		},
		{
			name:    "file missing path",
			ref:     "file://" + missingP,
			wantErr: true,
		},
		{
			name:    "file empty key",
			ref:     "file://",
			wantErr: true,
			errSub:  "empty key",
		},
		{
			name:    "unknown scheme",
			ref:     "vault://kv/data/pw",
			wantErr: true,
			errSub:  "unknown",
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
			errSub:  "empty",
		},
		{
			name:    "missing scheme",
			ref:     "just-a-value",
			wantErr: true,
			errSub:  "scheme",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(t)
			}
			got, err := Resolve(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err %q does not contain %q", err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestRegistry_RegisterAndDispatch(t *testing.T) {
	// Fresh registry; must not touch the default one.
	reg := NewRegistry()
	reg.Register("test", ProviderFunc(func(key string) (string, error) {
		if key == "boom" {
			return "", errors.New("simulated failure")
		}
		return "val-" + key, nil
	}))

	got, err := reg.Resolve("test://hello")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "val-hello" {
		t.Fatalf("got %q", got)
	}

	if _, err := reg.Resolve("test://boom"); err == nil {
		t.Fatalf("expected provider error")
	}

	if _, err := reg.Resolve("unknown://x"); err == nil {
		t.Fatalf("expected unknown-scheme error")
	}
}

// TestFileProvider_RejectsSymlink confirms O_NOFOLLOW: a symlink at the
// configured path fails the open instead of silently following to a
// potentially attacker-controlled target.
func TestFileProvider_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := dir + "/real.pw"
	if err := os.WriteFile(real, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := dir + "/link.pw"
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileProvider{}).Get(link); err == nil {
		t.Fatal("expected symlink to be rejected, got nil")
	}
}

func TestRegistry_RejectsNilProvider(t *testing.T) {
	reg := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic on nil provider")
		}
	}()
	reg.Register("x", nil)
}
