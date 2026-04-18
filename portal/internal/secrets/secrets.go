// Package secrets resolves pluggable references like "env://NAME", "file:///p",
// or "inline://literal" to the underlying secret string. Providers are looked
// up by URI scheme so new backends (Vault, AWS Secrets Manager, ...) can plug
// in via build-tag-gated init() registrations without the core growing deps.
package secrets

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Provider resolves a scheme-specific key into its secret value.
// Implementations must be safe for concurrent use — Resolve is called on every
// /auth lookup from the policy engine.
type Provider interface {
	Get(key string) (string, error)
}

// ProviderFunc adapts a plain func to the Provider interface.
type ProviderFunc func(key string) (string, error)

// Get implements Provider.
func (f ProviderFunc) Get(key string) (string, error) { return f(key) }

// Registry maps URI schemes to providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry returns an empty registry. Tests use this to avoid mutating the
// process-global default.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}}
}

// Register installs p under scheme. Panics on duplicate or nil — misconfig is
// a boot-time bug, fail loud.
func (r *Registry) Register(scheme string, p Provider) {
	if p == nil {
		panic("secrets: nil provider for scheme " + scheme)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[scheme]; exists {
		panic("secrets: duplicate provider for scheme " + scheme)
	}
	r.providers[scheme] = p
}

// Resolve parses ref as "scheme://key" and dispatches to the registered provider.
func (r *Registry) Resolve(ref string) (string, error) {
	if ref == "" {
		return "", errors.New("secrets: empty reference")
	}
	idx := strings.Index(ref, "://")
	if idx <= 0 {
		return "", fmt.Errorf("secrets: reference %q missing scheme (want scheme://key)", ref)
	}
	scheme := ref[:idx]
	key := ref[idx+3:]

	r.mu.RLock()
	p, ok := r.providers[scheme]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("secrets: unknown scheme %q", scheme)
	}
	return p.Get(key)
}

// defaultRegistry holds the built-in providers. Tests use NewRegistry() to
// avoid sharing state.
var defaultRegistry = NewRegistry()

// Resolve dispatches ref against the default registry.
func Resolve(ref string) (string, error) { return defaultRegistry.Resolve(ref) }

// Register installs p on the default registry.
func Register(scheme string, p Provider) { defaultRegistry.Register(scheme, p) }

// EnvProvider reads secrets from environment variables.
type EnvProvider struct{}

// Get returns the env var value, or an error if unset or key is empty.
func (EnvProvider) Get(key string) (string, error) {
	if key == "" {
		return "", errors.New("secrets/env: empty key")
	}
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("secrets/env: %q not set", key)
	}
	return v, nil
}

// FileProvider reads secrets from files, enforcing strict permissions so a
// world-readable secret file becomes a fail-closed configuration error instead
// of a silent leak. A trailing newline (common with `echo "x" > secret`) is
// stripped — operators rarely intend it.
type FileProvider struct{}

// Get reads the file and returns its contents.
//
// Opens the file *before* checking permissions and stats the resulting fd, so a
// symlink swap between check and read can't bypass the mode guard. Regular
// files only — directories, symlinks pointing at non-files, and special files
// are rejected. The permission check is owner-only (no group/other bits).
func (FileProvider) Get(key string) (string, error) {
	if key == "" {
		return "", errors.New("secrets/file: empty key")
	}
	f, err := os.Open(key)
	if err != nil {
		return "", fmt.Errorf("secrets/file: open %q: %w", key, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("secrets/file: stat %q: %w", key, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secrets/file: %q is not a regular file", key)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf("secrets/file: %q has unsafe permissions %04o (want 0600 or stricter)", key, mode)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("secrets/file: read %q: %w", key, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// InlineProvider returns the key verbatim.
//
// Deprecated: inline secrets defeat the point of the secrets package — they
// live in the same store row as everything else. Use env:// or file:// for
// anything real. Kept for bootstrap / smoke-test flows.
type InlineProvider struct{}

// Get implements Provider.
func (InlineProvider) Get(key string) (string, error) { return key, nil }

func init() {
	defaultRegistry.Register("env", EnvProvider{})
	defaultRegistry.Register("file", FileProvider{})
	defaultRegistry.Register("inline", InlineProvider{})
}
