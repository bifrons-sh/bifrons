package policy

import (
	"errors"
	"fmt"
	"os"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"gopkg.in/yaml.v3"
)

// ErrRequestNotAllowed is returned by RequestPolicy.Authorize when no allowed
// group grants the requested (instance, database, level) trio.
var ErrRequestNotAllowed = errors.New("request not allowed by Entra policy")

// AccessMode aliases domain.AccessMode so existing policy-package call sites
// keep working — the canonical type lives on the grant.
//   - "permanent" — shared BackendAccount, no per-grant provisioning.
//   - "ephemeral" — per-grant DB account created at /claim time and dropped
//     on revoke/expire. Requires a DBA BackendAccount on the backend.
type AccessMode = domain.AccessMode

const (
	ModePermanent = domain.ModePermanent
	ModeEphemeral = domain.ModeEphemeral
)

// RequestPolicy compiles the YAML group → allowed-trio table the portal
// consults before accepting a non-admin grant request. The trio shape is
//
//	(instance alias, database, level) → mode
//
// where instance is the Backend.Name, database is a specific DB on that
// instance, level is one of "ro" / "app" / "dba", and mode controls
// provisioning. Authorize returns the matching mode on success so callers
// can branch ephemeral vs permanent without a second YAML lookup.
type RequestPolicy struct {
	// byGroup is indexed by group SLUG — the portal-local group identifier the
	// grant create handler passes to Authorize (it derives keys from
	// store.Group.Slug, not the upstream IdP group id). Keying on anything else
	// here would fail every non-operator request closed (403). Each inner map
	// is keyed by (instance|database|level) → mode.
	byGroup map[string]map[trioKey]AccessMode
}

type trioKey struct {
	instance string
	database string
	level    string
}

type policyFile struct {
	Groups []policyGroup `yaml:"groups"`
}

type policyGroup struct {
	// Slug is the lookup key: it MUST match store.Group.Slug (the portal-local
	// slug the grant create handler resolves from the user's group membership).
	// This is NOT the upstream IdP group id. For backward compatibility with
	// older single-field configs, when Slug is empty the legacy ID field is
	// used as the lookup key — but operators should populate Slug going forward.
	Slug string `yaml:"slug"`
	// ID is optional, opaque metadata only (e.g. the upstream Entra group id
	// recorded for traceability). It is never used for lookup unless Slug is
	// empty (legacy fallback above).
	ID    string        `yaml:"id"`
	Name  string        `yaml:"name"`
	Allow []policyAllow `yaml:"allow"`
}

// lookupKey returns the group's policy lookup key: the slug, falling back to
// the legacy id when no slug is set. Slugs are what Authorize is called with.
func (g policyGroup) lookupKey() string {
	if g.Slug != "" {
		return g.Slug
	}
	return g.ID
}

type policyAllow struct {
	Instance string `yaml:"instance"`
	Database string `yaml:"database"`
	Level    string `yaml:"level"`
	Mode     string `yaml:"mode"`
}

// LoadRequestPolicy reads a YAML policy file and compiles it. Any error (file
// missing, malformed YAML, empty group id, empty instance/database/level,
// invalid mode) is surfaced — callers at boot should exit 2 so operators
// don't silently lose RBAC scoping.
func LoadRequestPolicy(path string) (*RequestPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("entra policy: read %s: %w", path, err)
	}
	var f policyFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("entra policy: parse %s: %w", path, err)
	}
	p := &RequestPolicy{byGroup: map[string]map[trioKey]AccessMode{}}
	for i, g := range f.Groups {
		key := g.lookupKey()
		if key == "" {
			return nil, fmt.Errorf("entra policy: groups[%d] missing slug (lookup key)", i)
		}
		for j, a := range g.Allow {
			if a.Instance == "" {
				return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] missing instance", i, j)
			}
			if a.Database == "" {
				return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] missing database", i, j)
			}
			if a.Level == "" {
				return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] missing level", i, j)
			}
			mode := AccessMode(a.Mode)
			if mode == "" {
				mode = ModePermanent
			}
			if mode != ModePermanent && mode != ModeEphemeral {
				return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] invalid mode %q (want permanent|ephemeral)", i, j, a.Mode)
			}
			trios, ok := p.byGroup[key]
			if !ok {
				trios = map[trioKey]AccessMode{}
				p.byGroup[key] = trios
			}
			trios[trioKey{instance: a.Instance, database: a.Database, level: a.Level}] = mode
		}
	}
	return p, nil
}

// NewRequestPolicy builds a policy in-memory from pre-compiled trios. Intended
// for tests; production callers go through LoadRequestPolicy.
func NewRequestPolicy(groups map[string]map[Trio]AccessMode) *RequestPolicy {
	p := &RequestPolicy{byGroup: map[string]map[trioKey]AccessMode{}}
	for gid, trios := range groups {
		p.byGroup[gid] = map[trioKey]AccessMode{}
		for k, mode := range trios {
			if mode == "" {
				mode = ModePermanent
			}
			p.byGroup[gid][trioKey{instance: k.Instance, database: k.Database, level: k.Level}] = mode
		}
	}
	return p
}

// Trio is the public, exported shape callers use with NewRequestPolicy. The
// internal map key is unexported to keep the policy implementation private.
type Trio struct {
	Instance string
	Database string
	Level    string
}

// Authorize returns the matching mode when at least one of userGroups grants
// access to (instance, database, level); otherwise ErrRequestNotAllowed.
// A nil RequestPolicy denies everything — operators who didn't configure a
// policy should not be able to pass this check.
func (p *RequestPolicy) Authorize(userGroups []string, instance, database, level string) (AccessMode, error) {
	if p == nil {
		return "", ErrRequestNotAllowed
	}
	key := trioKey{instance: instance, database: database, level: level}
	for _, gid := range userGroups {
		trios, ok := p.byGroup[gid]
		if !ok {
			continue
		}
		if mode, ok := trios[key]; ok {
			return mode, nil
		}
	}
	return "", ErrRequestNotAllowed
}

// Groups returns the configured group ids — used only for boot-time logging
// so operators can verify the policy parsed as intended without echoing the
// full (potentially large) allow list.
func (p *RequestPolicy) Groups() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.byGroup))
	for gid := range p.byGroup {
		out = append(out, gid)
	}
	return out
}
