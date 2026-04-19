package policy

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ErrRequestNotAllowed is returned by RequestPolicy.Authorize when no allowed
// group grants the requested (backend, role) tuple.
var ErrRequestNotAllowed = errors.New("request not allowed by Entra policy")

// RequestPolicy maps Entra group IDs to allowed (backend_id, role) tuples.
// The portal consults it before accepting a non-admin grant request.
type RequestPolicy struct {
	// byGroup is indexed by group id; each inner map is backend_id → role set.
	byGroup map[string]map[string]map[string]struct{}
}

type policyFile struct {
	Groups []policyGroup `yaml:"groups"`
}

type policyGroup struct {
	ID    string        `yaml:"id"`
	Name  string        `yaml:"name"`
	Allow []policyAllow `yaml:"allow"`
}

type policyAllow struct {
	Backend string   `yaml:"backend"`
	Roles   []string `yaml:"roles"`
}

// LoadRequestPolicy reads a YAML policy file and compiles it into a
// RequestPolicy. Any error (file missing, malformed YAML, empty group id,
// empty backend id) is surfaced — callers at boot should exit 2 so operators
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
	p := &RequestPolicy{byGroup: map[string]map[string]map[string]struct{}{}}
	for i, g := range f.Groups {
		if g.ID == "" {
			return nil, fmt.Errorf("entra policy: groups[%d] missing id", i)
		}
		for j, a := range g.Allow {
			if a.Backend == "" {
				return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] missing backend", i, j)
			}
			if len(a.Roles) == 0 {
				return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] missing roles", i, j)
			}
			backends, ok := p.byGroup[g.ID]
			if !ok {
				backends = map[string]map[string]struct{}{}
				p.byGroup[g.ID] = backends
			}
			roles, ok := backends[a.Backend]
			if !ok {
				roles = map[string]struct{}{}
				backends[a.Backend] = roles
			}
			for _, r := range a.Roles {
				if r == "" {
					return nil, fmt.Errorf("entra policy: groups[%d].allow[%d] empty role", i, j)
				}
				roles[r] = struct{}{}
			}
		}
	}
	return p, nil
}

// NewRequestPolicy builds a policy in-memory from pre-compiled tuples. Intended
// for tests; production callers go through LoadRequestPolicy.
func NewRequestPolicy(groups map[string]map[string][]string) *RequestPolicy {
	p := &RequestPolicy{byGroup: map[string]map[string]map[string]struct{}{}}
	for gid, backends := range groups {
		p.byGroup[gid] = map[string]map[string]struct{}{}
		for bid, roles := range backends {
			set := map[string]struct{}{}
			for _, r := range roles {
				set[r] = struct{}{}
			}
			p.byGroup[gid][bid] = set
		}
	}
	return p
}

// Authorize returns nil when at least one of userGroups grants access to
// (backendID, role); otherwise ErrRequestNotAllowed. Matching is exact on
// group id and backend id; role strings use the domain.Role values ("app",
// "dba"). A nil RequestPolicy denies everything — operators who didn't
// configure a policy should not be able to pass this check.
func (p *RequestPolicy) Authorize(userGroups []string, backendID, role string) error {
	if p == nil {
		return ErrRequestNotAllowed
	}
	for _, gid := range userGroups {
		backends, ok := p.byGroup[gid]
		if !ok {
			continue
		}
		roles, ok := backends[backendID]
		if !ok {
			continue
		}
		if _, ok := roles[role]; ok {
			return nil
		}
	}
	return ErrRequestNotAllowed
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
