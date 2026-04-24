package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// StoreUserProvisioner adapts store.Store to oidc.UserProvisioner.
//
// Behaviour:
//   - lookup by OIDC subject → existing portal user wins, its persisted
//     IsOperator is authoritative (lets the admin API flip admin on/off
//     without needing to wait for the IdP claim to catch up).
//   - not found → create a new user. Username is preferred_username when
//     supplied, else the local-part of email, else sub. A uniqueness
//     collision is resolved by appending a short suffix of the subject so
//     two IdPs that publish the same preferred_username can coexist.
type StoreUserProvisioner struct {
	Store store.Store
}

// ProvisionOIDCUser implements oidc.UserProvisioner.
func (p StoreUserProvisioner) ProvisionOIDCUser(ctx context.Context, sub, email, preferredUsername string, claimIsAdmin bool) (string, bool, error) {
	if sub == "" {
		return "", false, errors.New("empty subject")
	}
	u, err := p.Store.GetUserByExternalID(ctx, sub)
	if err == nil {
		// Existing user — trust the stored IsOperator over the claim so the
		// admin API is the source of truth once a user is provisioned.
		return u.ID, u.IsOperator, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return "", false, fmt.Errorf("lookup by external_id: %w", err)
	}

	// First login: materialise the user row.
	username := firstUsername(preferredUsername, email, sub)
	now := time.Now().UTC()
	nu := domain.User{
		ID:         domain.NewID("u"),
		Username:   username,
		DisplayName: preferredUsername,
		Email:      email,
		ExternalID: sub,
		IsOperator:    claimIsAdmin,
		Status:     "active",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	err = p.Store.CreateUser(ctx, nu)
	if err == nil {
		return nu.ID, nu.IsOperator, nil
	}
	// On UNIQUE collision for username (not external_id — we already proved
	// that was free), retry once with a subject-suffixed username so two IdP
	// identities that share a preferred_username can coexist.
	if errors.Is(err, store.ErrConflict) {
		suffix := sub
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}
		nu.Username = username + "-" + suffix
		if err := p.Store.CreateUser(ctx, nu); err != nil {
			return "", false, fmt.Errorf("create oidc user (retry): %w", err)
		}
		return nu.ID, nu.IsOperator, nil
	}
	return "", false, fmt.Errorf("create oidc user: %w", err)
}

// firstUsername picks the first non-empty candidate for a portal username.
// Email local-part beats the raw subject for human-readability; both beat an
// empty field.
func firstUsername(candidates ...string) string {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if at := strings.IndexByte(c, '@'); at > 0 {
			return c[:at]
		}
		return c
	}
	return ""
}

// Ensure interface satisfaction at compile time.
var _ oidc.UserProvisioner = StoreUserProvisioner{}
