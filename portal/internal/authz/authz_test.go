package authz

import (
	"testing"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/oidc"
)

func principalStaticBearer(entraWired bool) Principal {
	var c entra.Client
	if entraWired {
		c = entra.NewFakeClient()
	}
	return NewPrincipal(nil, c)
}

func principalAdmin() Principal {
	// Post-split vocabulary: "admin" here means "gate2-eligible principal"
	// (member of the T2 group), not just IsOperator. The rename in
	// specs/phase-7-validation-ui.md §7.8.1 decoupled config authority
	// (is_operator) from gate2 eligibility (T2Subjects). Keep the helper
	// name terse for tests, but wire both so it works for every rule that
	// used to implicitly assume operator ⇒ T2.
	return NewPrincipal(&oidc.Session{Subject: "sub-admin", IsOperator: true}, nil).
		WithT2Subjects(map[string]struct{}{"sub-admin": {}})
}

func principalOperatorOnly() Principal {
	// Operator with no T2 set membership — exercises the split: config
	// authority without gate-clearing authority.
	return NewPrincipal(&oidc.Session{Subject: "sub-op", IsOperator: true}, nil)
}

func principalOwner(pid, sub string) Principal {
	return NewPrincipal(&oidc.Session{Subject: sub, PortalUserID: pid, IsOperator: false}, nil)
}

func principalValidator(sub string) Principal {
	return NewPrincipal(&oidc.Session{Subject: sub, IsOperator: false}, entra.NewFakeClient())
}

func grantFor(owner, validatorSub string) domain.Grant {
	return domain.Grant{ID: "g-1", UserID: owner, T1Subject: validatorSub}
}

func TestAuthorize_View(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	cases := []struct {
		name  string
		p     Principal
		allow bool
	}{
		{"static-bearer", principalStaticBearer(false), true},
		{"admin", principalAdmin(), true},
		{"owner", principalOwner("u-alice", "sub-alice"), true},
		{"stranger", principalOwner("u-bob", "sub-bob"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Authorize(ActionView, g, c.p)
			if d.Allow != c.allow {
				t.Errorf("Allow=%v want %v (reason=%q)", d.Allow, c.allow, d.Reason)
			}
			if !c.allow && !d.NotFoundErr {
				t.Errorf("View denial should be probe-resistant (NotFoundErr=true), got %+v", d)
			}
		})
	}
}

func TestAuthorize_ApproveValidatorHalf_StaticBearerDemotedWhenEntraAndValidatorSet(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	// No Entra → static bearer satisfies validator half (bootstrap path).
	if d := Authorize(ActionApproveT1, g, principalStaticBearer(false)); !d.Allow {
		t.Errorf("static-bearer without Entra should satisfy validator half: %+v", d)
	}
	// Entra wired + T1Subject set → static bearer must NOT satisfy.
	if d := Authorize(ActionApproveT1, g, principalStaticBearer(true)); d.Allow {
		t.Errorf("static-bearer with Entra + T1Subject should be denied validator half: %+v", d)
	}
	// OIDC session whose sub matches T1Subject → allowed.
	if d := Authorize(ActionApproveT1, g, principalValidator("sub-mgr")); !d.Allow {
		t.Errorf("real validator should satisfy validator half: %+v", d)
	}
	// OIDC session whose sub does NOT match → denied.
	if d := Authorize(ActionApproveT1, g, principalValidator("sub-impostor")); d.Allow {
		t.Errorf("impostor should be denied validator half: %+v", d)
	}
}

func TestAuthorize_ApproveT2Half(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	// A session in the T2 set clears gate2.
	if d := Authorize(ActionApproveT2, g, principalAdmin()); !d.Allow {
		t.Errorf("T2-eligible session should satisfy gate2: %+v", d)
	}
	// Static-bearer retains bootstrap bypass.
	if d := Authorize(ActionApproveT2, g, principalStaticBearer(false)); !d.Allow {
		t.Errorf("static-bearer should satisfy gate2 (bootstrap path): %+v", d)
	}
	// T1-only principal (not in T2 set) is denied.
	if d := Authorize(ActionApproveT2, g, principalValidator("sub-mgr")); d.Allow {
		t.Errorf("validator-only should NOT satisfy gate2: %+v", d)
	}
	// Operator with no T2 set membership is denied — the split means
	// config authority doesn't auto-grant gate-clearing authority.
	if d := Authorize(ActionApproveT2, g, principalOperatorOnly()); d.Allow {
		t.Errorf("operator without T2 membership should NOT satisfy gate2: %+v", d)
	}
}

func TestAuthorize_Claim(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	if d := Authorize(ActionClaim, g, principalOwner("u-alice", "sub-alice")); !d.Allow {
		t.Errorf("owner should be able to claim: %+v", d)
	}
	if d := Authorize(ActionClaim, g, principalAdmin()); !d.Allow {
		t.Errorf("admin should be able to claim on behalf: %+v", d)
	}
	if d := Authorize(ActionClaim, g, principalOwner("u-bob", "sub-bob")); d.Allow {
		t.Errorf("non-owner non-admin should be denied: %+v", d)
	}
}

func TestAuthorize_Deny_EitherT1OrT2(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	if d := Authorize(ActionDeny, g, principalValidator("sub-mgr")); !d.Allow {
		t.Error("T1 validator should be able to deny")
	}
	if d := Authorize(ActionDeny, g, principalAdmin()); !d.Allow {
		t.Error("T2-eligible principal should be able to deny")
	}
	if d := Authorize(ActionDeny, g, principalOperatorOnly()); d.Allow {
		t.Error("operator without T2 membership should NOT be able to deny")
	}
	if d := Authorize(ActionDeny, g, principalOwner("u-alice", "sub-alice")); d.Allow {
		t.Error("owner should NOT be able to deny their own grant")
	}
}

func TestAuthorize_CreateRequiresPortalBinding(t *testing.T) {
	noBinding := NewPrincipal(&oidc.Session{Subject: "sub-x", IsOperator: false}, nil)
	d := Authorize(ActionCreate, domain.Grant{}, noBinding)
	if d.Allow {
		t.Errorf("non-admin without PortalUserID must be denied create: %+v", d)
	}
}
