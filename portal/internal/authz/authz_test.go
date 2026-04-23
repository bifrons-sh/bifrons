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
	return NewPrincipal(&oidc.Session{Subject: "sub-admin", IsAdmin: true}, nil)
}

func principalOwner(pid, sub string) Principal {
	return NewPrincipal(&oidc.Session{Subject: sub, PortalUserID: pid, IsAdmin: false}, nil)
}

func principalValidator(sub string) Principal {
	return NewPrincipal(&oidc.Session{Subject: sub, IsAdmin: false}, entra.NewFakeClient())
}

func grantFor(owner, validatorSub string) domain.Grant {
	return domain.Grant{ID: "g-1", UserID: owner, ValidatorSubject: validatorSub}
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
	if d := Authorize(ActionApproveValidator, g, principalStaticBearer(false)); !d.Allow {
		t.Errorf("static-bearer without Entra should satisfy validator half: %+v", d)
	}
	// Entra wired + ValidatorSubject set → static bearer must NOT satisfy.
	if d := Authorize(ActionApproveValidator, g, principalStaticBearer(true)); d.Allow {
		t.Errorf("static-bearer with Entra + ValidatorSubject should be denied validator half: %+v", d)
	}
	// OIDC session whose sub matches ValidatorSubject → allowed.
	if d := Authorize(ActionApproveValidator, g, principalValidator("sub-mgr")); !d.Allow {
		t.Errorf("real validator should satisfy validator half: %+v", d)
	}
	// OIDC session whose sub does NOT match → denied.
	if d := Authorize(ActionApproveValidator, g, principalValidator("sub-impostor")); d.Allow {
		t.Errorf("impostor should be denied validator half: %+v", d)
	}
}

func TestAuthorize_ApproveAdminHalf(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	if d := Authorize(ActionApproveAdmin, g, principalAdmin()); !d.Allow {
		t.Errorf("admin session should satisfy admin half: %+v", d)
	}
	if d := Authorize(ActionApproveAdmin, g, principalStaticBearer(false)); !d.Allow {
		t.Errorf("static-bearer should satisfy admin half: %+v", d)
	}
	if d := Authorize(ActionApproveAdmin, g, principalValidator("sub-mgr")); d.Allow {
		t.Errorf("validator-only should NOT satisfy admin half: %+v", d)
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

func TestAuthorize_Deny_EitherValidatorOrAdmin(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	if d := Authorize(ActionDeny, g, principalValidator("sub-mgr")); !d.Allow {
		t.Error("validator should be able to deny")
	}
	if d := Authorize(ActionDeny, g, principalAdmin()); !d.Allow {
		t.Error("admin should be able to deny")
	}
	if d := Authorize(ActionDeny, g, principalOwner("u-alice", "sub-alice")); d.Allow {
		t.Error("owner should NOT be able to deny their own grant")
	}
}

func TestAuthorize_CreateRequiresPortalBinding(t *testing.T) {
	noBinding := NewPrincipal(&oidc.Session{Subject: "sub-x", IsAdmin: false}, nil)
	d := Authorize(ActionCreate, domain.Grant{}, noBinding)
	if d.Allow {
		t.Errorf("non-admin without PortalUserID must be denied create: %+v", d)
	}
}
