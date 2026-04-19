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

func principalManager(sub string) Principal {
	return NewPrincipal(&oidc.Session{Subject: sub, IsAdmin: false}, entra.NewFakeClient())
}

func grantFor(owner, managerSub string) domain.Grant {
	return domain.Grant{ID: "g-1", UserID: owner, ManagerSubject: managerSub}
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

func TestAuthorize_ApproveManagerHalf_StaticBearerDemotedWhenEntraAndManagerSet(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	// No Entra → static bearer satisfies manager half (bootstrap path).
	if d := Authorize(ActionApproveManager, g, principalStaticBearer(false)); !d.Allow {
		t.Errorf("static-bearer without Entra should satisfy manager half: %+v", d)
	}
	// Entra wired + ManagerSubject set → static bearer must NOT satisfy.
	if d := Authorize(ActionApproveManager, g, principalStaticBearer(true)); d.Allow {
		t.Errorf("static-bearer with Entra + ManagerSubject should be denied manager half: %+v", d)
	}
	// OIDC session whose sub matches ManagerSubject → allowed.
	if d := Authorize(ActionApproveManager, g, principalManager("sub-mgr")); !d.Allow {
		t.Errorf("real manager should satisfy manager half: %+v", d)
	}
	// OIDC session whose sub does NOT match → denied.
	if d := Authorize(ActionApproveManager, g, principalManager("sub-impostor")); d.Allow {
		t.Errorf("impostor should be denied manager half: %+v", d)
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
	if d := Authorize(ActionApproveAdmin, g, principalManager("sub-mgr")); d.Allow {
		t.Errorf("manager-only should NOT satisfy admin half: %+v", d)
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

func TestAuthorize_Deny_EitherManagerOrAdmin(t *testing.T) {
	g := grantFor("u-alice", "sub-mgr")
	if d := Authorize(ActionDeny, g, principalManager("sub-mgr")); !d.Allow {
		t.Error("manager should be able to deny")
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
