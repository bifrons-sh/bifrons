package ephemeral

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func TestNewStoreDBALookup_MissingAccount(t *testing.T) {
	s := store.NewMemory()
	lookup := NewStoreDBALookup(s)
	_, err := lookup(context.Background(), "nope")
	if !errors.Is(err, ErrNoDBACredential) {
		t.Errorf("expected ErrNoDBACredential, got %v", err)
	}
}

func TestNewStoreDBALookup_PlaintextPassword(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()
	b := domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertBackendAccount(ctx, domain.BackendAccount{
		ID: "ba-dba", BackendID: b.ID, Role: domain.RoleDBA,
		Username: "root", Password: "rootpw",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	dba, err := NewStoreDBALookup(s)(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dba.Username != "root" || dba.Password != "rootpw" {
		t.Errorf("got %+v", dba)
	}
}

func TestNewStoreDBALookup_EnvRef(t *testing.T) {
	t.Setenv("EPH_DBA_PW", "env-pw")
	s := store.NewMemory()
	ctx := context.Background()
	b := domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432}
	_ = s.CreateBackend(ctx, b)
	_ = s.UpsertBackendAccount(ctx, domain.BackendAccount{
		ID: "ba-dba", BackendID: b.ID, Role: domain.RoleDBA,
		Username: "root", PasswordRef: "env://EPH_DBA_PW",
	})
	dba, err := NewStoreDBALookup(s)(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dba.Password != "env-pw" {
		t.Errorf("expected env-pw, got %q", dba.Password)
	}
}
