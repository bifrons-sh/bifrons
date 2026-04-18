package mysql

import (
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestPubkeyLRU_GetPutEviction(t *testing.T) {
	var c pubkeyLRU
	if _, ok := c.get("missing"); ok {
		t.Fatal("empty cache should miss")
	}

	// Put distinct sentinel pubkeys keyed by address.
	keys := make([]*rsa.PublicKey, pubKeyLRUCap+2)
	for i := range keys {
		keys[i] = &rsa.PublicKey{E: i + 1}
		c.put(fmt.Sprintf("backend-%d", i), keys[i])
	}
	// First two should have been evicted (cap is full, LRU order).
	if _, ok := c.get("backend-0"); ok {
		t.Errorf("backend-0 should have been evicted")
	}
	if _, ok := c.get("backend-1"); ok {
		t.Errorf("backend-1 should have been evicted")
	}
	// Most recent is still present.
	if got, ok := c.get(fmt.Sprintf("backend-%d", pubKeyLRUCap+1)); !ok || got != keys[pubKeyLRUCap+1] {
		t.Errorf("most-recent entry missing")
	}
}

func TestPubkeyLRU_PutUpdatesAndPromotes(t *testing.T) {
	var c pubkeyLRU
	a := &rsa.PublicKey{E: 1}
	b := &rsa.PublicKey{E: 2}
	c.put("k", a)
	c.put("k", b) // update in-place
	got, ok := c.get("k")
	if !ok || got != b {
		t.Fatalf("expected update to replace value, got %v", got)
	}
}
