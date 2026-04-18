package mysql

import (
	"container/list"
	"crypto/rsa"
	"sync"
)

// pubKeyLRUCap bounds the number of cached backend RSA public keys. A single
// proxy instance usually fronts 1–3 backends; the cap is a guard against a
// misconfigured multi-backend deployment growing memory unbounded.
const pubKeyLRUCap = 128

// pubkeyLRU is a tiny LRU over (remoteAddr -> *rsa.PublicKey). Zero-value
// ready; all ops take the write lock because reads also touch the recency
// list. At the scales this cache lives (≤128 entries, cache-hit on steady-
// state), lock contention is negligible.
type pubkeyLRU struct {
	mu    sync.Mutex
	order *list.List // front = most recent
	items map[string]*list.Element
}

type pubkeyEntry struct {
	key string
	val *rsa.PublicKey
}

func (c *pubkeyLRU) get(key string) (*rsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		return nil, false
	}
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*pubkeyEntry).val, true
}

func (c *pubkeyLRU) put(key string, val *rsa.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = make(map[string]*list.Element, pubKeyLRUCap)
		c.order = list.New()
	}
	if el, ok := c.items[key]; ok {
		el.Value.(*pubkeyEntry).val = val
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= pubKeyLRUCap {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*pubkeyEntry).key)
		}
	}
	c.items[key] = c.order.PushFront(&pubkeyEntry{key: key, val: val})
}
