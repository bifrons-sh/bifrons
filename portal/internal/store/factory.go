package store

import (
	"fmt"
	"sync"
)

// OpenFunc constructs a Store from a driver-specific DSN. Registered by impl
// packages via Register() (typically in an init()).
type OpenFunc func(dsn string) (Store, error)

var (
	driversMu sync.RWMutex
	drivers   = map[string]OpenFunc{}
)

// Register wires a URL scheme (e.g. "sqlite") to an opener. Panics on duplicate
// registration — driver collisions are programmer errors, not runtime ones.
func Register(scheme string, fn OpenFunc) {
	driversMu.Lock()
	defer driversMu.Unlock()
	if _, ok := drivers[scheme]; ok {
		panic("store: duplicate driver registration: " + scheme)
	}
	drivers[scheme] = fn
}

// NewFromURL builds a Store from a short URL-style descriptor. Built-ins:
//
//	""                     → in-memory Store (alias for "memory")
//	memory                 → in-memory Store
//	<scheme>://<dsn>       → delegated to the registered driver (e.g. sqlite)
//
// Special case for sqlite convenience: "sqlite::memory:" is accepted as the
// well-known in-memory DSN.
func NewFromURL(url string) (Store, error) {
	if url == "" || url == "memory" {
		return NewMemory(), nil
	}
	if url == "sqlite::memory:" {
		return dispatch("sqlite", ":memory:")
	}
	for scheme, opener := range snapshotDrivers() {
		prefix := scheme + "://"
		if len(url) >= len(prefix) && url[:len(prefix)] == prefix {
			return opener(url[len(prefix):])
		}
	}
	return nil, fmt.Errorf("unsupported store URL %q (want memory | sqlite::memory: | sqlite:///path | <scheme>://…)", url)
}

func dispatch(scheme, dsn string) (Store, error) {
	driversMu.RLock()
	fn, ok := drivers[scheme]
	driversMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("store: driver %q not registered (missing blank import?)", scheme)
	}
	return fn(dsn)
}

func snapshotDrivers() map[string]OpenFunc {
	driversMu.RLock()
	defer driversMu.RUnlock()
	out := make(map[string]OpenFunc, len(drivers))
	for k, v := range drivers {
		out[k] = v
	}
	return out
}
