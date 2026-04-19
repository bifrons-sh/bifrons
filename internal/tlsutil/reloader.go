package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// pollInterval is the fallback poll cadence when fsnotify is unavailable
// (e.g. filesystems without inotify such as some NFS/fuse mounts). Var
// (not const) so tests can shrink it to keep the suite snappy.
var pollInterval = 30 * time.Second

// forcePollFallback is set by tests to exercise the polling code path
// without having to simulate an fsnotify failure at the OS level.
var forcePollFallback = false

// Reloader owns a hot-swappable keypair + optional peer CA pool.
// A single handshake reads the atomic pointers, so an in-flight rotation
// never tears a connection; existing TLS sessions keep the old cert
// because Go caches it on the *tls.Conn.
type Reloader struct {
	certPath string
	keyPath  string
	caPath   string

	current atomic.Pointer[tls.Certificate]
	ca      atomic.Pointer[x509.CertPool]

	logger *slog.Logger

	// Watcher state (fsnotify path) — nil when we fell back to polling.
	watcher *fsnotify.Watcher

	// Poll-path state — mtimes keyed by absolute path.
	mtimes map[string]time.Time

	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// NewReloader loads the initial keypair + optional CA and starts a background
// watcher. certPath/keyPath may both be empty — in that case the Reloader
// only tracks the CA (useful for backend dialers that verify but don't present
// a client cert). At least one of the three paths must be non-empty.
func NewReloader(certPath, keyPath, caPath string, logger *slog.Logger) (*Reloader, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil, errors.New("tlsutil: reloader requires at least one path")
	}
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("tlsutil: cert and key paths must be set together")
	}

	r := &Reloader{
		certPath: certPath,
		keyPath:  keyPath,
		caPath:   caPath,
		logger:   logger,
		mtimes:   make(map[string]time.Time),
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}

	// Initial load — failure here is fatal; we never served the old one.
	if err := r.loadCert(); err != nil {
		return nil, err
	}
	if err := r.loadCA(); err != nil {
		return nil, err
	}

	r.snapshotMTimes()
	r.startWatcher()

	return r, nil
}

// GetCertificate is suitable for tls.Config.GetCertificate. It returns the
// currently-loaded keypair for each new handshake.
func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := r.current.Load()
	if cert == nil {
		return nil, errors.New("tlsutil: no certificate loaded")
	}
	return cert, nil
}

// GetClientCertificate is suitable for tls.Config.GetClientCertificate.
// Backends call this when presenting our mTLS client cert on dial.
func (r *Reloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert := r.current.Load()
	if cert == nil {
		return nil, errors.New("tlsutil: no certificate loaded")
	}
	return cert, nil
}

// CAPool returns the currently-loaded CA pool, or nil if none.
func (r *Reloader) CAPool() *x509.CertPool {
	return r.ca.Load()
}

// VerifyPeerCertificate implements tls.Config.VerifyPeerCertificate using
// the live CA pool. It mirrors Go's default verification but against the
// reloader's atomic pool so rotations take effect immediately.
func (r *Reloader) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	pool := r.ca.Load()
	if pool == nil {
		// No CA configured — nothing to verify here (the tls.Config's
		// ClientAuth / InsecureSkipVerify decide whether that is ok).
		return nil
	}
	if len(rawCerts) == 0 {
		return errors.New("tlsutil: no peer certificates presented")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("tlsutil: parse peer cert: %w", err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
	})
	return err
}

// Close stops the background watcher. Safe to call more than once.
func (r *Reloader) Close() error {
	r.once.Do(func() {
		close(r.stop)
		<-r.stopped
		if r.watcher != nil {
			_ = r.watcher.Close()
		}
	})
	return nil
}

// loadCert reads the cert+key from disk and atomically swaps the pointer.
// Returns an error without swapping if parsing fails.
func (r *Reloader) loadCert() error {
	if r.certPath == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	r.current.Store(&cert)
	return nil
}

// loadCA reads the CA bundle and atomically swaps the pool pointer.
func (r *Reloader) loadCA() error {
	if r.caPath == "" {
		return nil
	}
	pem, err := os.ReadFile(r.caPath)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("no valid certificates in %s", r.caPath)
	}
	r.ca.Store(pool)
	return nil
}

// reload re-reads everything; if any piece is malformed, nothing is swapped
// (loadCert/loadCA are already atomic and guard their own stores, and the
// prior state on *other* fields is preserved by returning early).
func (r *Reloader) reload() {
	// Re-read cert+key atomically: parse first, only then swap. tls.LoadX509KeyPair
	// already does parse-before-return, so if it errs the pointer stays put.
	if r.certPath != "" {
		if err := r.loadCert(); err != nil {
			r.logger.Warn("cert_reload_failed",
				"path", r.certPath,
				"err", err.Error())
			return
		}
	}
	if r.caPath != "" {
		if err := r.loadCA(); err != nil {
			r.logger.Warn("cert_reload_failed",
				"path", r.caPath,
				"err", err.Error())
			return
		}
	}

	cert := r.current.Load()
	attrs := []any{}
	if r.certPath != "" {
		attrs = append(attrs, "cert", r.certPath)
	}
	if r.caPath != "" {
		attrs = append(attrs, "ca", r.caPath)
	}
	if cert != nil && cert.Leaf != nil {
		attrs = append(attrs, "not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	r.logger.Info("cert_reloaded", attrs...)
}

// snapshotMTimes records current mtimes for the poll-fallback path.
func (r *Reloader) snapshotMTimes() {
	for _, p := range r.paths() {
		if fi, err := os.Stat(p); err == nil {
			r.mtimes[p] = fi.ModTime()
		}
	}
}

func (r *Reloader) paths() []string {
	out := make([]string, 0, 3)
	if r.certPath != "" {
		out = append(out, r.certPath)
	}
	if r.keyPath != "" {
		out = append(out, r.keyPath)
	}
	if r.caPath != "" {
		out = append(out, r.caPath)
	}
	return out
}

// startWatcher spins up an fsnotify watcher on the parent directories of
// each path (so atomic-replace rotations — rename-over-target, the kubelet
// configmap pattern — are caught). If fsnotify init fails we fall back to
// a 30s polling goroutine.
func (r *Reloader) startWatcher() {
	if forcePollFallback {
		r.logger.Info("cert_watcher_poll_fallback", "reason", "forced", "interval", pollInterval.String())
		go r.pollLoop()
		return
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		r.logger.Info("cert_watcher_poll_fallback", "reason", err.Error(), "interval", pollInterval.String())
		go r.pollLoop()
		return
	}

	// Watch parent directories; atomic rename delivers a CREATE on the new
	// inode in the same dir, which a file-level watch would miss.
	seen := map[string]struct{}{}
	for _, p := range r.paths() {
		dir := filepath.Dir(p)
		if _, ok := seen[dir]; ok {
			continue
		}
		if err := w.Add(dir); err != nil {
			_ = w.Close()
			r.logger.Info("cert_watcher_poll_fallback", "reason", err.Error(), "dir", dir, "interval", pollInterval.String())
			go r.pollLoop()
			return
		}
		seen[dir] = struct{}{}
	}

	r.watcher = w
	go r.watchLoop()
}

// watchLoop debounces fsnotify events (write-then-rename fires a burst) and
// triggers a reload when any watched path is touched.
func (r *Reloader) watchLoop() {
	defer close(r.stopped)

	// Build a set for O(1) filtering against dir-level events.
	targets := map[string]struct{}{}
	for _, p := range r.paths() {
		targets[filepath.Clean(p)] = struct{}{}
	}

	var debounce *time.Timer
	const debounceWait = 200 * time.Millisecond
	trigger := func() {
		if debounce != nil {
			debounce.Stop()
		}
		debounce = time.AfterFunc(debounceWait, r.reload)
	}

	for {
		select {
		case <-r.stop:
			if debounce != nil {
				debounce.Stop()
			}
			return
		case ev, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if _, hit := targets[filepath.Clean(ev.Name)]; !hit {
				continue
			}
			// CHMOD alone is noise; Write/Create/Rename/Remove all mean "look again".
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
				trigger()
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.Warn("cert_watcher_error", "err", err.Error())
		}
	}
}

// pollLoop is the fsnotify-less fallback. It compares mtimes every
// pollInterval and reloads when any watched path has changed.
func (r *Reloader) pollLoop() {
	defer close(r.stopped)
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			changed := false
			for _, p := range r.paths() {
				fi, err := os.Stat(p)
				if err != nil {
					continue
				}
				if prev, ok := r.mtimes[p]; !ok || !prev.Equal(fi.ModTime()) {
					r.mtimes[p] = fi.ModTime()
					changed = true
				}
			}
			if changed {
				r.reload()
			}
		}
	}
}
