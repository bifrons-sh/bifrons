import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';

// Legacy redirect: the v0.1 SPA used a hash router (#/grants, #/backends, …).
// react-router can't match against the hash, so any bookmark from the old
// version would land on NotFound. Rewrite once before mount so the new path
// router takes over. Cheap, runs once, idempotent.
if (window.location.hash.startsWith('#/')) {
  const hashPath = window.location.hash.slice(1);
  const next = `${window.location.pathname.replace(/\/$/, '')}${hashPath}${window.location.search}`;
  window.history.replaceState(null, '', next);
}

// Global error sinks. The portal SPA runs in an embedded operator console;
// silent JS errors are far worse than a noisy console.
window.addEventListener('error', (e) => {
  console.error('[portal-ui] error', e.error ?? e.message);
});
window.addEventListener('unhandledrejection', (e) => {
  console.error('[portal-ui] unhandled rejection', e.reason);
});

const host = document.getElementById('app');
if (!host) throw new Error('missing #app mount node');
createRoot(host).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
