// Landing / login view.
//
// Dual-purpose: when the user is authenticated, it renders a session
// summary + quick links. When they aren't, it shows a single CTA that
// kicks off the OIDC login flow via the backend's /oidc/login handler.

import { escapeHtml } from '../app.js';
import type { Session } from '../api.js';

export function renderLogin(root: HTMLElement, session: Session | null): void {
  if (!session) {
    root.innerHTML = `
      <section class="panel">
        <h2>Sign in</h2>
        <p class="muted">You need to authenticate to browse grants and backends.</p>
        <button id="login-btn" type="button">Login with OIDC</button>
      </section>
    `;
    // Inline handlers are forbidden by CSP; wire the click programmatically.
    root.querySelector<HTMLButtonElement>('#login-btn')?.addEventListener('click', () => {
      window.location.assign('/oidc/login');
    });
    return;
  }

  root.innerHTML = `
    <section class="panel">
      <h2>Welcome, ${escapeHtml(session.username)}</h2>
      <p class="muted">
        Signed in as <code>${escapeHtml(session.email ?? session.subject ?? session.username)}</code>
        ${session.is_admin ? '· <strong>admin</strong>' : ''}
      </p>
      <p>
        <a href="#/grants">Browse grants →</a><br />
        <a href="#/backends">Browse backends →</a>
      </p>
    </section>
  `;
}
