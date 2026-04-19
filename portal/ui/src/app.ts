// Minimal hash-based router + shell layout.
//
// Why hash routing: the Go SPA fallback already rewrites unknown paths
// to index.html, but hash routing keeps the whole UI self-contained and
// survives even if that fallback is ever tightened. It also removes any
// need for server reconfiguration when new views are added.

import { fetchSession, type Session } from './api.js';
import { renderLogin } from './views/login.js';
import { renderGrants } from './views/grants.js';
import { renderBackends } from './views/backends.js';

type View = (root: HTMLElement, session: Session | null) => void | Promise<void>;

const routes: Record<string, View> = {
  '': renderLogin,
  '/': renderLogin,
  '/grants': renderGrants,
  '/backends': renderBackends,
};

let cachedSession: Session | null = null;

function currentRoute(): string {
  // Strip the leading '#'; default to '/'.
  const raw = window.location.hash.replace(/^#/, '');
  return raw || '/';
}

function navLink(label: string, href: string, current: string): string {
  const active = current === href ? ' class="active"' : '';
  return `<a href="#${href}"${active} data-nav="${href}">${label}</a>`;
}

function renderShell(session: Session | null, current: string): void {
  const app = document.getElementById('app');
  if (!app) return;
  const who = session
    ? `${escapeHtml(session.username)}${session.is_admin ? ' (admin)' : ''}`
    : 'not signed in';
  app.innerHTML = `
    <header class="topbar">
      <h1>Access Portal</h1>
      <nav>
        ${navLink('Home', '/', current)}
        ${navLink('Grants', '/grants', current)}
        ${navLink('Backends', '/backends', current)}
      </nav>
      <div class="spacer"></div>
      <span class="user">${who}</span>
    </header>
    <main id="view"></main>
  `;
}

async function route(): Promise<void> {
  const path = currentRoute();
  const view = routes[path] ?? renderLogin;
  renderShell(cachedSession, path);
  const host = document.getElementById('view');
  if (!host) return;
  try {
    await view(host, cachedSession);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    host.innerHTML = `<div class="panel error">Failed to load: ${escapeHtml(msg)}</div>`;
  }
}

export async function bootstrap(): Promise<void> {
  // Probe session once on load; views that need a fresh value can call
  // fetchSession again. Keeping one cached copy avoids a flash of
  // "not signed in" during the initial render.
  try {
    cachedSession = await fetchSession();
  } catch {
    cachedSession = null;
  }
  window.addEventListener('hashchange', () => {
    void route();
  });
  await route();
}

// escapeHtml keeps untrusted strings (session.username, error messages,
// grant IDs returned by the API) out of the innerHTML fast-path without
// pulling in a full templating dependency.
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
