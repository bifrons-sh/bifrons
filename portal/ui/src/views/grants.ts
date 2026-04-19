// Grants list view.
//
// Status filter chips live in the URL hash (?status=PENDING) so the
// selection survives reloads + can be deep-linked. No pagination yet —
// the portal's grant store is expected to stay small (hundreds of open
// grants at a busy shop); we'll add it when list sizes demand it.

import { escapeHtml } from '../app.js';
import { listGrants, type Grant } from '../api.js';

const STATUSES = ['ALL', 'PENDING', 'APPROVED', 'DENIED', 'REVOKED', 'EXPIRED'] as const;

function currentStatus(): string {
  const q = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
  return q.get('status') ?? 'ALL';
}

function formatTime(iso?: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export async function renderGrants(root: HTMLElement): Promise<void> {
  const status = currentStatus();
  root.innerHTML = `
    <section class="panel">
      <h2>Grants</h2>
      <div class="chips" id="chips">
        ${STATUSES.map(
          (s) =>
            `<button class="chip${s === status ? ' active' : ''}" data-status="${s}" type="button">${s}</button>`,
        ).join('')}
      </div>
      <div id="grid" class="muted">Loading…</div>
    </section>
  `;

  root.querySelectorAll<HTMLButtonElement>('.chip').forEach((el) => {
    el.addEventListener('click', () => {
      const s = el.dataset.status ?? 'ALL';
      window.location.hash = s === 'ALL' ? '/grants' : `/grants?status=${s}`;
    });
  });

  const grid = root.querySelector<HTMLDivElement>('#grid');
  if (!grid) return;
  try {
    const grants = await listGrants(status === 'ALL' ? undefined : status);
    if (grants.length === 0) {
      grid.innerHTML = '<p class="muted">No grants match this filter.</p>';
      return;
    }
    grid.innerHTML = renderGrantTable(grants);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    grid.innerHTML = `<p class="error">Failed to load grants: ${escapeHtml(msg)}</p>`;
  }
}

function renderGrantTable(grants: Grant[]): string {
  const rows = grants
    .map(
      (g) => `
      <tr>
        <td><code>${escapeHtml(g.id)}</code></td>
        <td>${escapeHtml(g.user_id)}</td>
        <td>${escapeHtml(g.backend_id)}</td>
        <td>${escapeHtml(g.role)}</td>
        <td><span class="pill pill-${escapeHtml(g.status)}">${escapeHtml(g.status)}</span></td>
        <td>${escapeHtml(formatTime(g.expires_at))}</td>
      </tr>`,
    )
    .join('');
  return `
    <table>
      <thead>
        <tr>
          <th>ID</th><th>User</th><th>Backend</th><th>Role</th><th>Status</th><th>Expires</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}
