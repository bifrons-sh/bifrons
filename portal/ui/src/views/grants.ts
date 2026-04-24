// Grants list view.
//
// Two scopes:
//   - mine      → my own requests (default tab; everyone has it).
//   - validator → grants waiting on my approval. Tab only renders when the
//                 awaiting-set is non-empty, so non-validators don't see a
//                 dead surface (phase-7 §7.4 bridge).
//
// Status filter chips live in the URL hash (?status=PENDING&scope=mine) so
// the selection survives reloads and can be deep-linked from email links.

import { escapeHtml } from '../app.js';
import { listGrants, type Grant } from '../api.js';

const STATUSES = ['ALL', 'PENDING', 'VALIDATOR_APPROVED', 'APPROVED', 'DENIED', 'REVOKED', 'EXPIRED'] as const;

type Scope = 'mine' | 'validator';

function currentParams(): { status: string; scope: Scope } {
  const q = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
  const scope = q.get('scope') === 'validator' ? 'validator' : 'mine';
  return { status: q.get('status') ?? 'ALL', scope };
}

function setHash(scope: Scope, status: string): void {
  const params = new URLSearchParams();
  if (scope !== 'mine') params.set('scope', scope);
  if (status !== 'ALL') params.set('status', status);
  const qs = params.toString();
  window.location.hash = qs ? `/grants?${qs}` : '/grants';
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
  const { status, scope } = currentParams();
  // Probe the validator queue once on render. Non-empty → show the tab with
  // a count badge; empty → hide the tab so non-validators see no dead UI.
  // Failure is non-fatal: we degrade to the mine-only view rather than block
  // the page.
  let validatorQueue: Grant[] = [];
  try {
    validatorQueue = await listGrants({ scope: 'validator' });
  } catch {
    validatorQueue = [];
  }
  const showValidatorTab = validatorQueue.length > 0 || scope === 'validator';
  const queueBadge = validatorQueue.length > 0 ? ` <span class="badge">${validatorQueue.length}</span>` : '';

  root.innerHTML = `
    <section class="panel">
      <h2>Grants</h2>
      <div class="tabs" id="scope-tabs">
        <button class="tab${scope === 'mine' ? ' active' : ''}" data-scope="mine" type="button">My requests</button>
        ${showValidatorTab ? `<button class="tab${scope === 'validator' ? ' active' : ''}" data-scope="validator" type="button">Awaiting me${queueBadge}</button>` : ''}
      </div>
      <div class="chips" id="chips">
        ${STATUSES.map(
          (s) =>
            `<button class="chip${s === status ? ' active' : ''}" data-status="${s}" type="button">${s}</button>`,
        ).join('')}
      </div>
      <div id="grid" class="muted">Loading…</div>
    </section>
  `;

  root.querySelectorAll<HTMLButtonElement>('#scope-tabs .tab').forEach((el) => {
    el.addEventListener('click', () => {
      const s = (el.dataset.scope as Scope | undefined) ?? 'mine';
      setHash(s, 'ALL');
    });
  });
  root.querySelectorAll<HTMLButtonElement>('.chip').forEach((el) => {
    el.addEventListener('click', () => {
      const s = el.dataset.status ?? 'ALL';
      setHash(scope, s);
    });
  });

  const grid = root.querySelector<HTMLDivElement>('#grid');
  if (!grid) return;
  try {
    const grants = scope === 'validator'
      ? validatorQueue.filter((g) => status === 'ALL' || g.status === status)
      : await listGrants({ scope: 'mine', status: status === 'ALL' ? undefined : status });
    if (grants.length === 0) {
      grid.innerHTML = scope === 'validator'
        ? '<p class="muted">No grants are waiting on your approval.</p>'
        : '<p class="muted">No grants match this filter.</p>';
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
