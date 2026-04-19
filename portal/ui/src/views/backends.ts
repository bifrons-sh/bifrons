// Backends list view — strictly read-only at this stage. Backend CRUD
// stays in the admin REST API until a future phase adds write surfaces
// here (see specs/phase-6-future.md §6.2).

import { escapeHtml } from '../app.js';
import { listBackends, type Backend } from '../api.js';

export async function renderBackends(root: HTMLElement): Promise<void> {
  root.innerHTML = `
    <section class="panel">
      <h2>Backends</h2>
      <div id="grid" class="muted">Loading…</div>
    </section>
  `;
  const grid = root.querySelector<HTMLDivElement>('#grid');
  if (!grid) return;
  try {
    const backends = await listBackends();
    if (backends.length === 0) {
      grid.innerHTML = '<p class="muted">No backends registered yet.</p>';
      return;
    }
    grid.innerHTML = renderBackendTable(backends);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    grid.innerHTML = `<p class="error">Failed to load backends: ${escapeHtml(msg)}</p>`;
  }
}

function renderBackendTable(backends: Backend[]): string {
  const rows = backends
    .map(
      (b) => `
      <tr>
        <td><code>${escapeHtml(b.id)}</code></td>
        <td>${escapeHtml(b.name)}</td>
        <td>${escapeHtml(b.type)}</td>
        <td>${escapeHtml(b.host)}:${b.port}</td>
        <td>${escapeHtml((b.databases ?? []).join(', ') || '—')}</td>
      </tr>`,
    )
    .join('');
  return `
    <table>
      <thead>
        <tr><th>ID</th><th>Name</th><th>Type</th><th>Address</th><th>Databases</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}
