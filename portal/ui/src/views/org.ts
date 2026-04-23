// Org-hierarchy view: users ↔ validators + groups ↔ members.
//
// Populated by the cmd/entra-sync script on a cron. This view is a thin
// operator surface — useful for spot-checking what the sync wrote and for
// bootstrap tweaks before the first sync run. Heavy bulk edits belong in
// the sync fixture / upstream source, not here.

import { escapeHtml } from '../app.js';
import {
  addGroupMember,
  clearUserValidator,
  deleteGroup,
  listGroupMembers,
  listGroups,
  listUserGroups,
  listUsers,
  removeGroupMember,
  setUserValidator,
  upsertGroup,
  type Group,
  type Session,
  type User,
} from '../api.js';

// renderOrg is the view entry point. Only admins get the mutation affordances;
// everyone else sees read-only listings.
export async function renderOrg(root: HTMLElement, session: Session | null): Promise<void> {
  const isAdmin = !!session?.is_admin;
  root.innerHTML = `
    <section class="panel">
      <h2>Org hierarchy</h2>
      <p class="muted">
        Populated by the <code>entra-sync</code> script. The portal reads validators
        and group membership from here on grant creation — no live IdP call on
        the hot path.
      </p>
      <div id="org-err" class="error hidden"></div>
      <div id="users-panel"></div>
      <div id="groups-panel"></div>
    </section>
  `;
  const errBox = root.querySelector<HTMLDivElement>('#org-err');
  const showErr = (e: unknown): void => {
    if (!errBox) return;
    const msg = e instanceof Error ? e.message : String(e);
    errBox.textContent = msg;
    errBox.classList.remove('hidden');
  };

  try {
    const [users, groups] = await Promise.all([listUsers(), listGroups()]);
    await renderUsersPanel(root, users, isAdmin, showErr);
    await renderGroupsPanel(root, users, groups, isAdmin, showErr);
  } catch (e) {
    showErr(e);
  }
}

// --- users ---

async function renderUsersPanel(
  root: HTMLElement,
  users: User[],
  isAdmin: boolean,
  showErr: (e: unknown) => void,
): Promise<void> {
  const panel = root.querySelector<HTMLDivElement>('#users-panel');
  if (!panel) return;

  // Validator cell + is_admin are admin-only fields — the public API strips
  // them for non-admin callers (see publicUser in the Go server). Hide the
  // corresponding column for non-admins to avoid a row of empty dashes.
  const byID = new Map(users.map((u) => [u.id, u]));
  const rows = users
    .map((u) => {
      const mgr = u.validator_user_id ? byID.get(u.validator_user_id) : undefined;
      const mgrCell = mgr
        ? `${escapeHtml(mgr.username)} <span class="muted">(${escapeHtml(mgr.display_name || '')})</span>`
        : '<span class="muted">—</span>';
      const admin = u.is_admin ? ' <span class="badge">admin</span>' : '';
      return `
        <tr data-user-id="${escapeHtml(u.id)}">
          <td>${escapeHtml(u.username)}${admin}</td>
          <td>${escapeHtml(u.display_name || '')}</td>
          <td>${escapeHtml(u.email || '')}</td>
          ${
            isAdmin
              ? `<td class="validator-cell">${mgrCell}</td>
                 <td>
                   <button data-action="edit-validator" data-user-id="${escapeHtml(u.id)}">edit</button>
                   ${u.validator_user_id ? `<button data-action="clear-validator" data-user-id="${escapeHtml(u.id)}">clear</button>` : ''}
                 </td>`
              : ''
          }
        </tr>
      `;
    })
    .join('');

  const cols = isAdmin ? 5 : 3;
  panel.innerHTML = `
    <h3>Users</h3>
    <table>
      <thead>
        <tr><th>Username</th><th>Display name</th><th>Email</th>${isAdmin ? '<th>Validator</th><th></th>' : ''}</tr>
      </thead>
      <tbody>${rows || `<tr><td colspan="${cols}" class="muted">no users yet</td></tr>`}</tbody>
    </table>
  `;

  if (!isAdmin) return;
  panel.addEventListener('click', async (ev) => {
    const target = ev.target as HTMLElement;
    const action = target.dataset.action;
    const userID = target.dataset.userId;
    if (!action || !userID) return;
    try {
      if (action === 'edit-validator') {
        // Pick from the existing users via a prompt — minimal but effective
        // until the SPA grows a proper combobox.
        const picks = users
          .filter((u) => u.id !== userID)
          .map((u) => `${u.username} (id=${u.id})`);
        const choice = window.prompt(
          `Set validator for ${userID}. Paste the target username from:\n${picks.join('\n')}`,
        );
        if (!choice) return;
        const match = users.find((u) => u.username === choice.trim());
        if (!match) {
          showErr(new Error(`username not found: ${choice}`));
          return;
        }
        await setUserValidator(userID, match.id);
      } else if (action === 'clear-validator') {
        await clearUserValidator(userID);
      }
      // Re-render from fresh data on success.
      const fresh = await listUsers();
      await renderUsersPanel(root, fresh, isAdmin, showErr);
    } catch (e) {
      showErr(e);
    }
  });
}

// --- groups ---

async function renderGroupsPanel(
  root: HTMLElement,
  users: User[],
  groups: Group[],
  isAdmin: boolean,
  showErr: (e: unknown) => void,
): Promise<void> {
  const panel = root.querySelector<HTMLDivElement>('#groups-panel');
  if (!panel) return;

  // Pre-fetch member counts in parallel — the UI renders member names lazily
  // when a row expands, so keep the list compact here.
  const counts = await Promise.all(groups.map((g) => listGroupMembers(g.id).then((m) => m.length)));
  const rows = groups
    .map(
      (g, i) => `
        <tr data-group-id="${escapeHtml(g.id)}">
          <td><code>${escapeHtml(g.slug)}</code></td>
          <td>${escapeHtml(g.display_name || '')}</td>
          <td>${counts[i]}</td>
          <td>
            <button data-action="show-members" data-group-id="${escapeHtml(g.id)}">members</button>
            ${isAdmin ? `<button data-action="add-member" data-group-id="${escapeHtml(g.id)}">+ member</button>` : ''}
            ${isAdmin ? `<button data-action="delete-group" data-group-id="${escapeHtml(g.id)}">delete</button>` : ''}
          </td>
        </tr>
        <tr class="members-row hidden" data-members-for="${escapeHtml(g.id)}">
          <td colspan="4" class="members-cell">—</td>
        </tr>
      `,
    )
    .join('');

  panel.innerHTML = `
    <h3>Groups</h3>
    ${
      isAdmin
        ? `<form id="group-create">
             <input name="slug" placeholder="slug (required)" required>
             <input name="display_name" placeholder="display name">
             <button type="submit">Create / upsert</button>
           </form>`
        : ''
    }
    <table>
      <thead>
        <tr><th>Slug</th><th>Display name</th><th>Members</th><th></th></tr>
      </thead>
      <tbody>${rows || '<tr><td colspan="4" class="muted">no groups yet</td></tr>'}</tbody>
    </table>
  `;

  panel.addEventListener('click', async (ev) => {
    const target = ev.target as HTMLElement;
    const action = target.dataset.action;
    const gid = target.dataset.groupId;
    if (!action || !gid) return;
    try {
      if (action === 'show-members') {
        await toggleMembers(panel, gid);
      } else if (action === 'add-member' && isAdmin) {
        const choice = window.prompt(
          `Add member to group. Paste a username:\n${users.map((u) => u.username).join('\n')}`,
        );
        if (!choice) return;
        const match = users.find((u) => u.username === choice.trim());
        if (!match) {
          showErr(new Error(`username not found: ${choice}`));
          return;
        }
        await addGroupMember(gid, match.id);
        await renderGroupsPanel(root, users, await listGroups(), isAdmin, showErr);
      } else if (action === 'delete-group' && isAdmin) {
        if (
          !window.confirm(
            `Delete group ${gid}? User rows stay; membership in THIS group is dropped. Memberships in other groups are untouched.`,
          )
        )
          return;
        await deleteGroup(gid);
        await renderGroupsPanel(root, users, await listGroups(), isAdmin, showErr);
      }
    } catch (e) {
      showErr(e);
    }
  });

  if (!isAdmin) return;
  const form = panel.querySelector<HTMLFormElement>('#group-create');
  form?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fd = new FormData(form);
    try {
      await upsertGroup({
        slug: String(fd.get('slug') || ''),
        display_name: String(fd.get('display_name') || ''),
      });
      form.reset();
      await renderGroupsPanel(root, users, await listGroups(), isAdmin, showErr);
    } catch (e) {
      showErr(e);
    }
  });
}

async function toggleMembers(panel: HTMLElement, groupID: string): Promise<void> {
  const row = panel.querySelector<HTMLTableRowElement>(`tr[data-members-for="${CSS.escape(groupID)}"]`);
  if (!row) return;
  const cell = row.querySelector<HTMLTableCellElement>('.members-cell');
  if (!cell) return;
  if (!row.classList.contains('hidden')) {
    row.classList.add('hidden');
    return;
  }
  cell.textContent = 'Loading…';
  row.classList.remove('hidden');
  try {
    const members = await listGroupMembers(groupID);
    cell.innerHTML =
      members.length === 0
        ? '<span class="muted">no members</span>'
        : members
            .map(
              (m) =>
                `<span class="member">${escapeHtml(m.username)} <button data-action="remove-member" data-group-id="${escapeHtml(groupID)}" data-user-id="${escapeHtml(m.id)}">×</button></span>`,
            )
            .join(' ');
    cell.addEventListener('click', async (ev) => {
      const t = ev.target as HTMLElement;
      if (t.dataset.action !== 'remove-member') return;
      try {
        await removeGroupMember(t.dataset.groupId!, t.dataset.userId!);
        await toggleMembers(panel, groupID); // collapse
        await toggleMembers(panel, groupID); // re-open fresh
      } catch (e) {
        cell.textContent = e instanceof Error ? e.message : String(e);
      }
    });
  } catch (e) {
    cell.textContent = e instanceof Error ? e.message : String(e);
  }
}

// Reverse-index helper retained for completeness — current view doesn't yet
// surface it but keeping the import active makes it trivial to add a user
// detail drawer later.
export async function fetchUserGroups(userID: string): Promise<Group[]> {
  return listUserGroups(userID);
}
