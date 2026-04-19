// Tiny fetch wrapper for the portal REST API.
//
// Design notes:
//   - Same-origin by default — the portal serves /ui and /api from the
//     same process, so no CORS and cookies flow automatically.
//   - A 401 anywhere in the app means the operator's session expired.
//     We bounce straight to /oidc/login so the IdP can refresh it; the
//     callback returns us to the last requested SPA route via state.
//   - Errors are normalised to a single Error instance so views can
//     render `err.message` without type-juggling.

export interface Session {
  username: string;
  email?: string;
  subject?: string;
  is_admin: boolean;
}

export interface Grant {
  id: string;
  user_id: string;
  backend_id: string;
  role: string;
  status: string;
  database?: string;
  reason?: string;
  requested_by?: string;
  expires_at?: string | null;
  approved_at?: string | null;
  approved_by?: string;
  denied_at?: string | null;
  denied_by?: string;
  created_at?: string;
}

export interface Backend {
  id: string;
  name: string;
  type: string;
  host: string;
  port: number;
  databases?: string[];
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const resp = await fetch(path, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json', ...(init.headers ?? {}) },
    ...init,
  });

  if (resp.status === 401) {
    // Hard redirect — replace the current history entry so the Back
    // button doesn't ping-pong between SPA route and /oidc/login.
    window.location.replace('/oidc/login');
    // Never resolves; the navigation tears down the JS context.
    return new Promise<T>(() => {});
  }
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const body = await resp.json();
      if (body && typeof body.error === 'string') {
        msg = body.error;
      }
    } catch {
      /* non-JSON bodies fall through with the status line */
    }
    throw new Error(msg);
  }
  if (resp.status === 204) {
    return undefined as T;
  }
  return (await resp.json()) as T;
}

export function fetchSession(): Promise<Session | null> {
  // Session probe is treated specially: a failure just means "logged out".
  return fetch('/api/v1/session', { credentials: 'same-origin' }).then((r) => {
    if (r.status === 401) return null;
    if (!r.ok) throw new Error(`session probe failed: ${r.status}`);
    return r.json();
  });
}

export function listGrants(status?: string): Promise<Grant[]> {
  const q = status ? `?status=${encodeURIComponent(status)}` : '';
  return request<Grant[]>(`/api/v1/grants${q}`);
}

export function listBackends(): Promise<Backend[]> {
  return request<Backend[]>('/api/v1/backends');
}
