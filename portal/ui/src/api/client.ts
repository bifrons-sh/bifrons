// Tiny fetch wrapper for the portal REST API.
//
// Design:
//   - Same-origin (the SPA is served by the portal Go process under /ui)
//     so cookies + CSRF land naturally and CORS is a non-issue.
//   - 401 → hard-redirect to /oidc/login. The promise never resolves so
//     React Query keeps the failing query in `error` state, avoiding a
//     flash of empty content before the navigation.
//   - All errors normalised to Error so views can render `err.message`.

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'HttpError';
  }
}

interface RequestInitJSON extends Omit<RequestInit, 'body'> {
  body?: unknown;
}

async function request<T>(path: string, init: RequestInitJSON = {}): Promise<T> {
  const { body, headers, ...rest } = init;
  const isJSONBody = body !== undefined && body !== null && typeof body !== 'string';
  const resp = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(isJSONBody ? { 'Content-Type': 'application/json' } : {}),
      ...(headers ?? {}),
    },
    body: body === undefined ? undefined : isJSONBody ? JSON.stringify(body) : (body as BodyInit),
    ...rest,
  });

  if (resp.status === 401) {
    // OIDC isn't configured in local dev (user-token empty too); in that
    // path the portal lets requests through, so 401 here means a real
    // expired session in a deployed instance. Redirect to start the
    // login flow; the promise never settles.
    window.location.replace('/oidc/login');
    return new Promise<T>(() => {});
  }

  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data && typeof data.error === 'string') msg = data.error;
    } catch {
      /* non-JSON body */
    }
    throw new HttpError(resp.status, msg);
  }
  if (resp.status === 204) return undefined as T;
  // Some endpoints (claim, approve) return 200 with a JSON body. Some
  // return empty. Detect empty bodies safely.
  const text = await resp.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
