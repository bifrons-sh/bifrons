// Portal API DTOs. Only the fields the SPA actually reads/writes are
// modelled; the server is the source of truth and may return additional
// keys the UI safely ignores.

export type GrantStatus =
  | 'PENDING'
  | 'VALIDATOR_APPROVED'
  | 'APPROVED'
  | 'ACTIVE'
  | 'DENIED'
  | 'REVOKED'
  | 'EXPIRED';

export interface Session {
  username: string;
  user_id?: string;
  email?: string;
  subject?: string;
  is_operator: boolean;
  // IdP-side profile page (Keycloak: <issuer>/account/, Okta: /profile, …).
  // Surfaced by the portal from -oidc-account-url so the SPA can navigate
  // there after logout. Empty when the operator hasn't configured it; the
  // logout handler falls back to the portal root.
  account_url?: string;
}

export interface Grant {
  id: string;
  user_id: string;
  backend_id: string;
  database?: string;
  role: string;
  status: GrantStatus;
  reason?: string;
  requested_by?: string;
  requested_at?: string;
  approver_hint?: string;
  t1_subject?: string;
  t1_approved_by?: string;
  t1_approved_at?: string | null;
  t1_approved_on_behalf?: boolean;
  t1_on_behalf_reason?: string;
  t2_approved_by?: string;
  t2_approved_at?: string | null;
  denied_by?: string;
  denied_at?: string | null;
  request_expires_at?: string | null;
  claim_expires_at?: string | null;
  expires_at?: string | null;
  revoked_at?: string | null;
  policy_mode?: 'permanent' | 'ephemeral';
  ephemeral_username?: string;
  created_at?: string;
  updated_at?: string;
}

export interface Backend {
  id: string;
  name: string;
  type: 'mysql' | 'postgres' | 'mongo' | string;
  host: string;
  port: number;
  databases?: string[];
  approval_mode?: 'dual_strict' | 'dual_or' | 'validator_only';
  t2_group_slug?: string;
}

export interface User {
  id: string;
  username: string;
  display_name?: string;
  email?: string;
  external_id?: string;
  validator_user_id?: string;
  is_operator?: boolean;
  status?: string;
}

export interface Group {
  id: string;
  slug: string;
  display_name?: string;
  external_id?: string;
}

export interface ClaimResponse {
  backend_user: string;
  backend_pass: string;
  portal_password: string;
  expires_at: string;
}

// Provisioning is async (Workstream D): the worker may not finish within the
// portal's 2s inline budget, so a claim can land "pending" and the UI polls
// the status endpoint until it terminates.
export interface ClaimPending {
  state: 'pending' | 'in_flight';
  intent_id?: string;
  elapsed_ms?: number;
}

export interface ClaimFailed {
  state: 'failed';
  error_class: string;
  error_detail: string;
}

// POST /claim returns one of these as 2xx. The client wrapper hides the status
// code (202 is "ok" to fetch), so callers discriminate by shape:
// `backend_user` present ⇒ done; `state` present ⇒ still provisioning.
export type ClaimPostResult = ClaimResponse | ClaimPending;

// GET /claim/status: done (ClaimResponse), still working (ClaimPending), or
// terminally failed (ClaimFailed, surfaced as 422).
export type ClaimStatusResult = ClaimResponse | ClaimPending | ClaimFailed;

export function isClaimDone(r: ClaimPostResult | ClaimStatusResult): r is ClaimResponse {
  return 'backend_user' in r;
}

export function isClaimFailed(r: ClaimStatusResult): r is ClaimFailed {
  return 'state' in r && r.state === 'failed';
}

export interface CreateGrantInput {
  user_id?: string; // empty → derive from session
  backend_addr: string;
  database?: string;
  role: string;
  reason?: string;
  validation_window?: string;
  claim_window?: string;
  credential_ttl?: string;
}

export interface ApproveBody {
  on_behalf_of_t1?: boolean;
  reason?: string;
}
