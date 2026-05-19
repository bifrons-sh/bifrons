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
