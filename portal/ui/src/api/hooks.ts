// React Query bindings. Each hook owns one cache key family so mutations
// know exactly which lists to invalidate. Keep keys flat ['grants', scope,
// status] — flat keys make `invalidateQueries({ queryKey: ['grants'] })`
// behave as expected without surprises.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api } from './client';
import type {
  ApproveBody,
  Backend,
  ClaimPostResult,
  ClaimStatusResult,
  CreateGrantInput,
  Grant,
  GrantStatus,
  Group,
  Session,
  User,
} from './types';
import { isClaimDone, isClaimFailed } from './types';

// --- session probe ---------------------------------------------------------

// Returns null on 401 instead of redirecting; the SPA itself decides whether
// to render the welcome screen or kick off /oidc/login. All other failures
// surface as a thrown error (handled by the query's error state).
async function probeSession(): Promise<Session | null> {
  const resp = await fetch('/api/v1/session', { credentials: 'same-origin' });
  if (resp.status === 401) return null;
  if (!resp.ok) throw new Error(`session probe: ${resp.status}`);
  return (await resp.json()) as Session;
}

export function useSession() {
  return useQuery({
    queryKey: ['session'],
    queryFn: probeSession,
    // The session rarely changes mid-tab; refetch only on focus to catch
    // a server-side logout invalidating the cookie.
    staleTime: 60_000,
  });
}

// --- grants ---------------------------------------------------------------

export interface GrantListOpts {
  scope?: 'mine' | 'validator' | 'all';
  status?: GrantStatus | 'ALL';
}

export function useGrants(opts: GrantListOpts = {}) {
  const { scope, status } = opts;
  return useQuery({
    queryKey: ['grants', scope ?? null, status ?? null],
    queryFn: () => {
      const qs = new URLSearchParams();
      if (scope) qs.set('scope', scope);
      if (status && status !== 'ALL') qs.set('status', status);
      const s = qs.toString();
      return api.get<Grant[]>(`/api/v1/grants${s ? `?${s}` : ''}`);
    },
  });
}

export function useGrant(id: string | undefined) {
  return useQuery({
    queryKey: ['grant', id],
    queryFn: () => api.get<Grant>(`/api/v1/grants/${encodeURIComponent(id!)}`),
    enabled: !!id,
  });
}

export function useCreateGrant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateGrantInput) => api.post<Grant>('/api/v1/grants', input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['grants'] });
    },
  });
}

export function useApproveGrant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body?: ApproveBody }) =>
      api.post<Grant>(`/api/v1/grants/${encodeURIComponent(id)}/approve`, body ?? {}),
    onSuccess: (data) => {
      qc.setQueryData(['grant', data.id], data);
      void qc.invalidateQueries({ queryKey: ['grants'] });
    },
  });
}

export function useDenyGrant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<Grant>(`/api/v1/grants/${encodeURIComponent(id)}/deny`),
    onSuccess: (data) => {
      qc.setQueryData(['grant', data.id], data);
      void qc.invalidateQueries({ queryKey: ['grants'] });
    },
  });
}

// Poll cap: status refetches at 1s, so ~30 attempts ≈ 30s before we give up
// and tell the operator the provisioner looks slow / hard-down. Past this the
// grant may still settle server-side — the message says "retry", not "failed".
export const CLAIM_POLL_CAP = 30;

// POST /claim. Returns either issued creds (worker finished inline) or a
// pending marker (202). On the pending path the component flips to polling;
// invalidation of the grant lists is deferred to terminal completion (handled
// in useClaimStatus) so a still-PENDING claim doesn't churn the cache.
export function useClaimGrant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<ClaimPostResult>(`/api/v1/grants/${encodeURIComponent(id)}/claim`),
    onSuccess: (data, id) => {
      // Only a finished claim mutates grant state; a pending one hasn't moved
      // the grant to ACTIVE yet, so leave the caches alone until polling ends.
      if (isClaimDone(data)) {
        void qc.invalidateQueries({ queryKey: ['grant', id] });
        void qc.invalidateQueries({ queryKey: ['grants'] });
      }
    },
  });
}

// GET /claim/status. The shared client throws on non-2xx, but a 422 here is a
// structured terminal-failure body we want to render — so this query fetches
// directly and folds the 422 into a ClaimFailed value instead of an error.
// 401 still hard-redirects to keep auth behaviour consistent with the client.
async function fetchClaimStatus(id: string): Promise<ClaimStatusResult> {
  const resp = await fetch(`/api/v1/grants/${encodeURIComponent(id)}/claim/status`, {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  if (resp.status === 401) {
    window.location.replace('/oidc/login');
    return new Promise<ClaimStatusResult>(() => {});
  }
  if (resp.status === 422) {
    return (await resp.json()) as ClaimStatusResult; // ClaimFailed
  }
  if (!resp.ok) throw new Error(`claim status: ${resp.status}`);
  return (await resp.json()) as ClaimStatusResult;
}

// Polling companion to useClaimGrant. `enabled` is driven by the caller (true
// only after a pending POST). refetchInterval stops once the result is
// terminal (done or failed) by returning false; the caller enforces the
// CLAIM_POLL_CAP via dataUpdatedCount so a stuck provisioner can't poll
// forever.
export function useClaimStatus(id: string | undefined, enabled: boolean) {
  const qc = useQueryClient();
  return useQuery({
    queryKey: ['claim-status', id],
    queryFn: () => fetchClaimStatus(id!),
    enabled: enabled && !!id,
    // Don't reuse a stale terminal result from a previous claim attempt.
    gcTime: 0,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && (isClaimDone(data) || isClaimFailed(data))) {
        // Terminal: a finished claim flipped the grant to ACTIVE server-side.
        if (isClaimDone(data) && id) {
          void qc.invalidateQueries({ queryKey: ['grant', id] });
          void qc.invalidateQueries({ queryKey: ['grants'] });
        }
        return false;
      }
      return 1000;
    },
  });
}

// --- backends -------------------------------------------------------------

export function useBackends() {
  return useQuery({
    queryKey: ['backends'],
    queryFn: () => api.get<Backend[]>('/api/v1/backends'),
  });
}

// --- org: users + groups --------------------------------------------------

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => api.get<User[]>('/api/v1/users'),
  });
}

export function useGroups() {
  return useQuery({
    queryKey: ['groups'],
    queryFn: () => api.get<Group[]>('/api/v1/groups'),
  });
}

// useUserValidator hits the dedicated /validator endpoint, which (unlike the
// trimmed list) is callable by ANY authenticated user and returns the
// validator's id + username. The grant-detail page uses this to decide
// whether to render the Approve button — `useUsers()` would strip the
// `validator_user_id` field on non-admin sessions (see publicUser in the Go
// admin handler) and silently break the gate for the validator themselves.
export function useUserValidator(userID: string | undefined) {
  return useQuery({
    queryKey: ['user-validator', userID],
    queryFn: () =>
      api.get<{ validator: { id: string; username: string } | null }>(
        `/api/v1/users/${encodeURIComponent(userID!)}/validator`,
      ),
    enabled: !!userID,
  });
}

export function useGroupMembers(groupID: string | undefined) {
  return useQuery({
    queryKey: ['group-members', groupID],
    queryFn: () => api.get<User[]>(`/api/v1/groups/${encodeURIComponent(groupID!)}/members`),
    enabled: !!groupID,
  });
}

export function useSetUserValidator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userID, validatorUserID }: { userID: string; validatorUserID: string }) =>
      api.put<void>(`/api/v1/users/${encodeURIComponent(userID)}/validator`, {
        validator_user_id: validatorUserID,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

export function useClearUserValidator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userID: string) =>
      api.del<void>(`/api/v1/users/${encodeURIComponent(userID)}/validator`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['users'] });
    },
  });
}

export function useUpsertGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (g: { id?: string; slug: string; display_name?: string; external_id?: string }) =>
      api.post<Group>('/api/v1/groups', g),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['groups'] });
    },
  });
}

export function useDeleteGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (groupID: string) =>
      api.del<void>(`/api/v1/groups/${encodeURIComponent(groupID)}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['groups'] });
    },
  });
}

export function useAddGroupMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ groupID, userID }: { groupID: string; userID: string }) =>
      api.post<void>(
        `/api/v1/groups/${encodeURIComponent(groupID)}/members/${encodeURIComponent(userID)}`,
      ),
    onSuccess: (_d, { groupID }) => {
      void qc.invalidateQueries({ queryKey: ['group-members', groupID] });
      void qc.invalidateQueries({ queryKey: ['groups'] });
    },
  });
}

export function useRemoveGroupMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ groupID, userID }: { groupID: string; userID: string }) =>
      api.del<void>(
        `/api/v1/groups/${encodeURIComponent(groupID)}/members/${encodeURIComponent(userID)}`,
      ),
    onSuccess: (_d, { groupID }) => {
      void qc.invalidateQueries({ queryKey: ['group-members', groupID] });
      void qc.invalidateQueries({ queryKey: ['groups'] });
    },
  });
}
