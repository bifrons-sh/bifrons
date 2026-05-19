// React Query bindings. Each hook owns one cache key family so mutations
// know exactly which lists to invalidate. Keep keys flat ['grants', scope,
// status] — flat keys make `invalidateQueries({ queryKey: ['grants'] })`
// behave as expected without surprises.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api } from './client';
import type {
  ApproveBody,
  Backend,
  ClaimResponse,
  CreateGrantInput,
  Grant,
  GrantStatus,
  Group,
  Session,
  User,
} from './types';

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

export function useClaimGrant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<ClaimResponse>(`/api/v1/grants/${encodeURIComponent(id)}/claim`),
    onSuccess: (_data, id) => {
      void qc.invalidateQueries({ queryKey: ['grant', id] });
      void qc.invalidateQueries({ queryKey: ['grants'] });
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
