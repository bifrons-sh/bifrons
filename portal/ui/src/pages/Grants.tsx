// Grants list view. Drives both "My requests" (scope=mine) and "Awaiting me"
// (scope=validator). Status + scope + type filter live in URL search params
// so deep-links and the Back button work properly — this was the bug in v0.1
// where the hash router would fall through to the welcome screen on any
// filter change.

import {
  Anchor,
  Badge,
  Button,
  Card,
  Center,
  Chip,
  Group,
  Loader,
  ScrollArea,
  SegmentedControl,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
  UnstyledButton,
} from '@mantine/core';
import { IconChevronDown, IconChevronUp, IconPlus, IconRefresh, IconSelector } from '@tabler/icons-react';
import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { useBackends, useGrants, useSession, useUsers } from '../api/hooks';
import type { Backend, Grant, GrantStatus, User } from '../api/types';
import { GrantStatusPill } from '../components/GrantStatusPill';
import { formatRelative } from '../util/time';

// Colour vocabulary for engine badges — mirrors the Backends page so the
// "this is a postgres grant" hint is consistent across views.
const TYPE_COLOR: Record<string, string> = {
  mysql: 'orange',
  postgres: 'indigo',
  mongo: 'green',
};

const STATUSES: (GrantStatus | 'ALL')[] = [
  'ALL',
  'PENDING',
  'VALIDATOR_APPROVED',
  'APPROVED',
  'ACTIVE',
  'DENIED',
  'REVOKED',
  'EXPIRED',
];

// Sortable columns. Keys map to a selector function in `getSortValue`.
type SortKey = 'backend_name' | 'backend_type' | 'user' | 'role' | 'status' | 'requested' | 'expires';
type SortDir = 'asc' | 'desc';

function parseScope(v: string | null, isOperator: boolean): 'mine' | 'validator' | 'all' {
  if (v === 'validator') return 'validator';
  if (v === 'all' && isOperator) return 'all';
  return 'mine';
}

function parseStatus(v: string | null): GrantStatus | 'ALL' {
  if (!v) return 'ALL';
  return (STATUSES as string[]).includes(v) ? (v as GrantStatus | 'ALL') : 'ALL';
}

export function Grants() {
  const session = useSession();
  const isOperator = !!session.data?.is_operator;
  const [sp, setSp] = useSearchParams();
  const scope = parseScope(sp.get('scope'), isOperator);
  const status = parseStatus(sp.get('status'));
  const typeFilter = sp.get('type') ?? 'ALL';

  const list = useGrants({ scope, status });
  // Backends + users hydrate the IDs the grant row only carries by reference.
  // Both are small lists that the navbar already loads, so the query cache
  // serves these calls for free.
  const backends = useBackends();
  const users = useUsers();
  const backendByID = useMemo(
    () => new Map((backends.data ?? []).map((b) => [b.id, b])),
    [backends.data],
  );
  const userByID = useMemo(
    () => new Map((users.data ?? []).map((u) => [u.id, u])),
    [users.data],
  );

  // The set of engine types present in the current backend roster — drives
  // the chip filter dynamically so we don't render dead `kafka` etc.
  const availableTypes = useMemo(() => {
    const t = new Set<string>();
    for (const b of backends.data ?? []) t.add(b.type);
    return Array.from(t).sort();
  }, [backends.data]);

  // Client-side sort (the list endpoint doesn't accept order_by today).
  // Default: most recent first by requested time.
  const [sortKey, setSortKey] = useState<SortKey>('requested');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const filteredSorted = useMemo(() => {
    const rows = list.data ?? [];
    const filtered =
      typeFilter === 'ALL'
        ? rows
        : rows.filter((g) => backendByID.get(g.backend_id)?.type === typeFilter);
    const sign = sortDir === 'asc' ? 1 : -1;
    const sorted = [...filtered].sort((a, b) => {
      const av = getSortValue(a, sortKey, backendByID, userByID);
      const bv = getSortValue(b, sortKey, backendByID, userByID);
      if (av === bv) return 0;
      // Nullish/undefined values always sort last regardless of direction.
      if (av === undefined || av === null) return 1;
      if (bv === undefined || bv === null) return -1;
      return av < bv ? -1 * sign : 1 * sign;
    });
    return sorted;
  }, [list.data, typeFilter, sortKey, sortDir, backendByID, userByID]);

  const setScope = (s: 'mine' | 'validator' | 'all') => {
    const next = new URLSearchParams(sp);
    if (s === 'mine') next.delete('scope');
    else next.set('scope', s);
    setSp(next, { replace: false });
  };
  const setStatus = (s: GrantStatus | 'ALL') => {
    const next = new URLSearchParams(sp);
    if (s === 'ALL') next.delete('status');
    else next.set('status', s);
    setSp(next, { replace: true });
  };
  const setTypeFilter = (t: string) => {
    const next = new URLSearchParams(sp);
    if (!t || t === 'ALL') next.delete('type');
    else next.set('type', t);
    setSp(next, { replace: true });
  };

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'requested' || key === 'expires' ? 'desc' : 'asc');
    }
  };

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Grants</Title>
          <Text c="dimmed" size="sm">
            {scope === 'mine' && 'Access requests you submitted.'}
            {scope === 'validator' && 'Requests waiting on your approval as a validator.'}
            {scope === 'all' && 'Every grant in the system (admin scope).'}
          </Text>
        </div>
        <Group gap="xs">
          <Tooltip label="Refresh">
            <Button
              variant="default"
              size="sm"
              onClick={() => void list.refetch()}
              leftSection={<IconRefresh size={16} />}
            >
              Refresh
            </Button>
          </Tooltip>
          <Button component={Link} to="/grants/new" leftSection={<IconPlus size={16} />} size="sm">
            Request access
          </Button>
        </Group>
      </Group>

      <Card withBorder radius="md" p="md">
        <Stack gap="sm">
          <SegmentedControl
            value={scope}
            onChange={(v) => setScope(v as 'mine' | 'validator' | 'all')}
            data={[
              { value: 'mine', label: 'My requests' },
              { value: 'validator', label: 'Awaiting me' },
              ...(isOperator ? [{ value: 'all', label: 'All grants' }] : []),
            ]}
          />
          <FilterRow label="Status">
            <Chip.Group multiple={false} value={status} onChange={(v) => setStatus(v as GrantStatus | 'ALL')}>
              <Group gap="xs">
                {STATUSES.map((s) => (
                  <Chip key={s} value={s} size="xs" variant="outline">
                    {s === 'ALL' ? 'All' : labelStatus(s)}
                  </Chip>
                ))}
              </Group>
            </Chip.Group>
          </FilterRow>
          {availableTypes.length > 1 && (
            <FilterRow label="Type">
              <Chip.Group multiple={false} value={typeFilter} onChange={(v) => setTypeFilter(v as string)}>
                <Group gap="xs">
                  <Chip value="ALL" size="xs" variant="outline">
                    All
                  </Chip>
                  {availableTypes.map((t) => (
                    <Chip key={t} value={t} size="xs" variant="outline" color={TYPE_COLOR[t] ?? 'gray'}>
                      {t}
                    </Chip>
                  ))}
                </Group>
              </Chip.Group>
            </FilterRow>
          )}
        </Stack>
      </Card>

      <Card withBorder radius="md" p={0}>
        {list.isLoading ? (
          <Center p="xl">
            <Loader size="sm" />
          </Center>
        ) : list.isError ? (
          <Center p="xl">
            <Stack align="center" gap="xs">
              <Text c="red">Failed to load grants.</Text>
              <Text c="dimmed" size="sm">
                {(list.error as Error).message}
              </Text>
              <Button variant="light" size="xs" onClick={() => void list.refetch()}>
                Try again
              </Button>
            </Stack>
          </Center>
        ) : filteredSorted.length === 0 ? (
          <Center p="xl">
            <Stack align="center" gap="xs">
              <Text c="dimmed">
                {scope === 'validator'
                  ? 'No grants are waiting on your approval.'
                  : 'No grants match these filters.'}
              </Text>
              {scope === 'mine' && (
                <Anchor component={Link} to="/grants/new" size="sm">
                  Request access →
                </Anchor>
              )}
            </Stack>
          </Center>
        ) : (
          <GrantsTable
            rows={filteredSorted}
            backendByID={backendByID}
            userByID={userByID}
            sortKey={sortKey}
            sortDir={sortDir}
            onSort={toggleSort}
          />
        )}
      </Card>
    </Stack>
  );
}

function FilterRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Group gap="md" align="center" wrap="nowrap">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} w={56}>
        {label}
      </Text>
      {children}
    </Group>
  );
}

function GrantsTable({
  rows,
  backendByID,
  userByID,
  sortKey,
  sortDir,
  onSort,
}: {
  rows: Grant[];
  backendByID: Map<string, Backend>;
  userByID: Map<string, User>;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  return (
    <ScrollArea>
      <Table verticalSpacing="sm" highlightOnHover withRowBorders={false} striped="even" miw={1000}>
        <Table.Thead>
          <Table.Tr>
            <SortableTh sortKey="backend_type" current={sortKey} dir={sortDir} onClick={onSort} label="Type" />
            <SortableTh sortKey="backend_name" current={sortKey} dir={sortDir} onClick={onSort} label="Backend" />
            <SortableTh sortKey="user" current={sortKey} dir={sortDir} onClick={onSort} label="User" />
            <SortableTh sortKey="role" current={sortKey} dir={sortDir} onClick={onSort} label="Role · DB" />
            <SortableTh sortKey="status" current={sortKey} dir={sortDir} onClick={onSort} label="Status" />
            <SortableTh sortKey="requested" current={sortKey} dir={sortDir} onClick={onSort} label="Requested" />
            <SortableTh sortKey="expires" current={sortKey} dir={sortDir} onClick={onSort} label="Expires" />
            <Table.Th>Grant</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((g) => {
            const b = backendByID.get(g.backend_id);
            const u = userByID.get(g.user_id);
            return (
              <Table.Tr key={g.id}>
                <Table.Td>
                  {b ? (
                    <Badge color={TYPE_COLOR[b.type] ?? 'gray'} variant="light" size="sm">
                      {b.type}
                    </Badge>
                  ) : (
                    <Text size="xs" c="dimmed">
                      —
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  {b ? (
                    <Tooltip label={`${b.host}:${b.port}`}>
                      <Text size="sm" fw={500} truncate maw={260}>
                        {b.name}
                      </Text>
                    </Tooltip>
                  ) : (
                    <Text size="sm" ff="monospace" c="dimmed" truncate maw={200}>
                      {g.backend_id}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  {u ? (
                    <Tooltip label={u.email || u.id} disabled={!u.email && !u.id}>
                      <Text size="sm" truncate maw={180}>
                        {u.username}
                      </Text>
                    </Tooltip>
                  ) : (
                    <Text size="sm" ff="monospace" c="dimmed" truncate maw={160}>
                      {g.user_id}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="sm">
                    <strong>{g.role}</strong>
                    {g.database ? <Text component="span" c="dimmed"> · {g.database}</Text> : null}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <GrantStatusPill status={g.status} />
                </Table.Td>
                <Table.Td>
                  <Tooltip label={g.requested_at ?? '—'} disabled={!g.requested_at}>
                    <Text size="sm" c="dimmed">
                      {formatRelative(g.requested_at ?? g.created_at)}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Tooltip label={g.expires_at ?? '—'} disabled={!g.expires_at}>
                    <Text size="sm" c="dimmed">
                      {formatRelative(g.expires_at)}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Anchor component={Link} to={`/grants/${g.id}`} size="xs" ff="monospace">
                    {g.id.slice(0, 12)}…
                  </Anchor>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}

function SortableTh({
  sortKey,
  current,
  dir,
  onClick,
  label,
}: {
  sortKey: SortKey;
  current: SortKey;
  dir: SortDir;
  onClick: (k: SortKey) => void;
  label: string;
}) {
  const active = current === sortKey;
  const Icon = active ? (dir === 'asc' ? IconChevronUp : IconChevronDown) : IconSelector;
  return (
    <Table.Th>
      <UnstyledButton
        onClick={() => onClick(sortKey)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          color: active ? 'var(--mantine-color-indigo-6)' : 'inherit',
        }}
        aria-label={`Sort by ${label}`}
      >
        <Text size="sm" fw={600} component="span">
          {label}
        </Text>
        <Icon size={14} />
      </UnstyledButton>
    </Table.Th>
  );
}

function getSortValue(
  g: Grant,
  key: SortKey,
  backendByID: Map<string, Backend>,
  userByID: Map<string, User>,
): string | number | undefined {
  switch (key) {
    case 'backend_name':
      return backendByID.get(g.backend_id)?.name?.toLowerCase() ?? g.backend_id;
    case 'backend_type':
      return backendByID.get(g.backend_id)?.type?.toLowerCase() ?? 'zzzz';
    case 'user':
      return userByID.get(g.user_id)?.username?.toLowerCase() ?? g.user_id;
    case 'role':
      return `${g.role} ${g.database ?? ''}`;
    case 'status':
      return g.status;
    case 'requested':
      return Date.parse(g.requested_at ?? g.created_at ?? '') || 0;
    case 'expires':
      return Date.parse(g.expires_at ?? '') || 0;
  }
}

function labelStatus(s: GrantStatus): string {
  switch (s) {
    case 'VALIDATOR_APPROVED':
      return 'T1 ✓';
    default:
      return s.charAt(0) + s.slice(1).toLowerCase();
  }
}
