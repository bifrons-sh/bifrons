import {
  Anchor,
  Button,
  Card,
  Grid,
  Group,
  SimpleGrid,
  Skeleton,
  Stack,
  Text,
  Title,
} from '@mantine/core';
import { IconArrowRight, IconClockExclamation, IconClockPause, IconShieldLock } from '@tabler/icons-react';
import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import { useBackends, useGrants, useSession } from '../api/hooks';
import { GrantStatusPill } from '../components/GrantStatusPill';
import { formatRelative } from '../util/time';

// Home is the landing page after sign-in: a quick health snapshot + shortcuts.
// Non-signed-in users see the bare CTA — Sign in or the demo-mode pointer.

export function Home() {
  const session = useSession();
  const mine = useGrants({ scope: 'mine' });
  const queue = useGrants({ scope: 'validator' });
  const backends = useBackends();
  // Index once instead of backends.find() per recent-request row — keeps the
  // backend lookup O(n) rather than O(n²). Mirrors the byID pattern in Grants.
  const backendByID = useMemo(
    () => new Map((backends.data ?? []).map((b) => [b.id, b])),
    [backends.data],
  );

  if (session.isLoading) {
    return <Skeleton h={200} />;
  }

  if (!session.data) {
    return (
      <Card withBorder radius="md" p="xl" maw={520} mx="auto" mt="xl">
        <Stack>
          <Title order={3}>Sign in</Title>
          <Text c="dimmed">You need to authenticate to browse grants and backends.</Text>
          <Group>
            <Button onClick={() => window.location.assign('/oidc/login')}>Login with OIDC</Button>
          </Group>
          <Text size="xs" c="dimmed">
            In a local dev stack the portal often runs without OIDC and an empty user-token.
            If you see this screen, the operator has wired auth properly.
          </Text>
        </Stack>
      </Card>
    );
  }

  const mineList = mine.data ?? [];
  const pendingMine = mineList.filter((g) => g.status === 'PENDING' || g.status === 'VALIDATOR_APPROVED');
  const claimable = mineList.filter((g) => g.status === 'APPROVED');
  const activeMine = mineList.filter((g) => g.status === 'ACTIVE');

  return (
    <Stack gap="lg">
      <div>
        <Title order={2}>Welcome, {session.data.username}</Title>
        <Text c="dimmed" size="sm">
          {session.data.email ?? session.data.subject ?? session.data.username}
          {session.data.is_operator ? ' · admin' : ''}
        </Text>
      </div>

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing="md">
        <StatCard
          icon={<IconClockPause size={20} />}
          label="In flight"
          value={pendingMine.length}
          to="/grants?status=PENDING"
        />
        <StatCard
          icon={<IconShieldLock size={20} />}
          label="Ready to claim"
          value={claimable.length}
          to="/grants?status=APPROVED"
          tone="green"
        />
        <StatCard
          icon={<IconClockExclamation size={20} />}
          label="Active sessions"
          value={activeMine.length}
          to="/grants?status=ACTIVE"
          tone="blue"
        />
        <StatCard
          icon={<IconClockExclamation size={20} />}
          label="Awaiting my approval"
          value={queue.data?.length ?? 0}
          to="/grants?scope=validator"
          tone="orange"
        />
      </SimpleGrid>

      <Grid gutter="md">
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Card withBorder radius="md">
            <Group justify="space-between" mb="sm">
              <Title order={4}>Recent requests</Title>
              <Anchor component={Link} to="/grants" size="sm">
                View all <IconArrowRight size={14} style={{ verticalAlign: '-2px' }} />
              </Anchor>
            </Group>
            {mineList.length === 0 ? (
              <Text c="dimmed" size="sm">
                You haven't requested access yet.{' '}
                <Anchor component={Link} to="/grants/new">
                  Request access →
                </Anchor>
              </Text>
            ) : (
              <Stack gap="xs">
                {mineList.slice(0, 5).map((g) => {
                  const b = backendByID.get(g.backend_id);
                  return (
                    <Group key={g.id} justify="space-between" wrap="nowrap">
                      <Stack gap={0} style={{ minWidth: 0 }}>
                        <Anchor component={Link} to={`/grants/${g.id}`} size="sm" truncate>
                          {b ? <strong>{b.name}</strong> : <Text component="span" ff="monospace">{g.backend_id}</Text>}
                          {b && <Text component="span" c="dimmed"> ({b.type})</Text>}
                          {' · '}{g.role}{g.database ? `@${g.database}` : ''}
                        </Anchor>
                        <Text size="xs" c="dimmed">
                          requested {formatRelative(g.requested_at ?? g.created_at)}
                        </Text>
                      </Stack>
                      <GrantStatusPill status={g.status} />
                    </Group>
                  );
                })}
              </Stack>
            )}
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="sm">
              Backends
            </Title>
            {backends.isLoading ? (
              <Skeleton h={80} />
            ) : (backends.data?.length ?? 0) === 0 ? (
              <Text c="dimmed" size="sm">
                No backends registered yet.
              </Text>
            ) : (
              <Stack gap="xs">
                {backends.data?.slice(0, 6).map((b) => (
                  <Group key={b.id} justify="space-between" wrap="nowrap">
                    <Stack gap={0}>
                      <Text size="sm" fw={500}>
                        {b.name}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {b.type} · {b.host}:{b.port}
                      </Text>
                    </Stack>
                  </Group>
                ))}
              </Stack>
            )}
            <Anchor component={Link} to="/backends" size="sm" mt="sm">
              All backends →
            </Anchor>
          </Card>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}

function StatCard({
  icon,
  label,
  value,
  to,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  to: string;
  tone?: 'green' | 'orange' | 'blue';
}) {
  return (
    <Card component={Link} to={to} withBorder radius="md" p="md" style={{ textDecoration: 'none' }}>
      <Group justify="space-between" align="flex-start">
        <Stack gap={2}>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {label}
          </Text>
          <Title order={2} fw={600} c={tone}>
            {value}
          </Title>
        </Stack>
        <div style={{ color: tone ? `var(--mantine-color-${tone}-6)` : undefined }}>{icon}</div>
      </Group>
    </Card>
  );
}
