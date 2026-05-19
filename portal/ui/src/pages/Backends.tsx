// Backends list — read-only at this stage. Mutation surfaces (create
// backend, upsert account) live in the admin API and aren't wired here
// until a later phase.

import {
  Anchor,
  Badge,
  Card,
  Center,
  Group,
  Loader,
  ScrollArea,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { IconPlus } from '@tabler/icons-react';
import { Link } from 'react-router-dom';

import { useBackends } from '../api/hooks';

const TYPE_COLOR: Record<string, string> = {
  mysql: 'orange',
  postgres: 'indigo',
  mongo: 'green',
};

export function Backends() {
  const { data, isLoading, isError, error } = useBackends();

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Backends</Title>
          <Text c="dimmed" size="sm">
            Database instances the portal proxies front. Use{' '}
            <Anchor component={Link} to="/grants/new">
              Request access
            </Anchor>{' '}
            to ask for a session on one of these.
          </Text>
        </div>
      </Group>

      <Card withBorder radius="md" p={0}>
        {isLoading ? (
          <Center p="xl">
            <Loader size="sm" />
          </Center>
        ) : isError ? (
          <Center p="xl">
            <Text c="red">{(error as Error).message}</Text>
          </Center>
        ) : (data ?? []).length === 0 ? (
          <Center p="xl">
            <Stack align="center" gap="xs">
              <Text c="dimmed">No backends registered yet.</Text>
              <Text size="xs" c="dimmed">
                Admin: <code>POST /api/v1/backends</code> from <code>dev/seed.sh</code>.
              </Text>
              <Anchor component={Link} to="/grants/new">
                <IconPlus size={14} /> Try requesting once seeded
              </Anchor>
            </Stack>
          </Center>
        ) : (
          <ScrollArea>
            <Table verticalSpacing="sm" highlightOnHover withRowBorders={false} striped="even" miw={760}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Address</Table.Th>
                  <Table.Th>Databases</Table.Th>
                  <Table.Th>ID</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data!.map((b) => (
                  <Table.Tr key={b.id}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {b.name}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={TYPE_COLOR[b.type] ?? 'gray'} variant="light" size="sm">
                        {b.type}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace">
                        {b.host}:{b.port}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {b.databases?.length
                          ? b.databases.map((d) => (
                              <Badge key={d} variant="default" size="xs">
                                {d}
                              </Badge>
                            ))
                          : (
                            <Text size="xs" c="dimmed">
                              —
                            </Text>
                          )}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" ff="monospace" c="dimmed">
                        {b.id}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        )}
      </Card>
    </Stack>
  );
}
