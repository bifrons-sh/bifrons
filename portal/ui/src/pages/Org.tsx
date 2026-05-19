// Org hierarchy: users ↔ validators + groups ↔ members.
// Admin actions use Mantine modals + searchable Select pickers — no more
// window.prompt with paste-the-username UX.

import {
  ActionIcon,
  Anchor,
  Badge,
  Button,
  Card,
  Center,
  Collapse,
  Group,
  Loader,
  Menu,
  Modal,
  ScrollArea,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import {
  IconChevronDown,
  IconChevronRight,
  IconDots,
  IconPlus,
  IconTrash,
  IconUserCheck,
  IconUserMinus,
  IconUserOff,
  IconX,
} from '@tabler/icons-react';
import { useState } from 'react';

import {
  useAddGroupMember,
  useClearUserValidator,
  useDeleteGroup,
  useGroupMembers,
  useGroups,
  useRemoveGroupMember,
  useSession,
  useSetUserValidator,
  useUpsertGroup,
  useUsers,
} from '../api/hooks';
import type { Group as OrgGroup, User } from '../api/types';

export function Org() {
  const session = useSession();
  const isOperator = !!session.data?.is_operator;
  const users = useUsers();
  const groups = useGroups();

  return (
    <Stack gap="md">
      <div>
        <Title order={2}>Org</Title>
        <Text c="dimmed" size="sm">
          Validators bind a user to their natural T1 approver. Groups feed the
          per-backend T2 (admin) tier. Populated by <code>entra-sync</code>;
          spot-edit here when the sync is paused or for bootstrap.
        </Text>
      </div>

      {users.isLoading || groups.isLoading ? (
        <Center p="xl">
          <Loader />
        </Center>
      ) : (
        <>
          <UsersPanel users={users.data ?? []} isOperator={isOperator} />
          <GroupsPanel groups={groups.data ?? []} users={users.data ?? []} isOperator={isOperator} />
        </>
      )}
    </Stack>
  );
}

// ----- users ---------------------------------------------------------------

function UsersPanel({ users, isOperator }: { users: User[]; isOperator: boolean }) {
  const [editing, setEditing] = useState<User | null>(null);
  return (
    <Card withBorder radius="md" p={0}>
      <Group justify="space-between" p="md" pb={0}>
        <Title order={4}>Users</Title>
        <Badge variant="default" size="sm">
          {users.length}
        </Badge>
      </Group>
      <ScrollArea>
        <Table verticalSpacing="sm" highlightOnHover withRowBorders={false} striped="even" miw={720}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Username</Table.Th>
              <Table.Th>Display name</Table.Th>
              <Table.Th>Email</Table.Th>
              {isOperator && <Table.Th>Validator</Table.Th>}
              {isOperator && <Table.Th>{/* actions */}</Table.Th>}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => {
              const validator = users.find((v) => v.id === u.validator_user_id);
              return (
                <Table.Tr key={u.id}>
                  <Table.Td>
                    <Group gap="xs">
                      <Text size="sm" fw={500}>
                        {u.username}
                      </Text>
                      {u.is_operator && (
                        <Badge color="indigo" variant="light" size="xs">
                          admin
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {u.display_name || '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{u.email || <Text component="span" c="dimmed">—</Text>}</Text>
                  </Table.Td>
                  {isOperator && (
                    <Table.Td>
                      {validator ? (
                        <Group gap={4}>
                          <IconUserCheck size={14} color="var(--mantine-color-teal-6)" />
                          <Text size="sm">{validator.username}</Text>
                        </Group>
                      ) : (
                        <Group gap={4} c="dimmed">
                          <IconUserOff size={14} />
                          <Text size="sm">unassigned</Text>
                        </Group>
                      )}
                    </Table.Td>
                  )}
                  {isOperator && (
                    <Table.Td>
                      <Button size="xs" variant="default" onClick={() => setEditing(u)}>
                        Edit validator
                      </Button>
                    </Table.Td>
                  )}
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </ScrollArea>
      {editing && (
        <ValidatorEditor user={editing} users={users} onClose={() => setEditing(null)} />
      )}
    </Card>
  );
}

function ValidatorEditor({
  user,
  users,
  onClose,
}: {
  user: User;
  users: User[];
  onClose: () => void;
}) {
  const setMut = useSetUserValidator();
  const clearMut = useClearUserValidator();
  const [pick, setPick] = useState<string | null>(user.validator_user_id ?? null);

  const options = users
    .filter((u) => u.id !== user.id)
    .map((u) => ({ value: u.id, label: `${u.username}${u.email ? ` · ${u.email}` : ''}` }));

  const save = async () => {
    if (!pick) return;
    try {
      await setMut.mutateAsync({ userID: user.id, validatorUserID: pick });
      notifications.show({ color: 'green', title: 'Validator set', message: `${user.username} → ${pick}` });
      onClose();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed', message: (e as Error).message });
    }
  };
  const clear = async () => {
    try {
      await clearMut.mutateAsync(user.id);
      notifications.show({ color: 'orange', title: 'Validator cleared', message: user.username });
      onClose();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed', message: (e as Error).message });
    }
  };

  return (
    <Modal opened onClose={onClose} title={`Validator for ${user.username}`} size="md">
      <Stack>
        <Select
          label="Pick a validator"
          searchable
          placeholder="Start typing a username or email"
          data={options}
          value={pick}
          onChange={setPick}
        />
        <Group justify="space-between">
          <Button
            variant="light"
            color="red"
            leftSection={<IconUserMinus size={14} />}
            disabled={!user.validator_user_id}
            loading={clearMut.isPending}
            onClick={clear}
          >
            Clear validator
          </Button>
          <Group gap="xs">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={save} disabled={!pick} loading={setMut.isPending}>
              Save
            </Button>
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}

// ----- groups --------------------------------------------------------------

function GroupsPanel({
  groups,
  users,
  isOperator,
}: {
  groups: OrgGroup[];
  users: User[];
  isOperator: boolean;
}) {
  const upsert = useUpsertGroup();
  const del = useDeleteGroup();
  const [createOpen, createCtl] = useDisclosure(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const submitGroup = async (slug: string, displayName: string) => {
    try {
      await upsert.mutateAsync({ slug: slug.trim(), display_name: displayName.trim() || undefined });
      notifications.show({ color: 'green', title: 'Group saved', message: slug });
      createCtl.close();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Group save failed', message: (e as Error).message });
    }
  };

  const deleteGroup = async (g: OrgGroup) => {
    if (!confirm(`Delete group "${g.slug}"? Memberships in this group are dropped; user rows remain.`))
      return;
    try {
      await del.mutateAsync(g.id);
      notifications.show({ color: 'orange', title: 'Group deleted', message: g.slug });
    } catch (e) {
      notifications.show({ color: 'red', title: 'Delete failed', message: (e as Error).message });
    }
  };

  return (
    <Card withBorder radius="md" p={0}>
      <Group justify="space-between" p="md" pb={0}>
        <Group gap="xs">
          <Title order={4}>Groups</Title>
          <Badge variant="default" size="sm">
            {groups.length}
          </Badge>
        </Group>
        {isOperator && (
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={createCtl.open}>
            New group
          </Button>
        )}
      </Group>
      <ScrollArea>
        <Table verticalSpacing="sm" highlightOnHover withRowBorders={false} striped="even" miw={680}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={32} />
              <Table.Th>Slug</Table.Th>
              <Table.Th>Display name</Table.Th>
              <Table.Th>External ID</Table.Th>
              {isOperator && <Table.Th>{/* actions */}</Table.Th>}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {groups.map((g) => (
              <GroupRow
                key={g.id}
                g={g}
                users={users}
                isOperator={isOperator}
                expanded={expanded === g.id}
                onToggle={() => setExpanded((x) => (x === g.id ? null : g.id))}
                onDelete={() => deleteGroup(g)}
              />
            ))}
          </Table.Tbody>
        </Table>
      </ScrollArea>
      {createOpen && <GroupCreator onClose={createCtl.close} onSubmit={submitGroup} pending={upsert.isPending} />}
    </Card>
  );
}

function GroupRow({
  g,
  users,
  isOperator,
  expanded,
  onToggle,
  onDelete,
}: {
  g: OrgGroup;
  users: User[];
  isOperator: boolean;
  expanded: boolean;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const members = useGroupMembers(expanded ? g.id : undefined);
  const addMut = useAddGroupMember();
  const removeMut = useRemoveGroupMember();
  const [addOpen, addCtl] = useDisclosure(false);
  return (
    <>
      <Table.Tr>
        <Table.Td>
          <ActionIcon variant="subtle" onClick={onToggle} aria-label="expand">
            {expanded ? <IconChevronDown size={16} /> : <IconChevronRight size={16} />}
          </ActionIcon>
        </Table.Td>
        <Table.Td>
          <Anchor onClick={onToggle} component="button" type="button" size="sm" ff="monospace">
            {g.slug}
          </Anchor>
        </Table.Td>
        <Table.Td>
          <Text size="sm">{g.display_name || <Text component="span" c="dimmed">—</Text>}</Text>
        </Table.Td>
        <Table.Td>
          <Text size="xs" c="dimmed" ff="monospace">
            {g.external_id || '—'}
          </Text>
        </Table.Td>
        {isOperator && (
          <Table.Td>
            <Menu position="bottom-end">
              <Menu.Target>
                <ActionIcon variant="subtle" aria-label="actions">
                  <IconDots size={16} />
                </ActionIcon>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Item leftSection={<IconPlus size={14} />} onClick={addCtl.open}>
                  Add member
                </Menu.Item>
                <Menu.Divider />
                <Menu.Item color="red" leftSection={<IconTrash size={14} />} onClick={onDelete}>
                  Delete group
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Table.Td>
        )}
      </Table.Tr>
      <Table.Tr>
        <Table.Td colSpan={isOperator ? 5 : 4} p={0} style={{ border: 0 }}>
          <Collapse in={expanded}>
            <div style={{ padding: 'var(--mantine-spacing-md)', background: 'var(--mantine-color-default-hover)' }}>
              {members.isLoading ? (
                <Loader size="xs" />
              ) : members.isError ? (
                <Text c="red" size="sm">
                  {(members.error as Error).message}
                </Text>
              ) : (members.data ?? []).length === 0 ? (
                <Text size="sm" c="dimmed">
                  No members yet.
                </Text>
              ) : (
                <Group gap="xs" wrap="wrap">
                  {members.data!.map((m) => {
                    // Per-row in-flight guard: react-query's mutation.isPending
                    // is global to the mutation, so we also key on the target
                    // (groupID, userID) to avoid disabling unrelated chips.
                    const inFlight =
                      removeMut.isPending &&
                      removeMut.variables?.groupID === g.id &&
                      removeMut.variables?.userID === m.id;
                    return (
                      <Badge
                        key={m.id}
                        variant="light"
                        size="lg"
                        rightSection={
                          isOperator ? (
                            <Tooltip label="Remove from group">
                              <ActionIcon
                                size="xs"
                                variant="transparent"
                                aria-label="remove"
                                disabled={inFlight}
                                onClick={() =>
                                  removeMut.mutate({ groupID: g.id, userID: m.id })
                                }
                              >
                                <IconX size={12} />
                              </ActionIcon>
                            </Tooltip>
                          ) : undefined
                        }
                      >
                        {m.username}
                      </Badge>
                    );
                  })}
                </Group>
              )}
            </div>
          </Collapse>
        </Table.Td>
      </Table.Tr>
      {addOpen && (
        <AddMemberDialog
          group={g}
          users={users}
          existing={members.data ?? []}
          onClose={addCtl.close}
          onAdd={(userID) => addMut.mutateAsync({ groupID: g.id, userID })}
          pending={addMut.isPending}
        />
      )}
    </>
  );
}

function GroupCreator({
  onClose,
  onSubmit,
  pending,
}: {
  onClose: () => void;
  onSubmit: (slug: string, displayName: string) => Promise<void>;
  pending: boolean;
}) {
  const [slug, setSlug] = useState('');
  const [displayName, setDisplayName] = useState('');
  return (
    <Modal opened onClose={onClose} title="New group" size="sm">
      <Stack>
        <TextInput
          required
          label="Slug"
          description="Stable identifier; used as the join key for T2 group lookups."
          placeholder="dba-prod"
          value={slug}
          onChange={(e) => setSlug(e.currentTarget.value)}
        />
        <TextInput
          label="Display name"
          placeholder="Production DBA team"
          value={displayName}
          onChange={(e) => setDisplayName(e.currentTarget.value)}
        />
        <Group justify="flex-end" gap="xs">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={!slug.trim()} loading={pending} onClick={() => onSubmit(slug, displayName)}>
            Create / upsert
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function AddMemberDialog({
  group,
  users,
  existing,
  onClose,
  onAdd,
  pending,
}: {
  group: OrgGroup;
  users: User[];
  existing: User[];
  onClose: () => void;
  onAdd: (userID: string) => Promise<void>;
  pending: boolean;
}) {
  const existingIDs = new Set(existing.map((u) => u.id));
  const options = users
    .filter((u) => !existingIDs.has(u.id))
    .map((u) => ({ value: u.id, label: `${u.username}${u.email ? ` · ${u.email}` : ''}` }));
  const [pick, setPick] = useState<string | null>(null);
  return (
    <Modal opened onClose={onClose} title={`Add member to ${group.slug}`} size="md">
      <Stack>
        <Select
          label="User"
          searchable
          placeholder={options.length ? 'Pick a user' : 'every user is already a member'}
          data={options}
          value={pick}
          onChange={setPick}
          disabled={options.length === 0}
        />
        <Group justify="flex-end" gap="xs">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!pick}
            loading={pending}
            onClick={async () => {
              if (!pick) return;
              try {
                await onAdd(pick);
                notifications.show({ color: 'green', title: 'Member added', message: pick });
                onClose();
              } catch (e) {
                notifications.show({ color: 'red', title: 'Add failed', message: (e as Error).message });
              }
            }}
          >
            Add
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
