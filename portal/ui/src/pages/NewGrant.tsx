// Request-access form. Picks a backend (with cascading database list),
// role, optional reason. Admins can submit on behalf of another user.
// Submission lands the operator on the new grant's detail page so they can
// claim immediately when auto-approve is on or watch the gates otherwise.

import {
  Alert,
  Anchor,
  Button,
  Card,
  Divider,
  Group,
  Loader,
  Select,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconInfoCircle, IconSend } from '@tabler/icons-react';
import { useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useBackends, useCreateGrant, useSession, useUsers } from '../api/hooks';

interface FormValues {
  backend_id: string;
  database: string | null;
  role: string;
  reason: string;
  on_behalf_user_id: string;
  validation_window: string;
  claim_window: string;
  credential_ttl: string;
}

const ROLES = ['app', 'dba', 'readonly'];

export function NewGrant() {
  const session = useSession();
  const backends = useBackends();
  const users = useUsers();
  const create = useCreateGrant();
  const nav = useNavigate();
  const isOperator = !!session.data?.is_operator;

  const form = useForm<FormValues>({
    initialValues: {
      backend_id: '',
      database: null,
      role: 'app',
      reason: '',
      on_behalf_user_id: '',
      validation_window: '',
      claim_window: '',
      credential_ttl: '',
    },
    validate: {
      backend_id: (v) => (v ? null : 'Pick a backend.'),
      role: (v) => (v.trim() ? null : 'Role required.'),
      reason: (v) =>
        v.trim().length === 0 || v.trim().length >= 8
          ? null
          : 'Either leave empty or write at least 8 characters.',
    },
  });

  const selectedBackend = useMemo(
    () => backends.data?.find((b) => b.id === form.values.backend_id),
    [backends.data, form.values.backend_id],
  );

  const submit = form.onSubmit(async (values) => {
    if (!selectedBackend) return;
    try {
      const g = await create.mutateAsync({
        user_id: isOperator && values.on_behalf_user_id ? values.on_behalf_user_id : undefined,
        backend_addr: `${selectedBackend.host}:${selectedBackend.port}`,
        database: values.database ?? undefined,
        role: values.role.trim(),
        reason: values.reason.trim() || undefined,
        validation_window: values.validation_window || undefined,
        claim_window: values.claim_window || undefined,
        credential_ttl: values.credential_ttl || undefined,
      });
      notifications.show({
        color: 'green',
        title: 'Request submitted',
        message: `Grant ${g.id} created (status: ${g.status}).`,
      });
      nav(`/grants/${g.id}`);
    } catch (e) {
      notifications.show({ color: 'red', title: 'Request failed', message: (e as Error).message });
    }
  });

  if (session.isLoading || backends.isLoading) {
    return (
      <Group>
        <Loader />
      </Group>
    );
  }

  const backendOptions =
    backends.data?.map((b) => ({
      value: b.id,
      label: `${b.name} · ${b.type} · ${b.host}:${b.port}`,
    })) ?? [];

  const userOptions =
    users.data?.map((u) => ({
      value: u.id,
      label: `${u.username}${u.email ? ` · ${u.email}` : ''}`,
    })) ?? [];

  return (
    <Stack gap="md" maw={720}>
      <div>
        <Title order={2}>Request access</Title>
        <Text c="dimmed" size="sm">
          Submit a new grant request. Auto-approval, dual-gate validation, and ephemeral provisioning
          are all driven by the backend's configured policy.
        </Text>
      </div>

      <Card withBorder radius="md">
        <form onSubmit={submit}>
          <Stack gap="md">
            <Select
              required
              label="Backend"
              description="The DB instance you want to reach via the proxy."
              data={backendOptions}
              placeholder="Pick a backend"
              searchable
              {...form.getInputProps('backend_id')}
            />

            {/* Bottom-align the two inputs so descriptions of unequal length */}
            {/* don't push one Select higher than the other (alignment fix v0.2.1). */}
            <Group grow align="flex-end">
              <Select
                label="Database"
                description="Backend's registered databases — leave empty for any."
                data={selectedBackend?.databases?.map((d) => ({ value: d, label: d })) ?? []}
                placeholder={selectedBackend ? (selectedBackend.databases?.length ? 'Pick a database' : '—') : 'pick a backend first'}
                clearable
                disabled={!selectedBackend?.databases?.length}
                {...form.getInputProps('database')}
              />
              <Select
                required
                label="Role"
                description="Backend account the proxy impersonates."
                data={ROLES}
                {...form.getInputProps('role')}
                searchable
                allowDeselect={false}
              />
            </Group>

            <Textarea
              label="Reason"
              description="Optional — but recommended for any non-trivial request. Surfaces in the audit trail."
              autosize
              minRows={2}
              maxRows={6}
              placeholder="INC-1234 outage investigation, looking at the orders table"
              {...form.getInputProps('reason')}
            />

            {isOperator && (
              <>
                <Divider label="Admin overrides" labelPosition="left" />
                <Select
                  label="Request on behalf of"
                  description="Pick a user to submit this request as. Leaving empty creates the grant for yourself."
                  data={userOptions}
                  searchable
                  clearable
                  {...form.getInputProps('on_behalf_user_id')}
                />
                <Group grow>
                  <TextInput
                    label="Validation window"
                    description="e.g. 24h, 30m, 0 (default)"
                    placeholder="24h"
                    {...form.getInputProps('validation_window')}
                  />
                  <TextInput
                    label="Claim window"
                    description="e.g. 1h, 15m"
                    placeholder="1h"
                    {...form.getInputProps('claim_window')}
                  />
                  <TextInput
                    label="Credential TTL"
                    description="e.g. 1h, 8h"
                    placeholder="1h"
                    {...form.getInputProps('credential_ttl')}
                  />
                </Group>
              </>
            )}

            <Alert color="blue" icon={<IconInfoCircle size={16} />} variant="light">
              After approval (or if auto-approve is on), open the grant detail page and click{' '}
              <strong>Claim credentials</strong> to receive a one-shot portal password.
            </Alert>

            <Group justify="space-between">
              <Anchor component={Link} to="/grants" size="sm">
                Cancel
              </Anchor>
              <Button
                type="submit"
                leftSection={<IconSend size={16} />}
                loading={create.isPending}
                disabled={!form.isValid()}
              >
                Submit request
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>
    </Stack>
  );
}
