// Single grant view: header (id+status), metadata card, lifecycle timeline,
// action buttons (approve/deny/claim) appropriate to the current state and
// caller permissions. Replaces v0.1's "no way to act on a grant" gap.

import {
  Anchor,
  Badge,
  Breadcrumbs,
  Button,
  Card,
  Center,
  Checkbox,
  Code,
  Divider,
  Grid,
  Group,
  Loader,
  Modal,
  SimpleGrid,
  Stack,
  Text,
  Textarea,
  Title,
  Tooltip,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import {
  IconArrowBack,
  IconCheck,
  IconKey,
  IconShieldCheck,
  IconShieldX,
} from '@tabler/icons-react';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import {
  useApproveGrant,
  useBackends,
  useClaimGrant,
  useDenyGrant,
  useGrant,
  useSession,
  useUsers,
  useUserValidator,
} from '../api/hooks';
import type { Backend, ClaimResponse, Grant } from '../api/types';
import { ClaimReveal } from '../components/ClaimReveal';
import { CopyableCode } from '../components/CopyableCode';
import { GrantStatusPill } from '../components/GrantStatusPill';
import { GrantTimeline } from '../components/GrantTimeline';

export function GrantDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const session = useSession();
  const grant = useGrant(id);
  const backends = useBackends();
  const users = useUsers();
  // Dedicated lookup for the requester's validator — `users` strips
  // validator_user_id for non-admin callers, so the gate can't lean on it.
  // The /validator endpoint exposes the validator's id to any authenticated
  // caller and is what powers the "can david approve?" decision.
  const requesterValidator = useUserValidator(grant.data?.user_id);

  const [reveal, revealCtl] = useDisclosure(false);
  const [lastClaim, setLastClaim] = useState<ClaimResponse | null>(null);

  const approve = useApproveGrant();
  const deny = useDenyGrant();
  const claim = useClaimGrant();

  const [denyOpen, denyCtl] = useDisclosure(false);
  const [approveOpen, approveCtl] = useDisclosure(false);
  const [onBehalf, setOnBehalf] = useState(false);
  const [onBehalfReason, setOnBehalfReason] = useState('');

  if (grant.isLoading || session.isLoading) {
    return (
      <Center mih="40vh">
        <Loader />
      </Center>
    );
  }
  if (grant.isError || !grant.data) {
    return (
      <Stack align="center" gap="xs" mt="xl">
        <Title order={3}>Grant not found</Title>
        <Text c="dimmed">{(grant.error as Error | null)?.message ?? 'No such grant id.'}</Text>
        <Anchor component={Link} to="/grants">
          Back to grants →
        </Anchor>
      </Stack>
    );
  }

  const g = grant.data;
  const isOperator = !!session.data?.is_operator;
  const sessionUserID = session.data?.user_id;
  const isOwner = !!sessionUserID && sessionUserID === g.user_id;
  const backend = backends.data?.find((b) => b.id === g.backend_id);
  const requester = users.data?.find((u) => u.id === g.user_id);
  // The T1 (validator) gate is cleared by the requester's natural validator.
  // Pure UI gate — the backend re-checks authz on /approve, so a wrong client
  // verdict can't escalate; this just decides whether to render the buttons.
  const isValidatorOfRequester =
    !!sessionUserID && requesterValidator.data?.validator?.id === sessionUserID;

  const canApprove =
    (isOperator || isValidatorOfRequester) &&
    (g.status === 'PENDING' || g.status === 'VALIDATOR_APPROVED');
  const canDeny =
    (isOperator || isValidatorOfRequester) &&
    (g.status === 'PENDING' || g.status === 'VALIDATOR_APPROVED' || g.status === 'APPROVED');
  const canClaim = (isOwner || isOperator) && g.status === 'APPROVED';
  const reclaimable = (isOwner || isOperator) && g.status === 'ACTIVE';

  const doApprove = async () => {
    try {
      await approve.mutateAsync({
        id: g.id,
        body: onBehalf ? { on_behalf_of_t1: true, reason: onBehalfReason } : undefined,
      });
      notifications.show({ color: 'green', title: 'Approved', message: `Grant ${g.id} moved forward.` });
      approveCtl.close();
      setOnBehalf(false);
      setOnBehalfReason('');
    } catch (e) {
      notifications.show({ color: 'red', title: 'Approve failed', message: (e as Error).message });
    }
  };

  const doDeny = async () => {
    try {
      await deny.mutateAsync(g.id);
      notifications.show({ color: 'orange', title: 'Denied', message: `Grant ${g.id} denied.` });
      denyCtl.close();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Deny failed', message: (e as Error).message });
    }
  };

  const doClaim = async () => {
    try {
      const res = await claim.mutateAsync(g.id);
      setLastClaim(res);
      revealCtl.open();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Claim failed', message: (e as Error).message });
    }
  };

  return (
    <Stack gap="md">
      <Breadcrumbs>
        <Anchor component={Link} to="/grants">
          Grants
        </Anchor>
        <Text size="sm" ff="monospace">{g.id}</Text>
      </Breadcrumbs>

      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Stack gap={4}>
          <Group gap="xs" align="center">
            <Title order={2}>
              {g.role}
              {g.database ? <Text component="span" c="dimmed" inherit> · {g.database}</Text> : null}
            </Title>
            <GrantStatusPill status={g.status} size="md" />
            {g.policy_mode && (
              <Badge variant="light" color="gray" size="sm">
                {g.policy_mode}
              </Badge>
            )}
          </Group>
          <Text c="dimmed" ff="monospace" size="sm">
            {g.id}
          </Text>
        </Stack>
        <Group gap="xs">
          <Button
            variant="default"
            leftSection={<IconArrowBack size={16} />}
            size="sm"
            onClick={() => nav(-1)}
          >
            Back
          </Button>
          {canApprove && (
            <Button leftSection={<IconShieldCheck size={16} />} onClick={approveCtl.open} color="indigo">
              Approve
            </Button>
          )}
          {canDeny && (
            <Button leftSection={<IconShieldX size={16} />} onClick={denyCtl.open} color="red" variant="light">
              Deny
            </Button>
          )}
          {canClaim && (
            <Button leftSection={<IconKey size={16} />} onClick={doClaim} loading={claim.isPending} color="teal">
              Claim credentials
            </Button>
          )}
          {reclaimable && (
            <Tooltip label="Re-fetch the active credentials">
              <Button
                leftSection={<IconKey size={16} />}
                onClick={doClaim}
                variant="light"
                color="teal"
                loading={claim.isPending}
              >
                Show credentials
              </Button>
            </Tooltip>
          )}
        </Group>
      </Group>

      <Grid gutter="md">
        <Grid.Col span={{ base: 12, md: 7 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="sm">
              Request
            </Title>
            <SimpleGrid cols={2} spacing="xs">
              <Field k="Requester" v={requester ? `${requester.username}${requester.email ? ` · ${requester.email}` : ''}` : g.user_id} mono={!requester} />
              <Field k="Backend" v={backend ? `${backend.name} (${backend.type})` : g.backend_id} />
              {backend && <Field k="Backend address" v={`${backend.host}:${backend.port}`} mono />}
              <Field k="Role" v={g.role} />
              <Field k="Database" v={g.database ?? '—'} />
              <Field k="Reason" v={g.reason ?? '—'} />
              <Field k="Requested by" v={g.requested_by ?? '—'} mono />
              {g.approver_hint && <Field k="Notified approver" v={g.approver_hint} />}
              {g.t1_on_behalf_reason && (
                <Field k="On-behalf reason" v={g.t1_on_behalf_reason} />
              )}
            </SimpleGrid>
            <Divider my="md" />
            <Title order={5} mb="sm">
              Deadlines
            </Title>
            <SimpleGrid cols={3} spacing="xs">
              <DeadlineField k="Validation window" v={g.request_expires_at} />
              <DeadlineField k="Claim window" v={g.claim_expires_at} />
              <DeadlineField k="Credential TTL" v={g.expires_at} />
            </SimpleGrid>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Card withBorder radius="md">
            <Title order={4} mb="sm">
              Lifecycle
            </Title>
            <GrantTimeline g={g} />
          </Card>
        </Grid.Col>
      </Grid>

      {/* Approve dialog with on-behalf-of-T1 override toggle */}
      <Modal opened={approveOpen} onClose={approveCtl.close} title="Approve grant" size="md">
        <Stack>
          <Text size="sm">
            You're approving <Code>{g.id}</Code> for{' '}
            <strong>{requester?.username ?? g.user_id}</strong> on{' '}
            <strong>{backend?.name ?? g.backend_id}</strong>.
          </Text>
          {g.status === 'PENDING' && (
            <Checkbox
              label="I'm clearing the T1 (validator) gate on behalf of the natural validator"
              checked={onBehalf}
              onChange={(e) => setOnBehalf(e.currentTarget.checked)}
            />
          )}
          {onBehalf && (
            <Textarea
              label="Reason (≥20 chars)"
              description="Documented in the audit trail. Examples: 'INC-1234 outage, Bob on PTO'."
              autosize
              minRows={2}
              value={onBehalfReason}
              onChange={(e) => setOnBehalfReason(e.currentTarget.value)}
              error={onBehalf && onBehalfReason.trim().length < 20 ? 'At least 20 characters required.' : undefined}
            />
          )}
          <Group justify="flex-end" gap="xs">
            <Button variant="default" onClick={approveCtl.close}>
              Cancel
            </Button>
            <Button
              onClick={doApprove}
              loading={approve.isPending}
              disabled={onBehalf && onBehalfReason.trim().length < 20}
              leftSection={<IconCheck size={16} />}
            >
              Confirm
            </Button>
          </Group>
        </Stack>
      </Modal>

      {/* Deny dialog */}
      <Modal opened={denyOpen} onClose={denyCtl.close} title="Deny grant" size="sm">
        <Stack>
          <Text size="sm">
            Deny <Code>{g.id}</Code>? The requester will be notified.
          </Text>
          <Group justify="flex-end" gap="xs">
            <Button variant="default" onClick={denyCtl.close}>
              Cancel
            </Button>
            <Button onClick={doDeny} loading={deny.isPending} color="red">
              Confirm deny
            </Button>
          </Group>
        </Stack>
      </Modal>

      <ClaimReveal
        opened={reveal}
        onClose={revealCtl.close}
        claim={lastClaim}
        backend={backend as Backend | undefined}
        username={requester?.username ?? g.user_id}
      />
    </Stack>
  );
}

function Field({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <Stack gap={0}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {k}
      </Text>
      <Text size="sm" ff={mono ? 'monospace' : undefined}>
        {v}
      </Text>
    </Stack>
  );
}

function DeadlineField({ k, v }: { k: string; v?: string | null }) {
  return (
    <Stack gap={0}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {k}
      </Text>
      <Tooltip label={v ?? '—'} disabled={!v}>
        <Text size="sm">{v ? <CopyableCode value={v} display={v.replace('T', ' ').slice(0, 19)} monospace /> : '—'}</Text>
      </Tooltip>
    </Stack>
  );
}

// suppress unused import warning when Grant is consumed only via prop types
export type { Grant };
