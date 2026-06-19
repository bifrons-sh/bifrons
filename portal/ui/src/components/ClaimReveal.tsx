// Modal that surfaces a freshly-claimed grant's one-shot credentials
// alongside ready-to-paste connection strings per engine. The values are
// blurred until the operator clicks reveal — this is a kiosk-friendly
// safeguard against shoulder-surfing.

import { Alert, Button, Center, Code, Group, Loader, Modal, Stack, Tabs, Text } from '@mantine/core';
import { IconAlertTriangle, IconEye, IconEyeOff, IconInfoCircle } from '@tabler/icons-react';
import { useState } from 'react';

import type { Backend, ClaimResponse } from '../api/types';
import { CopyableCode } from './CopyableCode';

// Where the claim is in its async lifecycle. `waiting` covers both the
// pending POST and the in-flight poll; `failed` and `timeout` are terminal
// non-success states the modal renders instead of credentials.
export type ClaimPhase = 'waiting' | 'done' | 'failed' | 'timeout';

interface Props {
  opened: boolean;
  onClose: () => void;
  phase: ClaimPhase;
  claim: ClaimResponse | null;
  // Populated only when phase === 'failed'.
  failure?: { error_class: string; error_detail: string } | null;
  backend: Backend | undefined;
  username: string;
  proxyHostHint?: string; // override "127.0.0.1" when known
}

const DEFAULT_PROXY_PORTS: Record<string, number> = {
  mysql: 13306,
  postgres: 15432,
  mongo: 37017,
};

// Cap the masked-password placeholder length: showing one dot per real char
// would leak the exact secret length on long credentials, so clamp the dots.
const MAX_MASK_DOTS = 64;

export function ClaimReveal({
  opened,
  onClose,
  phase,
  claim,
  failure,
  backend,
  username,
  proxyHostHint,
}: Props) {
  const [revealed, setRevealed] = useState(false);
  // Default to the host the SPA was served from — the proxies are co-located
  // with the portal in every deployment we ship, so the user's current origin
  // is the safest hint. Was hardcoded to 127.0.0.1 which lied on jump hosts.
  const host = proxyHostHint
    ?? (typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1');
  const port = backend && DEFAULT_PROXY_PORTS[backend.type];

  const close = () => {
    setRevealed(false);
    onClose();
  };

  // Provisioning is async: render a spinner / failure / timeout panel until the
  // worker either issues creds or terminally fails. Escape stays disabled in
  // the done state (kiosk shoulder-surf guard) but is allowed while waiting so
  // a stuck claim doesn't trap the operator.
  if (phase !== 'done') {
    const titles: Record<Exclude<ClaimPhase, 'done'>, string> = {
      waiting: 'Provisioning credentials',
      failed: 'Provisioning failed',
      timeout: 'Provisioner not responding',
    };
    return (
      <Modal opened={opened} onClose={close} title={titles[phase]} size="md">
        <Stack gap="md">
          {phase === 'waiting' && (
            <Center mih={120}>
              <Stack align="center" gap="sm">
                <Loader />
                <Text size="sm" c="dimmed">
                  Waiting for the provisioner…
                </Text>
              </Stack>
            </Center>
          )}
          {phase === 'failed' && (
            <Alert color="red" icon={<IconAlertTriangle size={16} />} variant="light">
              <Text fw={600} size="sm">
                {failure?.error_class ?? 'error'}
              </Text>
              <Text size="sm">{failure?.error_detail ?? 'Provisioning failed.'}</Text>
            </Alert>
          )}
          {phase === 'timeout' && (
            <Alert color="yellow" icon={<IconAlertTriangle size={16} />} variant="light">
              The provisioner is taking longer than expected or is unreachable. The grant may
              still settle — re-claim in a moment, and if it keeps failing, contact an operator.
            </Alert>
          )}
          <Group justify="flex-end">
            <Button onClick={close} variant="default">
              {phase === 'waiting' ? 'Cancel' : 'Close'}
            </Button>
          </Group>
        </Stack>
      </Modal>
    );
  }

  // phase === 'done' from here: creds are guaranteed present.
  if (!claim) return null;

  const shown = revealed
    ? claim.portal_password
    : '•'.repeat(Math.min(claim.portal_password.length, MAX_MASK_DOTS));

  return (
    <Modal
      opened={opened}
      onClose={close}
      title="Credentials issued"
      size="xl"
      closeOnEscape={false}
    >
      <Stack gap="md">
        <Alert color="yellow" icon={<IconInfoCircle size={16} />} variant="light">
          One-shot value. The portal stores a hash but not the plaintext after this point —
          if you lose it, ask an admin to re-claim before the window expires
          (<strong>{claim.expires_at}</strong>).
        </Alert>

        <Group justify="space-between" align="flex-end">
          <div>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              Portal password
            </Text>
            <Text size="sm" c="dimmed">
              Present this to the proxy as <Code>{username}</Code>'s password.
            </Text>
          </div>
          <Button
            variant="default"
            size="xs"
            leftSection={revealed ? <IconEyeOff size={14} /> : <IconEye size={14} />}
            onClick={() => setRevealed((v) => !v)}
          >
            {revealed ? 'Hide' : 'Reveal'}
          </Button>
        </Group>
        <CopyableCode value={claim.portal_password} display={shown} block />

        {backend && port && (
          <Tabs defaultValue="cli">
            <Tabs.List>
              <Tabs.Tab value="cli">CLI</Tabs.Tab>
              <Tabs.Tab value="uri">URI</Tabs.Tab>
              <Tabs.Tab value="env">Env</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="cli" pt="sm">
              <CopyableCode value={cliCommand(backend.type, username, claim.portal_password, host, port, backend.databases?.[0])} block />
            </Tabs.Panel>
            <Tabs.Panel value="uri" pt="sm">
              <CopyableCode value={uriString(backend.type, username, claim.portal_password, host, port, backend.databases?.[0])} block />
            </Tabs.Panel>
            <Tabs.Panel value="env" pt="sm">
              <CopyableCode
                value={envBlock(backend.type, username, claim.portal_password, host, port, backend.databases?.[0])}
                block
              />
            </Tabs.Panel>
          </Tabs>
        )}

        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Done
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function cliCommand(
  type: string,
  user: string,
  pass: string,
  host: string,
  port: number,
  db?: string,
): string {
  const q = (s: string): string => `'${s.replace(/'/g, "'\\''")}'`;
  switch (type) {
    case 'mysql':
      return `mysql -h ${host} -P ${port} -u ${user} -p${q(pass)} ${db ?? ''}`.trim();
    case 'postgres':
      return `PGPASSWORD=${q(pass)} psql -h ${host} -p ${port} -U ${user} ${db ?? ''}`.trim();
    case 'mongo':
      return `mongosh "mongodb://${user}:${encodeURIComponent(pass)}@${host}:${port}/${db ?? 'admin'}?authSource=${db ?? 'admin'}&directConnection=true"`;
    default:
      return `# unknown engine type=${type}`;
  }
}

function uriString(type: string, user: string, pass: string, host: string, port: number, db?: string): string {
  const p = encodeURIComponent(pass);
  switch (type) {
    case 'mysql':
      return `mysql://${user}:${p}@${host}:${port}/${db ?? ''}`;
    case 'postgres':
      return `postgres://${user}:${p}@${host}:${port}/${db ?? ''}`;
    case 'mongo':
      return `mongodb://${user}:${p}@${host}:${port}/${db ?? 'admin'}?authSource=${db ?? 'admin'}&directConnection=true`;
    default:
      return `unknown://${user}:${p}@${host}:${port}`;
  }
}

function envBlock(type: string, user: string, pass: string, host: string, port: number, db?: string): string {
  const lines = [`DB_HOST=${host}`, `DB_PORT=${port}`, `DB_USER=${user}`, `DB_PASSWORD=${pass}`];
  if (db) lines.push(`DB_NAME=${db}`);
  lines.push(`DB_TYPE=${type}`);
  return lines.join('\n');
}
