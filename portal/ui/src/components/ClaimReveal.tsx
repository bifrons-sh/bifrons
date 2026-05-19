// Modal that surfaces a freshly-claimed grant's one-shot credentials
// alongside ready-to-paste connection strings per engine. The values are
// blurred until the operator clicks reveal — this is a kiosk-friendly
// safeguard against shoulder-surfing.

import { Alert, Button, Code, Group, Modal, Stack, Tabs, Text } from '@mantine/core';
import { IconEye, IconEyeOff, IconInfoCircle } from '@tabler/icons-react';
import { useState } from 'react';

import type { Backend, ClaimResponse } from '../api/types';
import { CopyableCode } from './CopyableCode';

interface Props {
  opened: boolean;
  onClose: () => void;
  claim: ClaimResponse | null;
  backend: Backend | undefined;
  username: string;
  proxyHostHint?: string; // override "127.0.0.1" when known
}

const DEFAULT_PROXY_PORTS: Record<string, number> = {
  mysql: 13306,
  postgres: 15432,
  mongo: 37017,
};

export function ClaimReveal({ opened, onClose, claim, backend, username, proxyHostHint }: Props) {
  const [revealed, setRevealed] = useState(false);
  // Default to the host the SPA was served from — the proxies are co-located
  // with the portal in every deployment we ship, so the user's current origin
  // is the safest hint. Was hardcoded to 127.0.0.1 which lied on jump hosts.
  const host = proxyHostHint
    ?? (typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1');
  const port = backend && DEFAULT_PROXY_PORTS[backend.type];

  if (!claim) return null;

  const shown = revealed ? claim.portal_password : '•'.repeat(Math.min(claim.portal_password.length, 64));

  return (
    <Modal
      opened={opened}
      onClose={() => {
        setRevealed(false);
        onClose();
      }}
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
