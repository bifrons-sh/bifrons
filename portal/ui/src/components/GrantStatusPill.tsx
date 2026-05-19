import { Badge, type MantineColor } from '@mantine/core';

import type { GrantStatus } from '../api/types';

// Visual mapping for the seven Grant lifecycle states. Kept here so any view
// that renders a grant row uses the same colour vocabulary.
const TONE: Record<GrantStatus, MantineColor> = {
  PENDING: 'yellow',
  VALIDATOR_APPROVED: 'orange',
  APPROVED: 'cyan',
  ACTIVE: 'teal',
  DENIED: 'red',
  REVOKED: 'red',
  EXPIRED: 'gray',
};

const LABEL: Record<GrantStatus, string> = {
  PENDING: 'Pending',
  VALIDATOR_APPROVED: 'T1 approved',
  APPROVED: 'Approved',
  ACTIVE: 'Active',
  DENIED: 'Denied',
  REVOKED: 'Revoked',
  EXPIRED: 'Expired',
};

export function GrantStatusPill({ status, size = 'sm' }: { status: GrantStatus; size?: 'xs' | 'sm' | 'md' }) {
  return (
    <Badge color={TONE[status]} variant="light" size={size} radius="sm">
      {LABEL[status] ?? status}
    </Badge>
  );
}
