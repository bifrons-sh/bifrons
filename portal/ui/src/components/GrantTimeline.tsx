// Visual timeline of a grant's tri-phase lifecycle. Each step lights up when
// the corresponding timestamp is set on the grant. The implementation is
// data-driven so the same component renders for auto-approved (dual_or,
// validator_only) and dual_strict workflows without branching.

import { Text, Timeline } from '@mantine/core';
import {
  IconCheck,
  IconClockExclamation,
  IconHourglassHigh,
  IconShieldCheck,
  IconShieldX,
  IconUser,
} from '@tabler/icons-react';

import type { Grant } from '../api/types';
import { formatAbsolute, formatRelative } from '../util/time';

interface Step {
  title: string;
  when: string | null | undefined;
  who?: string;
  icon: React.ReactNode;
  done: boolean;
  tone?: 'red';
}

export function GrantTimeline({ g }: { g: Grant }) {
  const steps = buildSteps(g);
  const activeIdx = steps.reduce((acc, s, i) => (s.done ? i : acc), -1);

  return (
    <Timeline active={activeIdx} bulletSize={26} lineWidth={2}>
      {steps.map((s, i) => (
        <Timeline.Item
          key={i}
          bullet={s.icon}
          title={s.title}
          color={s.tone === 'red' ? 'red' : s.done ? 'indigo' : 'gray'}
        >
          {s.who && (
            <Text size="xs" c="dimmed">
              by <Text component="span" ff="monospace">{s.who}</Text>
            </Text>
          )}
          {s.when ? (
            <Text size="xs" c="dimmed" title={formatAbsolute(s.when)}>
              {formatRelative(s.when)} · {formatAbsolute(s.when)}
            </Text>
          ) : (
            <Text size="xs" c="dimmed">
              —
            </Text>
          )}
        </Timeline.Item>
      ))}
    </Timeline>
  );
}

function buildSteps(g: Grant): Step[] {
  const steps: Step[] = [
    {
      title: 'Requested',
      when: g.requested_at ?? g.created_at,
      who: g.requested_by,
      icon: <IconUser size={14} />,
      done: !!(g.requested_at ?? g.created_at),
    },
    {
      title: g.t1_approved_on_behalf ? 'T1 approved (on-behalf)' : 'T1 approved',
      when: g.t1_approved_at,
      who: g.t1_approved_by,
      icon: <IconShieldCheck size={14} />,
      done: !!g.t1_approved_at,
    },
    {
      title: 'T2 approved',
      when: g.t2_approved_at,
      who: g.t2_approved_by,
      icon: <IconShieldCheck size={14} />,
      done: !!g.t2_approved_at,
    },
  ];

  // Terminal states branch the timeline.
  if (g.denied_at) {
    steps.push({
      title: 'Denied',
      when: g.denied_at,
      who: g.denied_by,
      icon: <IconShieldX size={14} />,
      done: true,
      tone: 'red',
    });
    return steps;
  }
  if (g.revoked_at) {
    steps.push({
      title: 'Revoked',
      when: g.revoked_at,
      icon: <IconShieldX size={14} />,
      done: true,
      tone: 'red',
    });
    return steps;
  }

  steps.push({
    title: 'Claimed (credentials issued)',
    when: g.status === 'ACTIVE' || (g.expires_at && g.status === 'EXPIRED') ? g.updated_at : null,
    icon: <IconCheck size={14} />,
    done: g.status === 'ACTIVE' || (!!g.expires_at && g.status === 'EXPIRED'),
  });
  steps.push({
    title: g.status === 'EXPIRED' ? 'Expired' : 'Credential TTL',
    when: g.expires_at,
    icon: g.status === 'EXPIRED' ? <IconClockExclamation size={14} /> : <IconHourglassHigh size={14} />,
    done: g.status === 'EXPIRED',
  });
  return steps;
}
