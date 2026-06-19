// Inline copy-to-clipboard for short secrets / commands. Click anywhere on
// the value to copy. The component flashes a "copied" check icon to give the
// operator unambiguous feedback.

import { ActionIcon, Code, CopyButton, Tooltip, useMantineColorScheme } from '@mantine/core';
import { IconCheck, IconCopy } from '@tabler/icons-react';

// How long the "copied" check icon stays lit — long enough to register as
// feedback, short enough not to mask a second copy.
const COPY_FEEDBACK_MS = 1500;

export function CopyableCode({
  value,
  display,
  monospace = true,
  block = false,
}: {
  value: string;
  display?: string;
  monospace?: boolean;
  block?: boolean;
}) {
  const { colorScheme } = useMantineColorScheme();
  return (
    <CopyButton value={value} timeout={COPY_FEEDBACK_MS}>
      {({ copied, copy }) => (
        <span
          style={{
            display: block ? 'flex' : 'inline-flex',
            alignItems: 'center',
            gap: 4,
            width: block ? '100%' : undefined,
          }}
        >
          <Code
            block={block}
            style={{
              flex: block ? 1 : undefined,
              cursor: 'pointer',
              fontFamily: monospace ? undefined : 'inherit',
              wordBreak: 'break-all',
              background: colorScheme === 'dark' ? 'var(--mantine-color-dark-7)' : undefined,
            }}
            onClick={copy}
          >
            {display ?? value}
          </Code>
          <Tooltip label={copied ? 'Copied' : 'Copy'}>
            <ActionIcon variant="subtle" onClick={copy} size="sm" aria-label="copy">
              {copied ? <IconCheck size={14} color="green" /> : <IconCopy size={14} />}
            </ActionIcon>
          </Tooltip>
        </span>
      )}
    </CopyButton>
  );
}
