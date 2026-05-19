// AppShell layout: top header + collapsible side navigation + scrollable
// outlet for routed pages. The validator-queue badge is computed from the
// react-query cache so it updates the moment any mutation invalidates
// ['grants'].

import {
  ActionIcon,
  AppShell,
  Avatar,
  Badge,
  Burger,
  Code,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Text,
  Title,
  Tooltip,
  useMantineColorScheme,
  useComputedColorScheme,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconBuildingWarehouse,
  IconHome2,
  IconInbox,
  IconLogout,
  IconMoon,
  IconPlus,
  IconShieldCheck,
  IconSitemap,
  IconSun,
  IconUserCircle,
} from '@tabler/icons-react';
import { NavLink as RRLink, Outlet, useLocation } from 'react-router-dom';

import { useGrants, useSession } from '../api/hooks';

export function Shell() {
  const [opened, { toggle }] = useDisclosure();
  const session = useSession();
  const location = useLocation();
  // Validator queue for the badge — silently empty on error so a broken
  // endpoint doesn't break the chrome.
  const validatorQueue = useGrants({ scope: 'validator' });
  const queueCount = validatorQueue.data?.length ?? 0;

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 260, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Title order={4} fw={600} style={{ letterSpacing: '-0.01em' }}>
              Access Portal
            </Title>
            <Badge variant="light" color="indigo" size="sm">
              POC
            </Badge>
          </Group>
          <Group gap="xs">
            <ColorSchemeToggle />
            <SessionMenu username={session.data?.username} email={session.data?.email} isOperator={!!session.data?.is_operator} />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs">
        <AppShell.Section grow component={ScrollArea} scrollbarSize={6}>
          <NavItem to="/" icon={<IconHome2 size={18} />} label="Home" exact />
          <NavItem
            to="/grants"
            icon={<IconShieldCheck size={18} />}
            label="My requests"
            search="?scope=mine"
          />
          {/* Only render the validator queue when there's something in it OR the */}
          {/* user is already on that view (so a deep-link doesn't lose its entry). */}
          {/* Hides the existence of a validator tier from non-validators. */}
          {(queueCount > 0 || location.search === '?scope=validator') && (
            <NavItem
              to="/grants?scope=validator"
              icon={<IconInbox size={18} />}
              label="Awaiting approval"
              search="?scope=validator"
              rightSection={queueCount > 0 ? <Badge size="xs" circle color="orange">{queueCount}</Badge> : undefined}
            />
          )}
          <NavItem to="/grants/new" icon={<IconPlus size={18} />} label="Request access" />
          <NavItem to="/backends" icon={<IconBuildingWarehouse size={18} />} label="Backends" />
          <NavItem to="/org" icon={<IconSitemap size={18} />} label="Org" />
        </AppShell.Section>
        <AppShell.Section>
          <Text size="xs" c="dimmed" ta="center" mt="sm">
            v0.2 · <Code>POC</Code>
          </Text>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}

// NavItem wraps Mantine's NavLink to honour `?scope=...` as an active match.
// react-router's NavLink active state only considers pathname; we want
// /grants?scope=validator and /grants?scope=mine to look like two distinct
// destinations.
function NavItem({
  to,
  icon,
  label,
  exact,
  search,
  rightSection,
}: {
  to: string;
  icon: React.ReactNode;
  label: string;
  exact?: boolean;
  search?: string;
  rightSection?: React.ReactNode;
}) {
  const loc = useLocation();
  const [path] = to.split('?');
  // Active when path matches (or is a prefix for nested routes) AND, when
  // a search filter is part of the entry, the loc.search matches it too.
  const pathActive = exact
    ? loc.pathname === path
    : loc.pathname === path || loc.pathname.startsWith(`${path}/`);
  const searchActive = search ? loc.search === search : true;
  const altMineActive = !search && path === '/grants' && loc.search !== '?scope=validator';
  const active = pathActive && (search ? searchActive : altMineActive || !loc.search);
  return (
    <RRLink to={to} style={{ textDecoration: 'none' }}>
      <NavLink
        component="div"
        label={label}
        leftSection={icon}
        rightSection={rightSection}
        active={active}
        variant="filled"
      />
    </RRLink>
  );
}

function ColorSchemeToggle() {
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme('light', { getInitialValueInEffect: true });
  const next = scheme === 'dark' ? 'light' : 'dark';
  return (
    <Tooltip label={`Switch to ${next} mode`}>
      <ActionIcon variant="default" onClick={() => setColorScheme(next)} aria-label="toggle color scheme">
        {scheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
      </ActionIcon>
    </Tooltip>
  );
}

function SessionMenu({
  username,
  email,
  isOperator,
}: {
  username?: string;
  email?: string;
  isOperator: boolean;
}) {
  const initials = (username ?? '?').slice(0, 2).toUpperCase();
  return (
    <Menu shadow="md" width={220} position="bottom-end">
      <Menu.Target>
        <Group gap="xs" style={{ cursor: 'pointer' }}>
          <Avatar size={32} radius="xl" color="indigo">
            {initials}
          </Avatar>
        </Group>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>
          {username ?? 'not signed in'}
          {isOperator ? ' · admin' : ''}
        </Menu.Label>
        {email && (
          <Menu.Item leftSection={<IconUserCircle size={16} />} disabled>
            <Text size="sm">{email}</Text>
          </Menu.Item>
        )}
        <Menu.Divider />
        <Menu.Item
          leftSection={<IconLogout size={16} />}
          onClick={async () => {
            // /oidc/logout is POST-only — handler returns 405 on GET so a
            // cross-site bookmark/link can't log a user out by surprise.
            // Use fetch+POST and then drop the browser at /ui/, where the
            // shell's session probe will redirect to /oidc/login.
            try {
              await fetch('/oidc/logout', {
                method: 'POST',
                credentials: 'same-origin',
              });
            } catch {
              // Network failure is non-fatal; the server-side session may
              // already be gone. Still navigate so the UI resets.
            }
            window.location.replace('/ui/');
          }}
        >
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
