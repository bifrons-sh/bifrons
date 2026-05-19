import { Anchor, Center, Stack, Text, Title } from '@mantine/core';
import { Link } from 'react-router-dom';

export function NotFound() {
  return (
    <Center mih="60vh">
      <Stack align="center" gap="xs">
        <Title order={1}>404</Title>
        <Text c="dimmed">That route doesn't exist.</Text>
        <Anchor component={Link} to="/">
          Go home →
        </Anchor>
      </Stack>
    </Center>
  );
}
