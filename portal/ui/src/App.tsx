import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

import { MantineProvider, createTheme } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { HttpError } from './api/client';
import { Shell } from './components/Shell';
import { Backends } from './pages/Backends';
import { GrantDetail } from './pages/GrantDetail';
import { Grants } from './pages/Grants';
import { Home } from './pages/Home';
import { NewGrant } from './pages/NewGrant';
import { NotFound } from './pages/NotFound';
import { Org } from './pages/Org';

// Single shared QueryClient — keeps the cache alive across route changes so
// the grants table doesn't refetch every time the user opens a detail drawer.
// Staletime is short (15s) because the dashboard is most useful when fresh,
// and refetchOnWindowFocus stays on by default for the same reason.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: true,
      retry: (failures, err) => {
        // 4xx is a client-side problem (auth, validation, not found) — no
        // amount of retrying will help and the user just sees latency.
        // Note: client.ts already hard-redirects on 401 before throwing, but
        // a 403/404/409 still surfaces here.
        if (err instanceof HttpError && err.status >= 400 && err.status < 500) {
          return false;
        }
        return failures < 2;
      },
    },
    mutations: {
      retry: false,
    },
  },
});

const theme = createTheme({
  primaryColor: 'indigo',
  defaultRadius: 'md',
  fontFamily:
    'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif',
  fontFamilyMonospace:
    'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
  headings: {
    fontWeight: '600',
  },
});

export function App() {
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <Notifications position="top-right" />
      <QueryClientProvider client={queryClient}>
        {/* basename="/ui" matches the Go mount; ui.go falls back to */}
        {/* index.html for any extensionless path so deep links work. */}
        {/* Legacy hash-route redirect: react-router matches against pathname */}
        {/* only, so we can't register Routes for #/grants etc. main.tsx */}
        {/* rewrites the location before mount; nothing to do here. */}
        <BrowserRouter basename="/ui">
          <Routes>
            <Route element={<Shell />}>
              <Route index element={<Home />} />
              <Route path="grants" element={<Grants />} />
              <Route path="grants/new" element={<NewGrant />} />
              <Route path="grants/:id" element={<GrantDetail />} />
              <Route path="backends" element={<Backends />} />
              <Route path="org" element={<Org />} />
              <Route path="*" element={<NotFound />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </MantineProvider>
  );
}
