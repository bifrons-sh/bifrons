import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';

dayjs.extend(relativeTime);

export function formatRelative(iso?: string | null): string {
  if (!iso) return '—';
  const d = dayjs(iso);
  if (!d.isValid()) return iso;
  return d.fromNow();
}

export function formatAbsolute(iso?: string | null): string {
  if (!iso) return '—';
  const d = dayjs(iso);
  if (!d.isValid()) return iso;
  return d.format('YYYY-MM-DD HH:mm:ss');
}
