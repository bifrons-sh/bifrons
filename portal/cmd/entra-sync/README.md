# entra-sync — portal org-hierarchy sync script

Keeps the portal's `users.validator_user_id` / `groups` / `group_members`
tables in step with an upstream org-hierarchy source. Run as cron (15 min
is a fine default) — the portal's grant-creation hot path reads from the
synced tables, so nothing on the request path ever touches the upstream IdP.

## Why this exists

The portal used to call Microsoft Graph directly on grant creation (one
round-trip to Graph's `/users/{id}/manager` endpoint — a Graph concept,
unrelated to the portal's "validator" role — plus one to `/users/{id}/memberOf`).
That made the IdP a hard runtime dependency. This script moves those reads
off the hot path: Graph goes down → the portal keeps serving, grants keep
flowing against whatever the last sync captured.

## Usage

```bash
./bin/entra-sync \
  -portal-url http://127.0.0.1:8080 \
  -token "$PORTAL_USER_TOKEN" \
  -source file -fixture example-fixture.json \
  -dry-run
```

Flags:

| Flag          | Env                      | Default                   | Purpose |
|---------------|--------------------------|---------------------------|---------|
| `-portal-url` | `PORTAL_URL`             | `http://127.0.0.1:8080`   | Portal base URL |
| `-token`      | `PORTAL_USER_TOKEN`      | empty                     | Admin bearer token |
| `-source`     | `ENTRA_SYNC_SOURCE`      | `file`                    | `file` (example) or `entra` (production stub) |
| `-fixture`    | `ENTRA_SYNC_FIXTURE`     | empty                     | Path to JSON fixture when `-source=file` |
| `-dry-run`    | —                        | `false`                   | Print the plan without mutating the portal |

## Fixture shape

```json
{
  "users": [
    { "username": "alice", "email": "alice@example.com",
      "external_id": "sub-alice",
      "validator_username": "bob",
      "groups": ["dev-team"] }
  ],
  "groups": [
    { "slug": "dev-team", "display_name": "Developers" }
  ]
}
```

Note: `validator_username` points at the validator's **username** (the portal
resolves it to the portal id internally). It is intentionally named
differently from the portal's on-row `validator_user_id` column to avoid
confusion in hand-written fixtures.

## Idempotency

Re-running the script converges state without dropping rows: new users /
groups / memberships are added, existing ones are left alone. Removed
entries are NOT deleted from the portal — that's a deliberate safety
choice. When you're confident the upstream is authoritative, a future
`-prune` flag can opt in to deletion.

## Production path

The `-source=entra` branch is a stub in this example build — flesh out
`loadFromEntra` in `main.go` to walk Graph (`/users`, `/users/{id}/manager`,
`/groups`, `/groups/{id}/members`) and populate the same `Fixture` shape.
Because `apply()` only speaks fixtures, swapping sources is a one-file
change that doesn't touch the portal.
