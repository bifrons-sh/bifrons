# Phase 7 — validation workflow UI + multi-validator model

**Status:** ⬜ (draft for refinement)

Reworks the approval layer to **1-of-N validators per user and per backend, with an admin gate on top**, and surfaces the lifecycle in the operator SPA so requesters, validators, and admins all have a place to live.

**Goal:** any one of a user's assigned validators OR any one of the target backend's assigned validators can clear the validator gate; an admin then clears the second gate. Requester sees their own requests; a DB-derived validator sees exactly what's waiting on them; admin sees the whole fleet, filterable.

Estimated: **~6.5 dev-days** across schema change + backend + UI + tests.

---

## 7.1 Approval model

Two-tier gate, each tier 1-of-N:

```
┌─────────────┐    any 1 of         ┌─────────────┐    any 1 of      ┌──────────┐
│  PENDING    │ ─── validators ───▶ │ VALIDATOR_  │ ───  admins ───▶ │ APPROVED │
│             │                     │ APPROVED    │                  │          │
└─────────────┘                     └─────────────┘                  └──────────┘
```

- **Validator set for a grant** = eligible approvers computed at create time:
  `union(user_validators[grant.user_id], backend_validators[grant.backend_id])`
  Any one of them approving flips the grant to `VALIDATOR_APPROVED`. Frozen at create time — reassignments afterwards do not retroactively re-target in-flight grants (four-eyes integrity, same rule as the current single-validator model).

- **Admin tier** stays as-is: any admin clears the second gate. "Possibly one admin on top" is a hint that the admin tier is intentionally thin (1 admin is enough, no N-of-M), and in principle **configurable per backend** to be skipped entirely for low-risk backends — see §7.8.1.

- **Deny** remains 1-of-1: any eligible validator OR any admin can deny a grant outright, terminating the flow. Denial does not require the full 1-of-N vote.

---

## 7.2 Personas and views

| Persona | Selector | Scope | Mutations |
|---|---|---|---|
| Requester | every authenticated session | grants where `grant.user_id == caller.portal_user_id` | `POST /claim` on own grants |
| Validator | any session in at least one grant's eligible-validator set | grants where `caller.sub ∈ grant.validator_subjects` | `POST /approve` (validator half), `POST /deny` |
| Admin | `session.is_admin` or static-bearer | all grants | `POST /approve` (admin half), `POST /deny`, `DELETE` (revoke), `PATCH` |

The validator persona is **fully data-derived** — nothing flags a user as "validator". The SPA discovers "you're a validator of N requests" by probing `GET /grants?scope=validator`. Empty probe → no validator tab.

---

## 7.3 Data model

### Breaking-change inventory

Before touching schema, here is the full set of load-bearing symbols that move or disappear. The implementer should plan to touch these in one commit so `go build` never leaves a broken state:

| Current | After 7.A | Notes |
|---|---|---|
| `users.validator_user_id` (SQL column, FK) | deleted | replaced by `user_validators` junction |
| `idx_users_validator` (SQL index) | deleted | replaced by `idx_user_validators_validator` |
| `grants.validator_subject` (SQL column) | deleted | eligible set moves to `grant_validators` |
| `domain.User.ValidatorUserID` (Go field) | deleted | callers use `store.ListUserValidators(userID)` |
| `domain.Grant.ValidatorSubject` (Go field) | deleted | callers use `store.ListGrantValidators(grantID)` |
| `store.SetUserValidator` | → `AddUserValidator` / `RemoveUserValidator` / `ListUserValidators` |
| `org_handler.setValidator` / `clearValidator` / `getValidator` (HTTP handlers) | → `addValidator` / `removeValidator` / `listValidators` |
| `PUT /api/v1/users/{id}/validator` + `DELETE` | → `POST/DELETE /api/v1/users/{id}/validators/{validator_id}` |
| `authz.IsValidatorFor` (single-equality) | set-membership check against `g.ValidatorSubjects` |
| `grants_handler.create`'s single-validator resolution block | replaced by snapshot block that writes `grant_validators` rows |
| Sync fixture field `validator_username` (single) | `validator_usernames: []string` |
| Tests referencing `ValidatorUserID` / `ValidatorSubject` scalar | rewritten against junction |

### Schema changes (amend `0001_initial.sql` — still pre-deploy)

```sql
-- DROP: users.validator_user_id column + idx_users_validator index
--      (do not ship 0001 with them — edit in place).
-- DROP: grants.validator_subject column (singular). The eligible set lives
--      in grant_validators; grants keeps validator_approved_by /
--      validator_approved_at as the winning-row cache for hot-path reads.

-- Many-to-many: a user may have multiple validators.
CREATE TABLE IF NOT EXISTS user_validators (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    validator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (user_id, validator_id),
    CHECK (user_id <> validator_id)   -- self-validator guarded at write time too
);
CREATE INDEX IF NOT EXISTS idx_user_validators_validator ON user_validators(validator_id);

-- Backend-level validators are a **group** (e.g. "dba-team"), not individual
-- users. Grant creation expands the group membership at snapshot time; group
-- membership changes after that do not retroactively re-target in-flight
-- grants (four-eyes integrity). Rationale in §7.8.2 — decision taken, not open.
CREATE TABLE IF NOT EXISTS backend_validator_groups (
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (backend_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_backend_validator_groups_group
    ON backend_validator_groups(group_id);

-- Per-grant snapshot of eligible validator subjects. One row per eligible
-- validator at create time; approval flips approved_at + approved_by on the
-- row the approver owns. Junction rather than JSON array so we can query
-- "grants awaiting my approval" with an indexed JOIN and keep an audit trail
-- of who approved which grant without a separate event log.
CREATE TABLE IF NOT EXISTS grant_validators (
    grant_id         TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    validator_subject TEXT NOT NULL,   -- OIDC sub, frozen at create time
    source           TEXT NOT NULL,    -- "user" | "backend_group:<slug>" — audit only
    approved_at      TEXT,
    approved_by      TEXT NOT NULL DEFAULT '',  -- same as validator_subject on normal path; distinct if an admin acts on-behalf
    PRIMARY KEY (grant_id, validator_subject)
);
CREATE INDEX IF NOT EXISTS idx_grant_validators_subject_pending
    ON grant_validators(validator_subject) WHERE approved_at IS NULL;

-- Per-backend toggle: when admin_gate_required=FALSE, a grant with
-- VALIDATOR_APPROVED status skips straight to APPROVED without the second
-- gate. Default TRUE preserves today's two-tier semantics. Rationale in
-- §7.8.1 — decision taken, column added here.
--
-- Add this column to the existing `backends` CREATE TABLE in 0001_initial.sql
-- directly (we're still pre-deploy). The dialect-specific form is:
--   sqlite:   admin_gate_required INTEGER NOT NULL DEFAULT 1
--   postgres: admin_gate_required BOOLEAN NOT NULL DEFAULT TRUE
-- Do NOT ship as an ALTER unless the schema has already shipped — edit in
-- place so the initial migration stays authoritative.
```

### Grant state derivation

- `grant.status = PENDING`: no row in `grant_validators` has `approved_at`.
- Any `grant_validators` row gets `approved_at` (and `approved_by`) → a compare-and-swap flips the grant to `VALIDATOR_APPROVED`. First writer wins; subsequent approvals by other eligible validators land as rows in `grant_validators` (advisory — the gate is already cleared) but do NOT re-trigger status changes.
- If `backends.admin_gate_required = FALSE` for the grant's backend, the same validator approval transitions straight to `APPROVED`, recording `ApprovedBy = ValidatorApprovedBy` and setting the claim window. The admin tier is effectively collapsed at write time, not at config-read time, so the audit trail always shows which tier ran.
- `grant.validator_subject` (singular, on the `grants` row) is **removed**. The frozen set lives in `grant_validators`. `grant.validator_approved_by` + `validator_approved_at` stay on `grants` as a convenience — they duplicate the winning row in `grant_validators` and keep the hot-path read single-row.

### When the eligible set is empty

If the union of user's validators + backend's validators is empty at create time, the grant is minted in `PENDING` with zero `grant_validators` rows. The validator gate then collapses to admin-only (same rule as the current single-validator `ValidatorSubject == ""` branch). Static-bearer bootstrap keeps working. Document behaviour in the UI: "no validator assigned — admin will approve directly".

### Cycle detection

`SetUserValidator` (now `AddUserValidator`) must walk every outgoing `validator_id` edge from the proposed validator upward and reject when the target user appears. DFS, bounded at 64 hops as today. Multiple edges per user mean the cycle detector walks a DAG rather than a chain; same 64-node cap guards any pathological org.

---

## 7.4 API surface

### New validator-assignment endpoints

Replaces `PUT /users/{id}/validator` from the draft. All mutations admin-gated; reads return the public-DTO trim for non-admins (username only, no `external_id` / `is_admin`).

User-side (user validators are individuals):

| Method | Path | Body | Semantics |
|---|---|---|---|
| `GET`    | `/api/v1/users/{id}/validators` | — | list this user's validator users |
| `POST`   | `/api/v1/users/{id}/validators/{validator_id}` | — | add (idempotent, cycle-checked) |
| `DELETE` | `/api/v1/users/{id}/validators/{validator_id}` | — | remove (idempotent) |
| `GET`    | `/api/v1/users/{id}/subordinates` | — | reverse index from `user_validators` — users this user validates |

Backend-side (backend validators are **groups**; members are expanded at grant-creation time — see §7.3 decision):

| Method | Path | Body | Semantics |
|---|---|---|---|
| `GET`    | `/api/v1/backends/{id}/validator-groups` | — | list groups authorised to validate this backend |
| `POST`   | `/api/v1/backends/{id}/validator-groups/{group_id}` | — | add (idempotent) |
| `DELETE` | `/api/v1/backends/{id}/validator-groups/{group_id}` | — | remove (idempotent) |

### Grants list extensions

`GET /api/v1/grants?scope={mine,validator,all}&status=...&backend_id=...&user_id=...&limit=...&before=...`

- `scope=validator` → grants where caller's subject appears in any `grant_validators` row. The store implementation **MUST** JOIN `grant_validators` into the grant list query (not fetch-and-filter per row); the N+1 path is explicitly forbidden. `idx_grant_validators_subject_pending` makes the JOIN's indexed predicate `(validator_subject = ? AND approved_at IS NULL)` cheap even for the pending-only view.
- `approved_by_me=true` optional filter — for validators reviewing their history.

`GET /api/v1/grants/counts?scope=...` — returns `{pending, validator_approved, approved, active, ...}`; for `scope=validator` the `pending` count means "pending MY approval" (excludes grants already cleared by another eligible validator).

### Grant list response shape

Each grant now carries an embedded `validators` array, populated by the store in a single JOIN (not a per-grant follow-up):

```jsonc
{
  "id": "g-…",
  "status": "PENDING",
  "validators": [
    { "subject": "sub-bob",   "username": "bob",   "source": "user",               "approved_at": null },
    { "subject": "sub-carol", "username": "carol", "source": "backend_group:dba",  "approved_at": "2026-04-20T10:14Z", "approved_by": "sub-carol" }
  ],
  "validator_gate_cleared_by": "sub-carol",   // the winning row, or null
  // ... existing fields
}
```

The list query shape per dialect:

**SQLite** (requires 3.38+ for `json_group_array` — modernc.org/sqlite 3.46+ is fine):

```sql
SELECT g.*,
       COALESCE((SELECT json_group_array(
           json_object('subject', gv.validator_subject,
                       'source', gv.source,
                       'approved_at', gv.approved_at,
                       'approved_by', gv.approved_by))
         FROM grant_validators gv WHERE gv.grant_id = g.id), '[]') AS validators
FROM grants g
/* optional JOIN for scope=validator: */
/* JOIN grant_validators vf ON vf.grant_id = g.id AND vf.validator_subject = ? */
WHERE …
```

**PostgreSQL**:

```sql
SELECT g.*,
       COALESCE((SELECT jsonb_agg(
           jsonb_build_object('subject', gv.validator_subject,
                              'source', gv.source,
                              'approved_at', gv.approved_at,
                              'approved_by', gv.approved_by))
         FROM grant_validators gv WHERE gv.grant_id = g.id), '[]'::jsonb) AS validators
FROM grants g
/* optional JOIN for scope=validator: */
/* JOIN grant_validators vf ON vf.grant_id = g.id AND vf.validator_subject = $1 */
WHERE …
```

Both forms return a JSON string; the Go layer unmarshals into `[]GrantValidator` (see below) in `scanGrantRow`. Username resolution (`subject` → `username`) stays client-side via the preloaded `/users` response, to keep the grant query backend-agnostic.

### New `domain.GrantValidator` type

```go
// GrantValidator is one row of a grant's frozen eligible-validator set.
// Serialised into the Grant list JSON under `validators` (see §7.4 query).
// Username is populated by the SPA from a client-side Map<externalID,User>;
// the server never JOINs users into this struct to keep list queries dialect-
// independent.
type GrantValidator struct {
    Subject    string     `json:"subject"`                 // OIDC sub; frozen at grant create time
    Source     string     `json:"source"`                  // "user" | "backend_group:<slug>" — audit only
    ApprovedAt *time.Time `json:"approved_at,omitempty"`   // nil until this eligible approver acts
    ApprovedBy string     `json:"approved_by,omitempty"`   // Subject of approver (== Subject on normal path; admin-on-behalf differs)
}
```

### `store` interface deltas

Replace `SetUserValidator` with:

```go
AddUserValidator(ctx, userID, validatorID string) error
RemoveUserValidator(ctx, userID, validatorID string) error
ListUserValidators(ctx, userID string) ([]domain.User, error)
ListUserSubordinates(ctx, validatorID string) ([]domain.User, error)

AddBackendValidatorGroup(ctx, backendID, groupID string) error
RemoveBackendValidatorGroup(ctx, backendID, groupID string) error
ListBackendValidatorGroups(ctx, backendID string) ([]domain.Group, error)

// Grant validators — junction owns the eligible set + approval records
CreateGrantValidators(ctx, grantID string, rows []domain.GrantValidator) error  // called by CreateGrant
ListGrantValidators(ctx, grantID string) ([]domain.GrantValidator, error)
ApproveGrantValidator(ctx, grantID, subject, approvedBy string) error           // CAS on approved_at IS NULL

// Backend gate toggle (per §7.8.1)
SetBackendAdminGateRequired(ctx, backendID string, required bool) error
```

`GrantFilter.ValidatorSubject` stays on the filter (implemented via JOIN per the query shape above).

The `ListGrants` contract changes: implementations MUST populate `domain.Grant.Validators []GrantValidator` on every returned row via the single-query JOIN shown above. Documented on the interface so a future SQL-dialect port can't silently regress to N+1.

---

## 7.5 Authz

`authz.IsValidatorFor(g)` changes from subject-equality to set-membership:

```go
func (p Principal) IsValidatorFor(g domain.Grant) bool {
    if p.IsStaticBearer() {
        return !p.EntraWired || len(g.ValidatorSubjects) == 0
    }
    if len(g.ValidatorSubjects) == 0 {
        return p.IsAdmin()          // empty set → admin-only collapse
    }
    for _, sub := range g.ValidatorSubjects {
        if p.Session.Subject == sub {
            return true
        }
    }
    return false
}
```

`g.ValidatorSubjects` is a derived `[]string` populated by `ListGrants` / `GetGrant` as a by-product of the JOIN specified in §7.4 — callers never issue a separate `ListGrantValidators` on the hot read path.

The `IsValidatorFor` gate checks eligibility; the actual write path (`ApproveGrantValidator`) does the CAS that flips the status once. Double-approval by two different validators racing lands the second approval as a no-op (CAS rejects), returning 409 with a "grant already cleared" message.

### Admin tier configurability (ties back to §7.8.1)

When the grant's backend has `admin_gate_required = FALSE`, the validator-approval path short-circuits the admin tier:

```
validatorApprove():
  flip status PENDING → VALIDATOR_APPROVED
  record validator_approved_by / validator_approved_at
  if backend.admin_gate_required == FALSE:
      flip status VALIDATOR_APPROVED → APPROVED
      copy ApprovedBy ← ValidatorApprovedBy
      stamp claim window from ClaimWindow config
      emit both notify.OnValidatorApproved and notify.OnApproved
```

The `authz` layer is unaware of the toggle — the handler makes the decision. `IsValidatorFor` / `IsAdmin` remain unchanged. Both lifecycle events fire so downstream auditors that key on status transitions see both gates clear in one request.

---

## 7.6 UI

### `/requests` route layout

```
┌─ tabs ─────────────────────────────────────────┐
│  My requests (3)                               │
│  Awaiting my approval (2)   [shown if count>0] │
│  All requests (42)          [admin only]       │
└────────────────────────────────────────────────┘
┌─ filters (collapsible) ────────────────────────┐
│  Status: [PENDING] [VALIDATOR_APPROVED] …      │
│  Backend: [all ▾]   User: [all ▾] (admin)       │
└────────────────────────────────────────────────┘
┌─ grants table ─────────────────────────────────┐
│ ID    Requester  Backend/role  Validators       Status      Age  │
│ g-…   alice      pg-prod/app   bob, carol ✔     🟡 PENDING  2m   │
│                                [approve][deny]                   │
│ g-…   carol      pg-prod/dba   alice ✔ dba-ops  🔵 VAL_APP  14m  │
│                                (admin action required)           │
└────────────────────────────────────────────────┘
```

### Validators column

- Shows each eligible approver's username.
- A checkmark (`✔`) next to any name indicates that validator has approved.
- Distinguishes visually between "user-chain validators" and "backend-level validators" (e.g. italics for backend-level) so operators see whether the approval came from the user's manager or the DBA team.

### Actions by row, gated by (status, caller):

| Status | Requester | Validator (eligible) | Admin |
|---|---|---|---|
| PENDING | Cancel (→ REVOKED) | Approve / Deny | Deny only |
| VALIDATOR_APPROVED | — | — | Approve / Deny |
| APPROVED | Claim | — | Claim-on-behalf / Revoke |
| ACTIVE | — | — | Revoke |
| terminal | — | — | — |

"Approve" on PENDING by any eligible validator flips status; if other validators were also eligible, their row in `grant_validators` stays open (advisory for audit — a second validator's approval POST after the first lands as a 409 "already cleared" with a friendly message).

### Org chart view update

The existing `/org` view shows a single "Manager" column — must switch to a "Validators" multi-cell (comma-separated, clickable to drill into each). Add a corresponding backend-level validator section under the backends view.

### Claim modal — unchanged from draft §7.5.

---

## 7.7 Observability

- Counter `grants_validator_approvals_total{race=won|lost}` — `lost` = 409 on ApproveGrantValidator CAS, i.e. a race between two eligible validators. Small/zero under normal operation; a spike means validators are coordinating poorly.
- Counter `grants_created_total{validator_count=0|1|2+}` — detects grants minted with no eligible validators (admin-only collapse).
- Counter `grants_list_requests_total{scope=mine|validator|all}`.
- Histogram `grants_list_duration_seconds{scope=...}` — catches N+1 regressions on the join path.

Audit rows continue to be emitted on state transitions through the existing handlers — adding validator granularity means one audit row per *state transition*, not per individual approval in the set.

---

## 7.8 Open questions for refinement

### 7.8.1 Admin-on-top — DECIDED: per-backend toggle

**Decision:** `backends.admin_gate_required BOOLEAN` (SQL column added in §7.3). Default TRUE preserves today's two-tier semantics; low-risk backends (staging, RO replicas) can set FALSE so validator-approved short-circuits to APPROVED. The alternative (per-role toggle, e.g. "ro grants skip admin") multiplies the config surface without adding operator value — it can be layered later as `backend_role_overrides` if ever needed.

Implementation: the toggle is read in the validator-approval handler, not in authz — see §7.5 "Admin tier configurability". The authz rulebook stays unaware of the short-circuit, which keeps the approve_admin / deny / claim checks unchanged.

### 7.8.2 Backend validators — DECIDED: groups only

**Decision:** `backend_validator_groups` junction keys on `group_id`. "The DBA team validates prod-pg" is the natural shape and reuses the existing `groups` table; operators add each DBA to the `dba-team` group once, not per-backend. Mixed user+group rows (option (c) in the original draft) adds a type-tag column for an edge case nobody has asked for yet — defer until a concrete user-level-per-backend need appears.

Trade-off accepted: a user added to the `dba-team` group **after** a grant is created is NOT retroactively added to that grant's eligible validator set, because `grant_validators` snapshots membership at create time. Matches the four-eyes audit invariant — "who was authorised when this request was filed?" is frozen. Document in the backend-validator admin form so operators know adding a member mid-flight does not unblock a stuck grant.

### 7.8.3 User-level validators — DECIDED: users only

**Decision:** `user_validators` keys on individual `validator_id`. Alice's validator is her line manager (one specific person), not a group. If group-level user validators ever emerge as a real need (e.g. "the security team is Alice's secondary validator"), the shape to add is a second junction `user_validator_groups` parallel to `backend_validator_groups`, snapshot-expanded the same way.

### 7.8.4 Empty-set grants: block, admin-only, or reject?

When neither the user nor the backend has any configured validator:

- **(a) Block at create**: 422 "no eligible validator configured for this trio".
- **(b) Admin-only collapse** (today's behaviour for single-validator): grant goes PENDING with an empty eligible set; admin alone clears it.
- **(c) Auto-approve the validator tier**: grant goes directly to VALIDATOR_APPROVED with `validator_gate_cleared_by = "auto"`.

Recommend **(b)**. Documented escape hatch for bootstrap / local-dev / deployments where admins are the intended sole reviewers. (a) is too strict for an operator fleet in early setup; (c) blurs audit ("who approved?").

### 7.8.5 Validator reassignment — drop or retain in-flight?

When an admin removes Bob from Alice's validator set while Alice has a PENDING grant:

- **(a) Retain** (default proposal): grant's `grant_validators` row for Bob stays; Bob can still approve.
- **(b) Prune**: remove Bob's row; if the set is now empty, collapse to admin-only (or notify admin).

Recommend (a). Reassignment affects *future* grants only; the frozen set matches audit expectations. Operators who want to strip in-flight authority can revoke the grant directly.

### 7.8.6 Deny semantics — 1-of-1 or majority?

Any validator can deny today. Should the set require consensus? Recommend **1-of-1 deny** — denial is a terminal safety decision; requiring consensus would let a single dissenter hold a request hostage. Flag if operators disagree.

### 7.8.7 Stacking: user validator AND admin == "super approver"?

If Alice's own validator happens to be an admin, they can clear both gates in two clicks. Should the UI offer a combined "approve both gates" action? Recommend **no** — two deliberate clicks preserves the cognitive separation between "I vouch for this person" and "I authorise this access". Flag.

### 7.8.8 Validator set on status display

Should the SPA show the full eligible set on PENDING grants (so requesters know who to chase) or only the approvers-of-record? Recommend **show the full set on PENDING, collapse to just the winner on VALIDATOR_APPROVED and later**. Matches principle of least surprise — you see who's blocking while blocked, then the history after.

---

## 7.9 Edge cases & invariants

1. **Frozen eligible set** — `grant_validators` snapshot at create time. Reassignments and group-membership changes never retroactively add/remove rows.
2. **Race on approval** — `ApproveGrantValidator` uses CAS on `approved_at IS NULL` per row plus CAS on `grant.status` transition. Two eligible validators clicking simultaneously: first wins, second gets 409 with "grant already cleared by &lt;name&gt;". The losing row's `approved_at` stays NULL (advisory — the winner alone clears the gate).
3. **Backend-validator-group removed while grant PENDING** — the group's member snapshot in `grant_validators` stays, so the approvers who were in the group at create time remain eligible. Reflects §7.8.2's freeze.
4. **Group member added/removed after grant created** — eligibility unchanged for that grant; new members are eligible only for grants created after the membership change.
5. **Validator's OIDC `sub` rotates** — `grant_validators.validator_subject` is a raw string so it survives the rename, but that grant becomes unclearable by the rotated identity. Mitigation: `UpdateUser`, when it changes `external_id`, must also `UPDATE grant_validators SET validator_subject = $new WHERE validator_subject = $old AND approved_at IS NULL` (winning rows are historical and must NOT be rewritten — that would revise audit). Tracked as an explicit store-level operation, not a silent side-effect.
6. **User deletion / disable** — `ON DELETE CASCADE` tears down `user_validators` + `backend_validator_groups`; `grant_validators.validator_subject` is a raw string so it survives user deletion. If the deletion strands a grant (every eligible subject gone), the grant collapses to admin-only via the empty-set rule once the last eligible validator is unreachable. Operators dealing with a legitimate user departure should use `revoke` on stuck grants rather than relying on collapse.
7. **Self-validator via transitive edge** (A validates B, B validates A) — cycle detector walks every outgoing edge on `AddUserValidator`, bounded to 64 hops. The CHECK constraint on `user_validators` blocks the direct self-loop at the DB layer.
8. **`admin_gate_required = FALSE` race with toggle** — if an operator flips the toggle between a grant's PENDING and VALIDATOR_APPROVED states, the validator-approval handler reads the current value at the moment of approval. Acceptable: the operator explicitly changed policy, and the grant's audit trail records which handler path ran (via the `OnApproved` event firing or not).

---

## 7.10 Acceptance criteria

- ⬜ Schema: `user_validators`, `backend_validator_groups`, `grant_validators` tables exist in both sqlite + postgres initial migration. `users.validator_user_id` column and `grants.validator_subject` column both removed. `backends.admin_gate_required` column added.
- ⬜ Admin API: add/remove/list endpoints for `users/{id}/validators` (user-ids) and `backends/{id}/validator-groups` (group-ids); `SetBackendAdminGateRequired` surfaced on the backends form.
- ⬜ Grant creation: eligible validator set computed as `union(user_validators, expand_group_members(backend_validator_groups))`, snapshot into `grant_validators` with `source` tagged `user` or `backend_group:<slug>`. Empty set → admin-only collapse with a log line.
- ⬜ `POST /grants/{id}/approve` on validator half: CAS on first eligible approver, 409 on subsequent. When `backend.admin_gate_required = FALSE`, the same request also fires the admin-tier transition.
- ⬜ `GET /grants?scope=validator` returns grants where caller appears in any `grant_validators` row with `approved_at IS NULL`. Implementation MUST use a single JOIN, not N+1 per-grant fetches — verified by a test that asserts query count is constant in the number of returned grants.
- ⬜ `GET /grants?scope=validator&approved_by_me=true` returns caller's approval history.
- ⬜ `authz.IsValidatorFor` uses set-membership; existing tests updated to assert 1-of-N.
- ⬜ SPA `/requests` view renders all three tabs conditionally, with the Validators column showing checkmarks as approvals land and visually separating user-chain validators from backend-group validators.
- ⬜ Org view renders multi-validator cells per user; backends view renders the backend's validator groups + the `admin_gate_required` toggle.
- ⬜ Sync fixture accepts `validator_usernames: []string` (per user) and `validator_group_slugs: []string` (per backend, pending §7.8.2).
- ⬜ Race test: two validators approving the same PENDING grant concurrently — exactly one gets 2xx, the other 409.
- ⬜ TS type-check + lint pass; `go test ./... -race` passes.
- ⬜ HLD §4.1 grant-lifecycle diagram updated to show the set-based gate.

---

## 7.11 Out of scope

- N-of-M validator quorum (`require_at_least: 2`) — 1-of-N is the decided default; quorum is a future bolt-on.
- Delegate / "out of office" validator passthrough — phase 7.x.
- Time-window rules ("Bob can only validate during business hours") — future.
- Per-grant ad-hoc validators ("this one-off needs Carol too") — future; would add a `grant_validators` admin endpoint to append rows mid-flight.
- CLI parity — phase 6 touches CLI broadly.
- Real-time updates (SSE / websockets) — polling is adequate.
- Validator-chain escalation (seniors can act on juniors' queues) — explicitly deferred; direct-only stays the rule.

---

## 7.12 Suggested phasing

| Sub-phase | Work | Effort |
|---|---|---|
| 7.A | Schema migration (amend 0001 per §7.3 inventory), store methods for user/backend-group/grant validators + `SetBackendAdminGateRequired`, cycle detector on new edge set, test rewrite for every call site in the breaking-change table | 2 days |
| 7.B | Grant create: compute + snapshot eligible set with `source` tagging; CAS approval path; `admin_gate_required` short-circuit; updated authz | 1 day |
| 7.C | Admin API for validator assignment (user-ids + backend-groups) + admin-gate toggle + sync fixture shape (`validator_usernames: []string`, `backend_validator_groups: []string`) | 1 day |
| 7.D | SPA `/requests` view (all three tabs) + validator column rendering with user / backend-group visual distinction | 1.5 days |
| 7.E | Org / backends UI updates for multi-validator + admin-gate toggle surface | 1 day |

A + B are the spine; C enables the ops workflow; D + E are the UX.
