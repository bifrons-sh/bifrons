#!/usr/bin/env bash
# Seed the running demo portal:
#   - five users mirroring the Keycloak realm (so the OIDC provisioner binds
#     by external_id on first login)
#   - validator relationships (bob→david, carol→david)
#   - portal groups (admins, validators, dba-prod, engineers)
#   - three backends (mysql/postgres/mongo) + shared `app` account on each
#
# Run AFTER `docker compose -f dev/compose.yml up -d --build` is healthy.

set -euo pipefail

readonly PORTAL_URL="${PORTAL_URL:-http://127.0.0.1:18080}"
readonly PORTAL_HEALTH_URL="${PORTAL_HEALTH_URL:-http://127.0.0.1:19095/healthz}"
readonly USER_TOKEN="${USER_TOKEN:-demo-bootstrap-token}"

H_USER=(-H "Authorization: Bearer ${USER_TOKEN}" -H "Content-Type: application/json")

# Scratch file for curl response bodies. Was a fixed /tmp path before — that
# is symlink-attack-prone on shared dev hosts and races against concurrent
# runs. mktemp + trap is the bash-rules-mandated form.
RESP_BODY="$(mktemp)"
trap 'rm -f "$RESP_BODY"' EXIT

# Keycloak user UUIDs as exported in dev/keycloak/realm.json. These are the
# `sub` claims OIDC will deliver; pre-binding them via external_id makes the
# first login a lookup-and-attach instead of a fresh provisioning.
ALICE_SUB="11111111-1111-1111-1111-111111111111"
BOB_SUB="22222222-2222-2222-2222-222222222222"
CAROL_SUB="33333333-3333-3333-3333-333333333333"
DAVID_SUB="44444444-4444-4444-4444-444444444444"
EVE_SUB="55555555-5555-5555-5555-555555555555"

echo "Waiting for portal at ${PORTAL_HEALTH_URL} ..."
for i in $(seq 1 90); do
  if curl -sf "${PORTAL_HEALTH_URL}" >/dev/null; then
    echo "  portal up"
    break
  fi
  sleep 1
  if [[ $i -eq 90 ]]; then
    echo "Portal never became healthy. Check: docker compose -f dev/compose.yml logs portal keycloak"
    exit 1
  fi
done

jget() { python3 -c "import sys,json; print(json.loads(sys.argv[1])[sys.argv[2]])" "$1" "$2"; }

# Idempotent user creator: if username already exists (409), look it up and
# return the existing id. This is what makes re-running seed.sh on a persisted
# sqlite store safe.
#
# Accepted trade-off: the lookup uses an unpaginated GET /api/v1/users. Fine
# for the demo (5 users); add a GET-by-username endpoint if the seed ever
# scales to dozens of org members. Same pattern applies in ensure_backend
# and ensure_group below.
ensure_user() {
  local username="$1" display="$2" email="$3" external_id="$4" is_operator="$5"
  local body
  body=$(python3 -c "
import json,sys
print(json.dumps({'username':sys.argv[1],'display_name':sys.argv[2],'email':sys.argv[3],'external_id':sys.argv[4],'is_operator':sys.argv[5]=='true'}))
" "$username" "$display" "$email" "$external_id" "$is_operator")
  local resp; resp=$(curl -s -o "$RESP_BODY" -w "%{http_code}" -X POST "${PORTAL_URL}/api/v1/users" "${H_USER[@]}" -d "$body")
  local code="$resp"
  if [[ "$code" == "201" ]]; then
    jget "$(cat "$RESP_BODY")" id
    return
  fi
  if [[ "$code" == "409" ]]; then
    # Look up via list (small N here). Could expose GET-by-username if it grows.
    curl -s "${PORTAL_URL}/api/v1/users" "${H_USER[@]}" \
      | python3 -c "
import json,sys
us=json.load(sys.stdin)
m=[u for u in us if u['username']==sys.argv[1]]
print(m[0]['id'] if m else '', file=sys.stdout)
" "$username"
    return
  fi
  echo "user create failed: code=$code body=$(cat "$RESP_BODY")" >&2
  exit 1
}

echo
echo "== Users =="
ALICE_ID=$(ensure_user alice "Alice Admin"    alice@example.test "$ALICE_SUB" true)
BOB_ID=$(ensure_user   bob   "Bob Engineer"   bob@example.test   "$BOB_SUB"   false)
CAROL_ID=$(ensure_user carol "Carol Engineer" carol@example.test "$CAROL_SUB" false)
DAVID_ID=$(ensure_user david "David Validator" david@example.test "$DAVID_SUB" false)
EVE_ID=$(ensure_user   eve   "Eve Newbie"     eve@example.test   "$EVE_SUB"   false)
printf "  alice=%s\n  bob=%s\n  carol=%s\n  david=%s\n  eve=%s\n" "$ALICE_ID" "$BOB_ID" "$CAROL_ID" "$DAVID_ID" "$EVE_ID"

echo
echo "== Validator wiring =="
set_validator() {
  local uid="$1" vid="$2"
  curl -sf -X PUT "${PORTAL_URL}/api/v1/users/${uid}/validator" "${H_USER[@]}" \
    -d "{\"validator_user_id\":\"${vid}\"}" >/dev/null
}
set_validator "$BOB_ID"   "$DAVID_ID" && echo "  bob   → david"
set_validator "$CAROL_ID" "$DAVID_ID" && echo "  carol → david"

echo
echo "== Groups =="
ensure_group() {
  local slug="$1" display="$2"
  local body="{\"slug\":\"${slug}\",\"display_name\":\"${display}\"}"
  curl -sf -X POST "${PORTAL_URL}/api/v1/groups" "${H_USER[@]}" -d "$body" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null \
    || curl -s "${PORTAL_URL}/api/v1/groups" "${H_USER[@]}" \
       | python3 -c "import sys,json; gs=json.load(sys.stdin); print([g for g in gs if g['slug']==sys.argv[1]][0]['id'])" "$slug"
}
ADMINS_GID=$(ensure_group admins "Admins")
VALIDATORS_GID=$(ensure_group validators "Validators")
DBA_PROD_GID=$(ensure_group dba-prod "DBA — prod")
ENGINEERS_GID=$(ensure_group engineers "Engineers")
echo "  admins=$ADMINS_GID validators=$VALIDATORS_GID dba-prod=$DBA_PROD_GID engineers=$ENGINEERS_GID"

add_member() {
  local gid="$1" uid="$2"
  # Idempotent: 409 / 400 on already-member is fine.
  curl -s -o /dev/null -X POST "${PORTAL_URL}/api/v1/groups/${gid}/members/${uid}" "${H_USER[@]}" || true
}
add_member "$ADMINS_GID"     "$ALICE_ID"
add_member "$DBA_PROD_GID"   "$ALICE_ID"
add_member "$DBA_PROD_GID"   "$DAVID_ID"
add_member "$VALIDATORS_GID" "$DAVID_ID"
add_member "$ENGINEERS_GID"  "$BOB_ID"
add_member "$ENGINEERS_GID"  "$CAROL_ID"
add_member "$ENGINEERS_GID"  "$EVE_ID"
echo "  group memberships applied"

echo
echo "== Backends =="
declare -A BACKEND_IDS BACKEND_ADDRS

ensure_backend() {
  local name="$1" type="$2" host="$3" port="$4"
  local body="{\"name\":\"${name}\",\"type\":\"${type}\",\"host\":\"${host}\",\"port\":${port},\"databases\":[\"demo\"]}"
  local resp; resp=$(curl -s -o "$RESP_BODY" -w "%{http_code}" -X POST "${PORTAL_URL}/api/v1/backends" "${H_USER[@]}" -d "$body")
  if [[ "$resp" == "201" ]]; then
    jget "$(cat "$RESP_BODY")" id
  else
    curl -s "${PORTAL_URL}/api/v1/backends" "${H_USER[@]}" \
      | python3 -c "import sys,json; bs=json.load(sys.stdin); print([b for b in bs if b['name']==sys.argv[1]][0]['id'])" "$name"
  fi
}

register_backend() {
  local name="$1" type="$2" host="$3" port="$4"
  local id; id=$(ensure_backend "$name" "$type" "$host" "$port")
  BACKEND_IDS[$type]=$id
  BACKEND_ADDRS[$type]="${host}:${port}"
  printf "  %-8s name=%s host=%s:%s id=%s\n" "$type" "$name" "$host" "$port" "$id"
}
register_backend "demo-mysql-primary"    mysql    mysql    3306
register_backend "demo-postgres-primary" postgres postgres 5432
register_backend "demo-mongo-primary"    mongo    mongo    27017

echo
echo "== Backend accounts (role=app) =="
upsert_account() {
  local bid="$1" role="$2" username="$3" password="$4"
  local body="{\"role\":\"${role}\",\"username\":\"${username}\",\"password\":\"${password}\"}"
  curl -sf -X POST "${PORTAL_URL}/api/v1/backends/${bid}/accounts" "${H_USER[@]}" -d "$body" >/dev/null
  echo "  ${role}=${username} on ${bid}"
}
upsert_account "${BACKEND_IDS[mysql]}"    app app app-pass
upsert_account "${BACKEND_IDS[postgres]}" app app app-pass
upsert_account "${BACKEND_IDS[mongo]}"    app app app-pass

cat <<EOF

================================================================
  Demo environment ready.
================================================================

Keycloak admin console : http://kc.localtest.me:18180/admin/
  user: admin   password: admin

Realm users (each can sign in to the portal):
  alice / alice    (admin — full powers)
  bob   / bob      (engineer — needs david's T1 approval to request DB access)
  carol / carol    (engineer — same)
  david / david    (validator for bob+carol; admin of dba-prod group)
  eve   / eve      (engineer with no validator yet — used to demo the rejection path)

Operator portal       : http://127.0.0.1:18080/ui/
Portal API health     : ${PORTAL_HEALTH_URL}
Portal API token (bootstrap, admin) : ${USER_TOKEN}

Try the workflow:
  1. Visit http://127.0.0.1:18080/ui/ → sign in as bob.
  2. "Request access" → pick a backend, submit. Grant lands PENDING.
  3. Sign out, sign in as david (his validator), open "Awaiting approval",
     click into the grant, Approve (T1 gate).
  4. Sign out, sign in as alice, find the grant, Approve again (T2 gate).
  5. Sign out, sign in as bob, claim credentials, connect via proxy:
       docker run --rm --network host mysql:8.0 mysql \\
         -h 127.0.0.1 -P 13306 -u bob -p<portal_password> demo

Tear down (drops the sqlite store + keycloak data):
  docker compose -f dev/compose.yml down -v
================================================================
EOF
