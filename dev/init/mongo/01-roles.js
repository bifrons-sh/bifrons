// Demo backend roles. mongo-proxy uses SCRAM-SHA-256 both ways and hard-codes
// `$db: admin` when re-authenticating to the backend, so the proxy-facing
// service accounts must live in the `admin` database with roles granted on
// `demo`. (Direct mongosh sessions can still auth via authSource=admin.)

const admin = db.getSiblingDB("admin");
const demo  = db.getSiblingDB("demo");

admin.createUser({
  user: "app",
  pwd: "app-pass",
  roles: [{ role: "readWrite", db: "demo" }],
  mechanisms: ["SCRAM-SHA-256"],
});

admin.createUser({
  user: "dba",
  pwd: "dba-pass",
  roles: [
    { role: "dbOwner",   db: "demo" },
    { role: "userAdmin", db: "demo" },
  ],
  mechanisms: ["SCRAM-SHA-256"],
});

// Seed data so the smoke-test query has something to return.
// runCommand insert avoids a mongosh quirk on getSiblingDB() handles.
demo.runCommand({
  insert: "hello",
  documents: [{ msg: "mongo demo row" }],
});
