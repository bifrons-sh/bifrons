package ephemeral

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoCommander is the minimal surface used by the Mongo provisioner.
// Satisfied by *mongo.Database; abstracted so unit tests can assert the
// exact command document without touching a real Mongo.
type MongoCommander interface {
	RunCommand(ctx context.Context, cmd any, opts ...options.Lister[options.RunCmdOptions]) *mongo.SingleResult
	Close(ctx context.Context) error
}

// MongoConnector opens an admin Mongo client and returns a database-scoped
// commander. The database name is the grant's target DB or "admin" when empty
// — createUser lives at the database level in Mongo.
type MongoConnector func(ctx context.Context, host string, port int, database string, dba DBACredential) (MongoCommander, error)

// DefaultMongoConnector uses go.mongodb.org/mongo-driver/v2 to connect.
func DefaultMongoConnector(ctx context.Context, host string, port int, database string, dba DBACredential) (MongoCommander, error) {
	if database == "" {
		database = "admin"
	}
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/?authSource=admin",
		escapeUserinfo(dba.Username, userinfoReserved), escapeUserinfo(dba.Password, userinfoReserved),
		host, port)
	clientOpts := options.Client().ApplyURI(uri)
	// Bound both the TCP connect AND server selection so a wedged master fails
	// fast instead of pinning the worker (see connectTimeout). Server selection
	// is the one that bites on a dead replica-set member — without a cap the
	// driver keeps re-scanning topology until the parent ctx (if any) expires.
	clientOpts.SetConnectTimeout(connectTimeout * time.Second)
	clientOpts.SetServerSelectionTimeout(connectTimeout * time.Second)
	// Security: encrypt the DBA credential on the portal->Mongo path by
	// default. The mongo driver does NOT enable TLS unless asked, so an
	// operator who forgets a `?tls=true` query param would ship admin creds in
	// cleartext. PORTAL_MONGO_TLS=false opts out for local-dev compose where
	// there's no TLS endpoint — but the opt-out only takes effect behind the
	// PORTAL_ALLOW_INSECURE_DBA_TLS gate.
	if mongoTLSEnabled(host) {
		clientOpts.SetTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("connect mongo admin: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		// Bound the cleanup Disconnect: an unreachable Mongo would otherwise
		// make teardown itself hang forever (context.Background never expires).
		discCtx, discCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer discCancel()
		_ = client.Disconnect(discCtx)
		return nil, fmt.Errorf("ping mongo admin: %w", err)
	}
	return &mongoDB{client: client, db: client.Database(database)}, nil
}

// mongoTLSEnabled reports whether to enable TLS. TLS stays on (the secure
// default) unless PORTAL_MONGO_TLS=false AND the insecure-TLS gate is set. A
// bare PORTAL_MONGO_TLS=false without the gate is ignored — we keep TLS on and
// Warn — so dropping encryption on the master cred is always a deliberate
// two-step. Either way the disable path emits an auditable Warn.
func mongoTLSEnabled(host string) bool {
	if envBoolDefault("PORTAL_MONGO_TLS", true) {
		return true
	}
	if !insecureDBATLSAllowed() {
		warnInsecureDBATLS(string(BackendMongo), host, "PORTAL_MONGO_TLS", "false",
			"override ignored: set PORTAL_ALLOW_INSECURE_DBA_TLS=true to take effect")
		return true
	}
	warnInsecureDBATLS(string(BackendMongo), host, "PORTAL_MONGO_TLS", "false",
		"explicit opt-in via PORTAL_ALLOW_INSECURE_DBA_TLS")
	return false
}

// mongoDB adapts *mongo.Database so Close is a single call that also tears
// down the client. Keeping the commander abstraction tight stops us leaking
// a generic handle the caller would forget to disconnect.
type mongoDB struct {
	client *mongo.Client
	db     *mongo.Database
}

func (m *mongoDB) RunCommand(ctx context.Context, cmd any, opts ...options.Lister[options.RunCmdOptions]) *mongo.SingleResult {
	return m.db.RunCommand(ctx, cmd, opts...)
}

func (m *mongoDB) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}

// MongoProvisioner creates a per-grant Mongo user via the createUser command.
// Mongo doesn't have a password-expiry primitive so the portal's Revoke is
// the only cleanup path — the orphan sweeper compensates for crashes.
type MongoProvisioner struct {
	lookup    DBALookup
	connector MongoConnector
}

// NewMongoProvisioner wires a Mongo driver. nil connector defaults to the
// go.mongodb.org/mongo-driver impl.
func NewMongoProvisioner(lookup DBALookup, c MongoConnector) *MongoProvisioner {
	if c == nil {
		c = DefaultMongoConnector
	}
	return &MongoProvisioner{lookup: lookup, connector: c}
}

// Provision issues:
//
//	runCommand({createUser: <user>, pwd: <pw>, roles: [{role: <role>, db: <db>}]})
//
// We run it against the grant's target database so the role binding is
// scoped to the grant, not global.
func (p *MongoProvisioner) Provision(ctx context.Context, req ProvisionRequest) (ProvisionedAccount, error) {
	dba, err := p.lookup(ctx, req.BackendID)
	if err != nil {
		return ProvisionedAccount{}, err
	}
	db := req.Database
	if db == "" {
		db = "admin"
	}
	conn, err := p.connector(ctx, req.Host, req.Port, db, dba)
	if err != nil {
		return ProvisionedAccount{}, err
	}
	defer conn.Close(context.Background())

	user, pw, idempotent, err := req.resolveCreds()
	if err != nil {
		return ProvisionedAccount{}, err
	}

	roles := bson.A{
		bson.D{{Key: "role", Value: string(req.Role)}, {Key: "db", Value: db}},
	}
	// bson.D preserves element order — Mongo's runCommand requires the
	// command name as the first key.
	cmd := bson.D{
		{Key: "createUser", Value: user},
		{Key: "pwd", Value: pw},
		{Key: "roles", Value: roles},
	}
	if err := conn.RunCommand(ctx, cmd).Err(); err != nil {
		// Deterministic-cred path (spec §8.4): on a lease-takeover the user may
		// already exist from a crashed worker. Fall back to updateUser to (re)set
		// the password + roles so the DB converges to the outbox's deterministic
		// credential. Without explicit creds we keep the legacy hard-fail.
		if idempotent && isMongoUserAlreadyExists(err) {
			update := bson.D{
				{Key: "updateUser", Value: user},
				{Key: "pwd", Value: pw},
				{Key: "roles", Value: roles},
			}
			if uerr := conn.RunCommand(ctx, update).Err(); uerr != nil {
				return ProvisionedAccount{}, fmt.Errorf("mongo updateUser: %w", uerr)
			}
		} else {
			return ProvisionedAccount{}, fmt.Errorf("mongo createUser: %w", err)
		}
	}

	return ProvisionedAccount{
		Username:    user,
		Password:    pw,
		BackendID:   req.BackendID,
		BackendType: BackendMongo,
		Host:        req.Host,
		Port:        req.Port,
		Database:    db,
		GrantID:     req.GrantID,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// Revoke issues {dropUser: <user>}. Mongo returns error code 11 (UserNotFound)
// when the user is already gone — we swallow that for idempotency.
func (p *MongoProvisioner) Revoke(ctx context.Context, acct ProvisionedAccount) error {
	dba, err := p.lookup(ctx, acct.BackendID)
	if err != nil {
		return err
	}
	conn, err := p.connector(ctx, acct.Host, acct.Port, acct.Database, dba)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())

	cmd := bson.D{{Key: "dropUser", Value: acct.Username}}
	if err := conn.RunCommand(ctx, cmd).Err(); err != nil && !isMongoUserNotFound(err) {
		return fmt.Errorf("mongo dropUser: %w", err)
	}
	return nil
}

// isMongoUserNotFound inspects a Mongo command error for code 11 (UserNotFound).
func isMongoUserNotFound(err error) bool {
	var cmdErr mongo.CommandError
	if !errors.As(err, &cmdErr) {
		return false
	}
	return cmdErr.Code == 11
}

// isMongoUserAlreadyExists inspects a Mongo command error for an
// already-exists outcome on createUser. Code 51003 is Mongo's dedicated "User
// already exists"; 11000 (DuplicateKey) covers older servers / the underlying
// system.users unique-index violation. Either signals the idempotent path
// should switch to updateUser.
func isMongoUserAlreadyExists(err error) bool {
	var cmdErr mongo.CommandError
	if !errors.As(err, &cmdErr) {
		return false
	}
	return cmdErr.Code == 51003 || cmdErr.Code == 11000
}
