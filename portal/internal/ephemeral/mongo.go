package ephemeral

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
		mongoEscape(dba.Username), mongoEscape(dba.Password), host, port)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect mongo admin: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo admin: %w", err)
	}
	return &mongoDB{client: client, db: client.Database(database)}, nil
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

// mongoEscape escapes the userinfo-reserved characters the same way pg does.
// We can't share code because mongo's URI is mongo-driver's territory; tiny
// dup is simpler than factoring for two callers.
func mongoEscape(s string) string {
	const reserved = "@:/?# "
	b := strings.Builder{}
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(reserved, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
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

	user, err := newUsername()
	if err != nil {
		return ProvisionedAccount{}, err
	}
	pw, err := newPassword()
	if err != nil {
		return ProvisionedAccount{}, err
	}

	// bson.D preserves element order — Mongo's runCommand requires the
	// command name as the first key.
	cmd := bson.D{
		{Key: "createUser", Value: user},
		{Key: "pwd", Value: pw},
		{Key: "roles", Value: bson.A{
			bson.D{{Key: "role", Value: string(req.Role)}, {Key: "db", Value: db}},
		}},
	}
	if err := conn.RunCommand(ctx, cmd).Err(); err != nil {
		return ProvisionedAccount{}, fmt.Errorf("mongo createUser: %w", err)
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
