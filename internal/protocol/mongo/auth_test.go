package mongo

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestExtractSCRAMUsername(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "n,,n=alice,r=abc", "alice"},
		{"with authzid", "n,a=other,n=alice,r=abc", "alice"},
		{"escaped comma", "n,,n=al=2Cice,r=abc", "al,ice"},
		{"escaped equals", "n,,n=al=3Dice,r=abc", "al=ice"},
		{"no header", "alice", ""},
		{"missing n attr", "n,,m=alice,r=abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSCRAMUsername(tt.input)
			if got != tt.want {
				t.Fatalf("extractSCRAMUsername(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestReqIDGen_Monotonic(t *testing.T) {
	g := &reqIDGen{n: 10}
	a := g.next()
	b := g.next()
	if b <= a {
		t.Fatalf("next did not advance: %d -> %d", a, b)
	}
}

func TestSensitiveCommandsAreRedacted(t *testing.T) {
	// Lookup is case-insensitive (normalized to lowercase before checking).
	for _, cmd := range []string{"saslstart", "saslcontinue", "createuser", "updateuser"} {
		if _, ok := sensitiveCommands[cmd]; !ok {
			t.Errorf("expected %q to be in sensitiveCommands", cmd)
		}
	}
}

func TestLogBSONCommand_SensitiveRedacted(t *testing.T) {
	for _, cmd := range []string{"saslStart", "SASLSTART", "createUser", "CreateUser"} {
		t.Run(cmd, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))
			h := NewHandler(log, nil)

			doc := bson.D{{Key: cmd, Value: int32(1)}, {Key: "payload", Value: bson.Binary{Data: []byte("nonce-and-proof-not-to-leak")}}}
			raw, err := bson.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			h.logBSONCommand(raw, h.logger, &sessionAudit{})
			out := buf.String()
			if strings.Contains(out, "nonce-and-proof-not-to-leak") {
				t.Fatalf("sensitive body leaked: %s", out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Fatalf("redaction marker missing: %s", out)
			}
		})
	}
}

func TestRewriteHelloWithoutSpeculative(t *testing.T) {
	// Build a hello message containing speculativeAuthenticate.
	doc := bson.D{
		{Key: "hello", Value: int32(1)},
		{Key: "speculativeAuthenticate", Value: bson.D{{Key: "saslStart", Value: int32(1)}}},
		{Key: "$db", Value: "admin"},
	}
	msg, err := buildOpMsg(42, doc)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, ok := rewriteHelloWithoutSpeculative(msg, doc, &reqIDGen{n: 1000})
	if !ok {
		t.Fatal("expected rewrite=true when speculativeAuthenticate present")
	}
	rebuiltDoc, err := extractFirstOpMsgDoc(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	if findKey(rebuiltDoc, "speculativeAuthenticate") != nil {
		t.Fatal("speculativeAuthenticate not stripped")
	}
	if findKey(rebuiltDoc, "hello") == nil {
		t.Fatal("hello field dropped accidentally")
	}

	// No-op when absent.
	docNoSpec := bson.D{{Key: "hello", Value: int32(1)}}
	msg2, _ := buildOpMsg(43, docNoSpec)
	_, ok2 := rewriteHelloWithoutSpeculative(msg2, docNoSpec, &reqIDGen{n: 1000})
	if ok2 {
		t.Fatal("expected rewrite=false when no speculativeAuthenticate")
	}
}
