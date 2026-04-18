package mongo

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestReadWireMessage(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid message",
			input:   makeWireMsg(2004, []byte("hello")),
			wantLen: headerSize + 5,
		},
		{
			name:    "header only",
			input:   makeWireMsg(2013, nil),
			wantLen: headerSize,
		},
		{
			name:    "truncated header",
			input:   []byte{0, 0, 0},
			wantErr: true,
		},
		{
			name:    "invalid length too small",
			input:   func() []byte { b := make([]byte, 16); binary.LittleEndian.PutUint32(b, 4); return b }(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			msg, err := readWireMessage(r)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(msg) != tt.wantLen {
				t.Fatalf("msg length = %d, want %d", len(msg), tt.wantLen)
			}
		})
	}
}

func TestInspectMessage_OpMsgFind(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(logger, nil)

	doc := bson.D{{Key: "find", Value: "users"}, {Key: "$db", Value: "testdb"}}
	msg := makeOpMsg(doc, false)

	h.inspectMessage(msg, h.logger, &sessionAudit{})

	logs := logBuf.String()
	if !bytes.Contains([]byte(logs), []byte(`"command":"find"`)) {
		t.Errorf("should log find command, got: %s", logs)
	}
	if !bytes.Contains([]byte(logs), []byte(`"target":"users"`)) {
		t.Errorf("should log target (collection) name, got: %s", logs)
	}
}

func TestInspectMessage_OpMsgInsert(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(logger, nil)

	doc := bson.D{{Key: "insert", Value: "orders"}, {Key: "ordered", Value: true}}
	msg := makeOpMsg(doc, false)

	h.inspectMessage(msg, h.logger, &sessionAudit{})

	if !bytes.Contains(logBuf.Bytes(), []byte("insert")) {
		t.Error("should log insert command")
	}
}

func TestInspectMessage_OpMsgWithChecksum(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(logger, nil)

	doc := bson.D{{Key: "ping", Value: 1}}
	msg := makeOpMsg(doc, true)

	h.inspectMessage(msg, h.logger, &sessionAudit{})

	if !bytes.Contains(logBuf.Bytes(), []byte("ping")) {
		t.Error("should log ping command even with checksum present")
	}
}

func TestInspectMessage_NonOpMsg(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(logger, nil)

	msg := makeWireMsg(2004, []byte("legacy"))
	h.inspectMessage(msg, h.logger, &sessionAudit{})

	if !bytes.Contains(logBuf.Bytes(), []byte("non-OP_MSG")) {
		t.Error("should log non-OP_MSG debug message")
	}
}

func TestInspectMessage_TooShort(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := NewHandler(logger, nil)

	// Should not panic on short messages
	h.inspectMessage([]byte{}, h.logger, &sessionAudit{})
	h.inspectMessage([]byte{0, 0, 0, 0}, h.logger, &sessionAudit{})
}

func TestRelayClientMessages(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(logger, nil)

	doc := bson.D{{Key: "find", Value: "test_coll"}, {Key: "$db", Value: "mydb"}}
	msg := makeOpMsg(doc, false)

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	go func() {
		clientW.Write(msg)
		clientW.Close()
	}()

	var backendBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := backendR.Read(buf)
			if n > 0 {
				backendBuf.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	_ = h.relayClientMessages(client, backend, h.logger, sessionAudit{})
	backend.Close()
	<-done // wait for reader goroutine to drain

	if backendBuf.Len() == 0 {
		t.Error("message should be forwarded to backend")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("find")) {
		t.Error("find command should appear in logs")
	}
}

// makeWireMsg builds a MongoDB wire protocol message with the given opCode and body.
func makeWireMsg(opCode int, body []byte) []byte {
	msgLen := headerSize + len(body)
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(msg[4:8], 1)    // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)   // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opCode))
	copy(msg[headerSize:], body)
	return msg
}

// makeOpMsg builds an OP_MSG with a single kind-0 section containing the given BSON document.
func makeOpMsg(doc bson.D, withChecksum bool) []byte {
	bsonDoc, err := bson.Marshal(doc)
	if err != nil {
		panic(err)
	}

	var flags uint32
	if withChecksum {
		flags = 1
	}

	// Build body: flagBits(4) + kind(1) + bson doc [+ checksum(4)]
	bodyLen := 4 + 1 + len(bsonDoc)
	if withChecksum {
		bodyLen += 4
	}

	body := make([]byte, bodyLen)
	binary.LittleEndian.PutUint32(body[0:4], flags)
	body[4] = 0 // section kind 0
	copy(body[5:], bsonDoc)
	// checksum bytes are left as zero (dummy)

	return makeWireMsg(opMsg, body)
}
