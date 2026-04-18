package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
)

func TestReadStartupMessage(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid startup",
			input:   makeStartupMsg(196608, map[string]string{"user": "test"}),
			wantLen: -1, // just check no error
		},
		{
			name:    "ssl request",
			input:   makeSSLRequest(),
			wantLen: 8,
		},
		{
			name:    "truncated",
			input:   []byte{0, 0},
			wantErr: true,
		},
		{
			name:    "invalid length too small",
			input:   []byte{0, 0, 0, 2},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			msg, err := readStartupMessage(r)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantLen > 0 && len(msg) != tt.wantLen {
				t.Fatalf("msg length = %d, want %d", len(msg), tt.wantLen)
			}
		})
	}
}

func TestReadMessage(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "simple query",
			input:   makePGMessage('Q', []byte("SELECT 1\x00")),
			wantLen: 1 + 4 + 9,
		},
		{
			name:    "truncated header",
			input:   []byte{'Q', 0},
			wantErr: true,
		},
		{
			name:    "invalid length too small",
			input:   []byte{'Q', 0, 0, 0, 2},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			msg, err := readMessage(r)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantLen > 0 && len(msg) != tt.wantLen {
				t.Fatalf("msg length = %d, want %d", len(msg), tt.wantLen)
			}
		})
	}
}

func TestMessagePayload(t *testing.T) {
	msg := makePGMessage('Q', []byte("SELECT\x00"))
	payload := messagePayload(msg)
	if string(payload) != "SELECT\x00" {
		t.Fatalf("payload = %q, want %q", string(payload), "SELECT\x00")
	}

	if p := messagePayload([]byte{'Q', 0, 0, 0, 4}); p != nil {
		t.Fatal("expected nil for header-only message")
	}
}

func TestTrimNull(t *testing.T) {
	if got := string(trimNull([]byte("hello\x00"))); got != "hello" {
		t.Fatalf("trimNull = %q, want %q", got, "hello")
	}
	if got := string(trimNull([]byte("hello"))); got != "hello" {
		t.Fatalf("trimNull (no null) = %q, want %q", got, "hello")
	}
	if got := trimNull([]byte{}); len(got) != 0 {
		t.Fatal("trimNull(empty) should be empty")
	}
}

func TestExtractParseQuery(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "named destination",
			payload: []byte("stmt1\x00SELECT 42\x00\x00\x00"),
			want:    "SELECT 42",
		},
		{
			name:    "empty destination",
			payload: []byte("\x00INSERT INTO t VALUES($1)\x00\x00\x00"),
			want:    "INSERT INTO t VALUES($1)",
		},
		{
			name:    "truncated before query",
			payload: []byte("stmt1\x00"),
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractParseQuery(tt.payload)
			if got != tt.want {
				t.Fatalf("extractParseQuery = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRelayClientMessages_SimpleQuery(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := NewHandler(logger, nil)

	queryMsg := makePGMessage('Q', []byte("SELECT 42\x00"))
	termMsg := makePGMessage('X', nil)

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	go func() {
		clientW.Write(append(queryMsg, termMsg...))
		clientW.Close()
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := backendR.Read(buf); err != nil {
				return
			}
		}
	}()

	_ = h.relayClientMessages(client, backend, h.logger, sessionAudit{})
	backend.Close()
	backendR.Close()

	if !bytes.Contains(logBuf.Bytes(), []byte("SELECT 42")) {
		t.Error("query should appear in logs")
	}
}

func TestRelayClientMessages_Parse(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := NewHandler(logger, nil)

	parsePayload := []byte("\x00INSERT INTO t\x00\x00\x00") // empty dest, query, 0 params
	parseMsg := makePGMessage('P', parsePayload)
	termMsg := makePGMessage('X', nil)

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	go func() {
		clientW.Write(append(parseMsg, termMsg...))
		clientW.Close()
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := backendR.Read(buf); err != nil {
				return
			}
		}
	}()

	_ = h.relayClientMessages(client, backend, h.logger, sessionAudit{})
	backend.Close()
	backendR.Close()

	if !bytes.Contains(logBuf.Bytes(), []byte("INSERT INTO t")) {
		t.Error("prepared statement query should appear in logs")
	}
}

func TestRecordQueryTruncation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	h := NewHandler(logger, nil)
	sess := sessionAudit{}

	h.recordQuery(logger, &sess, "query", []byte("SELECT 1"))
	if !bytes.Contains(buf.Bytes(), []byte(`"truncated":false`)) {
		t.Error("short query should not be truncated")
	}

	buf.Reset()

	long := make([]byte, maxLogQuery+100)
	for i := range long {
		long[i] = 'A'
	}
	h.recordQuery(logger, &sess, "query", long)
	if !bytes.Contains(buf.Bytes(), []byte(`"truncated":true`)) {
		t.Error("long query should be truncated")
	}
}

func TestHandleStartup_SSLReject(t *testing.T) {
	h := NewHandler(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), nil)

	// Client sends SSLRequest then a real startup message
	sslReq := makeSSLRequest()
	startup := makeStartupMsg(196608, map[string]string{"user": "test"})

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	// Client side: write SSLRequest, read response, then send startup.
	// Keep clientW open — proxy needs to forward auth messages back through it.
	go func() {
		defer clientW.Close()
		clientW.Write(sslReq)

		// Read 'N' response
		resp := make([]byte, 1)
		if _, err := clientW.Read(resp); err != nil {
			return
		}
		if resp[0] != 'N' {
			return
		}

		// Send real startup
		clientW.Write(startup)

		// Drain forwarded auth messages from proxy so writes don't block
		buf := make([]byte, 4096)
		for {
			if _, err := clientW.Read(buf); err != nil {
				return
			}
		}
	}()

	// Backend side: read forwarded startup, send AuthOk + ReadyForQuery
	go func() {
		defer backendR.Close()
		buf := make([]byte, 4096)
		backendR.Read(buf) // read startup message

		// Send AuthenticationOk (R, type=0)
		authOk := makePGMessage('R', []byte{0, 0, 0, 0})
		backendR.Write(authOk)

		// Send ReadyForQuery
		rdy := makePGMessage('Z', []byte{'I'})
		backendR.Write(rdy)
	}()

	log := h.logger
	result, _, err := h.handleStartup(context.Background(), client, backend, log)
	if err != nil {
		t.Fatalf("handleStartup failed: %v", err)
	}
	// Should return the same conn (no TLS upgrade)
	if result != client {
		t.Error("expected same conn back (no TLS upgrade)")
	}
}

// makePGMessage builds a PostgreSQL wire protocol message: [type][4-byte length BE][payload].
func makePGMessage(msgType byte, payload []byte) []byte {
	length := 4 + len(payload)
	msg := make([]byte, 1+length)
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], uint32(length))
	copy(msg[5:], payload)
	return msg
}

// makeStartupMsg builds a PostgreSQL startup message.
func makeStartupMsg(version uint32, params map[string]string) []byte {
	var buf bytes.Buffer
	buf.Write(make([]byte, 4)) // placeholder for length
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, version)
	buf.Write(b)
	for k, v := range params {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(v)
		buf.WriteByte(0)
	}
	buf.WriteByte(0) // terminator
	msg := buf.Bytes()
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// makeSSLRequest builds a PostgreSQL SSLRequest message.
func makeSSLRequest() []byte {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], sslRequestCode)
	return msg
}
