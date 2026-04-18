package mysql

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
)

func TestReadPacket(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int
		wantErr bool
	}{
		{
			name:    "simple COM_QUERY",
			input:   makePacket(0, []byte{comQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}),
			wantLen: 4 + 1 + 8,
		},
		{
			name:    "empty payload",
			input:   makePacket(0, []byte{}),
			wantLen: 4,
		},
		{
			name:    "truncated header",
			input:   []byte{0x05, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			pkt, err := readPacket(r)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pkt) != tt.wantLen {
				t.Fatalf("packet length = %d, want %d", len(pkt), tt.wantLen)
			}
		})
	}
}

func TestPacketPayload(t *testing.T) {
	pkt := makePacket(0, []byte{comQuery, 'S', 'E', 'L', 'E', 'C', 'T'})
	payload := packetPayload(pkt)
	if payload[0] != comQuery {
		t.Fatalf("first payload byte = %d, want %d", payload[0], comQuery)
	}
	if string(payload[1:]) != "SELECT" {
		t.Fatalf("payload = %q, want %q", string(payload[1:]), "SELECT")
	}
}

func TestPacketPayloadTooShort(t *testing.T) {
	if p := packetPayload([]byte{0, 0, 0, 0}); p != nil {
		t.Fatal("expected nil for 4-byte packet")
	}
	if p := packetPayload([]byte{0, 0}); p != nil {
		t.Fatal("expected nil for 2-byte packet")
	}
}

func TestWritePacket(t *testing.T) {
	pkt := makePacket(1, []byte{comQuery, 'X'})
	var buf bytes.Buffer
	if err := writePacket(&buf, pkt); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), pkt) {
		t.Fatal("written bytes mismatch")
	}
}

func TestRecordQueryTruncation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	h := NewHandler(logger)
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

func TestRelayClientPackets_Query(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := NewHandler(logger)

	query := []byte("SELECT 42")
	queryPkt := makePacket(0, append([]byte{comQuery}, query...))
	quitPkt := makePacket(1, []byte{comQuit})

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	go func() {
		clientW.Write(append(queryPkt, quitPkt...))
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

	err := h.relayClientPackets(client, backend, h.logger, sessionAudit{})
	if err != nil {
		t.Fatal(err)
	}
	backend.Close()
	backendR.Close()
	<-done

	if !bytes.Contains(backendBuf.Bytes(), query) {
		t.Error("query should be forwarded to backend")
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("SELECT 42")) {
		t.Error("query should appear in logs")
	}
}

func TestRelayClientPackets_Prepare(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := NewHandler(logger)

	stmt := []byte("INSERT INTO t VALUES (?)")
	prepPkt := makePacket(0, append([]byte{comStmtPrepare}, stmt...))
	quitPkt := makePacket(1, []byte{comQuit})

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	go func() {
		clientW.Write(append(prepPkt, quitPkt...))
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

	_ = h.relayClientPackets(client, backend, h.logger, sessionAudit{})
	backend.Close()
	backendR.Close()

	if !bytes.Contains(logBuf.Bytes(), []byte("INSERT INTO t VALUES (?)")) {
		t.Error("prepared statement should appear in logs")
	}
}

func TestRelayClientPackets_InitDB(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h := NewHandler(logger)

	initPkt := makePacket(0, append([]byte{comInitDB}, []byte("mydb")...))
	quitPkt := makePacket(1, []byte{comQuit})

	client, clientW := net.Pipe()
	backend, backendR := net.Pipe()

	go func() {
		clientW.Write(append(initPkt, quitPkt...))
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

	_ = h.relayClientPackets(client, backend, h.logger, sessionAudit{})
	backend.Close()
	backendR.Close()

	if !bytes.Contains(logBuf.Bytes(), []byte("mydb")) {
		t.Error("database name should appear in logs")
	}
}

// makePacket builds a MySQL wire protocol packet.
func makePacket(seq byte, payload []byte) []byte {
	length := len(payload)
	pkt := make([]byte, 4+length)
	pkt[0] = byte(length)
	pkt[1] = byte(length >> 8)
	pkt[2] = byte(length >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}
