package mongo

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// echoBackend spawns a goroutine that reads one OP_MSG and writes a canned response.
func echoBackend(t *testing.T, respDoc bson.D) (client net.Conn, stop func()) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		// Read the inbound OP_MSG header + body to drain the pipe.
		_, err := readWireMessage(b)
		if err != nil {
			return
		}
		resp, err := buildOpMsgResponse(9999, 0, respDoc)
		if err != nil {
			return
		}
		_, _ = b.Write(resp)
	}()
	return a, func() {
		_ = a.Close()
		<-done
	}
}

func TestBuildOpMsgResponse_SetsResponseTo(t *testing.T) {
	doc := bson.D{{Key: "ok", Value: float64(1)}}
	msg, err := buildOpMsgResponse(11, 22, doc)
	if err != nil {
		t.Fatal(err)
	}
	if got := getRequestID(msg); got != 11 {
		t.Errorf("requestID = %d, want 11", got)
	}
	// responseTo lives at msg[8:12]
	if msg[8] != 22 || msg[9] != 0 || msg[10] != 0 || msg[11] != 0 {
		t.Errorf("responseTo bytes = % x, want 22 00 00 00", msg[8:12])
	}
}

func TestWriteOpMsg_RoundTrip(t *testing.T) {
	client, stop := echoBackend(t, bson.D{{Key: "ok", Value: float64(1)}, {Key: "roundtrip", Value: true}})
	defer stop()

	if err := writeOpMsg(client, 42, bson.D{{Key: "ping", Value: int32(1)}}); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	resp, err := readWireMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := extractFirstOpMsgDoc(resp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := findKey(doc, "roundtrip").(bool); !ok || !v {
		t.Fatalf("missing roundtrip=true; got doc=%v", doc)
	}
}

func TestSendSASLResponse_Format(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer a.Close()
		msg, err := readWireMessage(a)
		if err != nil {
			done <- nil
			return
		}
		done <- msg
	}()

	ids := &reqIDGen{n: 100}
	if err := sendSASLResponse(b, 77, 3, true, []byte("payload-bytes"), ids); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()

	msg := <-done
	if msg == nil {
		t.Fatal("peer never received msg")
	}
	doc, err := extractFirstOpMsgDoc(msg)
	if err != nil {
		t.Fatal(err)
	}
	if convID, _ := findKey(doc, "conversationId").(int32); convID != 3 {
		t.Errorf("conversationId = %v", findKey(doc, "conversationId"))
	}
	if d, _ := findKey(doc, "done").(bool); !d {
		t.Error("done != true")
	}
	bin, ok := findKey(doc, "payload").(bson.Binary)
	if !ok || string(bin.Data) != "payload-bytes" {
		t.Errorf("payload = %v", findKey(doc, "payload"))
	}
}

func TestSendErrorResponse_Shape(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		defer a.Close()
		msg, _ := readWireMessage(a)
		done <- msg
	}()

	// Fabricate an "original request" to extract reqID from.
	origReq, _ := buildOpMsg(555, bson.D{{Key: "saslStart", Value: int32(1)}})
	ids := &reqIDGen{n: 100}
	if err := sendErrorResponse(b, origReq, "bad things", ids); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()

	msg := <-done
	doc, _ := extractFirstOpMsgDoc(msg)
	if ok, _ := findKey(doc, "ok").(float64); ok != 0 {
		t.Errorf("ok = %v, want 0", findKey(doc, "ok"))
	}
	if m, _ := findKey(doc, "errmsg").(string); m != "bad things" {
		t.Errorf("errmsg = %q", m)
	}
	if code, _ := findKey(doc, "code").(int32); code != 18 {
		t.Errorf("code = %d, want 18", code)
	}
}

func TestForwardAndRelay(t *testing.T) {
	// Backend: read one msg, write a canned response.
	bClient, bSrv := net.Pipe()
	defer bClient.Close()

	var gotBackend []byte
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		defer bSrv.Close()
		msg, err := readWireMessage(bSrv)
		if err != nil {
			return
		}
		gotBackend = msg
		resp, _ := buildOpMsgResponse(9, getRequestID(msg), bson.D{{Key: "ok", Value: float64(1)}})
		_, _ = bSrv.Write(resp)
	}()

	// Client: we'll just capture whatever the proxy relays back.
	cProxy, cClient := net.Pipe()
	gotClient := make(chan []byte, 1)
	go func() {
		defer cClient.Close()
		msg, err := readWireMessage(cClient)
		if err != nil {
			gotClient <- nil
			return
		}
		gotClient <- msg
	}()

	original, _ := buildOpMsg(1234, bson.D{{Key: "ping", Value: int32(1)}})
	if err := forwardAndRelay(cProxy, bClient, original); err != nil {
		t.Fatal(err)
	}
	<-backendDone

	if len(gotBackend) == 0 || getRequestID(gotBackend) != 1234 {
		t.Errorf("backend didn't get original msg: %x", gotBackend)
	}
	relayed := <-gotClient
	if relayed == nil {
		t.Fatal("client never received relayed response")
	}
	doc, _ := extractFirstOpMsgDoc(relayed)
	if ok, _ := findKey(doc, "ok").(float64); ok != 1 {
		t.Errorf("relayed ok = %v", findKey(doc, "ok"))
	}
}


// Ensure the test helper ctx/logger imports aren't stranded.
var (
	_ = context.Background
	_ = slog.Default
	_ = os.Stdout
)
