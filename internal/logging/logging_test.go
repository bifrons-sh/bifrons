package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewWithWriter_JSONShape(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOG_FORMAT", "json")

	var buf bytes.Buffer
	log := NewWithWriter(&buf, false)
	log.Info("hello", "k", "v")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}

	for _, key := range []string{"timestamp", "level", "msg", "source", "k"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing key %q in %v", key, m)
		}
	}
}

func TestStacktraceOnError(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("LOG_LEVEL", "debug")

	var buf bytes.Buffer
	log := NewWithWriter(&buf, false)

	log.Info("just info")
	if strings.Contains(buf.String(), "stacktrace") {
		t.Errorf("info-level record should not include stacktrace, got %s", buf.String())
	}

	buf.Reset()
	log.Error("boom")
	if !strings.Contains(buf.String(), "stacktrace") {
		t.Errorf("error-level record should include stacktrace, got %s", buf.String())
	}
}

func TestFormatOverrides(t *testing.T) {
	cases := []struct {
		name     string
		format   string
		isTTY    bool
		wantJSON bool
	}{
		{"auto+tty=console", "auto", true, false},
		{"auto+notty=json", "auto", false, true},
		{"force-console", "console", false, false},
		{"force-json", "json", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOG_FORMAT", tc.format)
			var buf bytes.Buffer
			log := NewWithWriter(&buf, tc.isTTY)
			log.Info("hi")
			isJSON := json.Valid(buf.Bytes()) && bytes.HasPrefix(bytes.TrimSpace(buf.Bytes()), []byte("{"))
			if isJSON != tc.wantJSON {
				t.Errorf("isJSON=%v want=%v output=%s", isJSON, tc.wantJSON, buf.String())
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"debug", "DEBUG"},
		{"INFO", "INFO"},
		{" warn ", "WARN"}, // whitespace tolerance is a feature, not a bug.
		{"error", "ERROR"},
		{"garbage", "INFO"},
	}
	for _, tc := range cases {
		in, want := tc.in, tc.want
		got := parseLevel(in).String()
		if got != want {
			t.Errorf("parseLevel(%q)=%s want %s", in, got, want)
		}
	}
}

func TestTimestampISO8601(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	var buf bytes.Buffer
	log := NewWithWriter(&buf, false)
	log.Info("x")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	ts, ok := m["timestamp"].(string)
	if !ok {
		t.Fatalf("timestamp not a string: %v", m["timestamp"])
	}
	// ISO8601 with millis and tz, e.g. 2026-04-18T12:34:56.789Z
	if !strings.Contains(ts, "T") || (!strings.HasSuffix(ts, "Z") && !strings.Contains(ts, "+")) {
		t.Errorf("timestamp %q does not look ISO8601", ts)
	}
}
