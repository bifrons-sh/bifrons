// Package logging configures the project-wide *slog.Logger to mirror the
// zap-based conventions used elsewhere: TTY auto-detection, ISO8601
// timestamps, caller info, and stacktraces on error-level records.
//
// Behavior is overridable via env:
//
//	LOG_LEVEL  : debug | info | warn | error  (default: info)
//	LOG_FORMAT : auto  | console | json       (default: auto)
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// New builds a *slog.Logger writing to stdout, configured per LOG_LEVEL /
// LOG_FORMAT env vars.
func New() *slog.Logger {
	return NewWithWriter(os.Stdout, isTerminal(os.Stdout))
}

// NewWithWriter is the testable seam: callers pass an explicit writer and
// declare whether it should be treated as a TTY for the "auto" format.
func NewWithWriter(w io.Writer, isTTY bool) *slog.Logger {
	level := parseLevel(getEnv("LOG_LEVEL", "info"))

	useConsole := false
	switch strings.ToLower(getEnv("LOG_FORMAT", "auto")) {
	case "console":
		useConsole = true
	case "json":
		useConsole = false
	default:
		useConsole = isTTY
	}

	opts := &slog.HandlerOptions{
		AddSource:   true,
		Level:       level,
		ReplaceAttr: replaceAttr,
	}

	var base slog.Handler
	if useConsole {
		base = slog.NewTextHandler(w, opts)
	} else {
		base = slog.NewJSONHandler(w, opts)
	}
	return slog.New(&stacktraceHandler{Handler: base})
}

// Sync mirrors zap's *Logger.Sync(). For os.Stdout this is a no-op on most
// platforms; we still attempt it so behavior matches when stdout is a file.
func Sync() {
	_ = os.Stdout.Sync()
}

func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		if t, ok := a.Value.Any().(time.Time); ok {
			return slog.String("timestamp", t.UTC().Format("2006-01-02T15:04:05.000Z07:00"))
		}
	}
	return a
}

// stacktraceHandler decorates a slog.Handler to emit a "stacktrace" attribute
// for records at LevelError or above, matching zap's AddStacktrace behavior.
type stacktraceHandler struct{ slog.Handler }

func (h *stacktraceHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		// Skip runtime.Callers + captureStack + this Handle method + slog's
		// internal dispatch + Logger.Error so the trace starts at the user's
		// call site. Trimming leaked slog frames keeps alert payloads tight.
		r.AddAttrs(slog.String("stacktrace", captureStack(5)))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *stacktraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &stacktraceHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *stacktraceHandler) WithGroup(name string) slog.Handler {
	return &stacktraceHandler{Handler: h.Handler.WithGroup(name)}
}

// captureStack returns a multi-line stack trace starting `skip` frames above
// the caller, formatted as "function\n\tfile:line".
func captureStack(skip int) string {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(skip, pcs)
	if n == 0 {
		return ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	var b strings.Builder
	for {
		f, more := frames.Next()
		b.WriteString(f.Function)
		b.WriteString("\n\t")
		b.WriteString(f.File)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(f.Line))
		b.WriteByte('\n')
		if !more {
			break
		}
	}
	return b.String()
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.ToUpper(strings.TrimSpace(s)))); err == nil {
		return l
	}
	return slog.LevelInfo
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
