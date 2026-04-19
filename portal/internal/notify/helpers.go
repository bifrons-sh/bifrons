package notify

import (
	"strings"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// displayOr returns u.DisplayName falling back to u.Username — used so emails
// read "Alice Smith" rather than "alice" when a display name is populated.
func displayOr(u domain.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

// firstNonEmpty returns the first non-empty string, or "" if all are empty.
func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}

// domainPart returns the substring after the last "@", or "<unknown>" when
// there's no "@". Used so error logs surface only the recipient domain, not
// the full address — the full recipient lands on the Info-level success log
// where it's intended audit.
func domainPart(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "<unknown>"
}

// escapeHTML is a minimal HTML-entity encoder sufficient for interpolating
// user-controlled strings (display name, backend name, reason) into the
// HTML email body. Not using html/template because the message shape is
// small and fixed; a dedicated function keeps the email path allocation-lean.
func escapeHTML(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
