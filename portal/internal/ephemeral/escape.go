package ephemeral

import (
	"fmt"
	"strings"
)

// userinfoReserved is the set of characters that must be percent-encoded when
// embedding a DBA username/password in the userinfo segment of a connection
// URI (postgres:// and mongodb:// alike). They share one rule because the
// userinfo grammar is the same across schemes — there is nothing
// driver-specific about it.
//
// `%` is listed FIRST and is itself encoded (→ `%25`): the encoder is a single
// left-to-right pass, so a literal `%` in a password must become `%25` rather
// than be left bare. A bare `%` would make the URI parser read the next two
// chars as a percent-escape and decode to the WRONG secret — silent auth
// failure against the most-privileged credential.
const userinfoReserved = "%@:/?# "

// escapeUserinfo percent-encodes the reserved userinfo characters so an
// operator using a DBA credential containing `@ : /` etc. can still form a
// valid connection URI. Kept inline (vs net/url) because we only need this
// tiny subset of the encoding rules.
func escapeUserinfo(s, reserved string) string {
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
