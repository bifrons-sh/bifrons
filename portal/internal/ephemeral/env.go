package ephemeral

import (
	"log/slog"
	"os"
	"strconv"
)

// envAllowInsecureDBATLS is the explicit opt-in gate guarding every TLS
// verification relaxation on the DBA (master-cred) connection. A non-verifying
// override (pg sslmode in {disable,allow,prefer,require}, mysql/mongo TLS
// false) only takes effect when this is true — otherwise we keep the secure
// default and Warn that the override was ignored. This makes "ship admin creds
// without cert verification" a deliberate, auditable two-step rather than a
// single env var an operator can flip by accident.
const envAllowInsecureDBATLS = "PORTAL_ALLOW_INSECURE_DBA_TLS"

// connectTimeout bounds the initial TCP+auth handshake to every backend.
//
// WHY a hard cap: the DBA credential is used on every Provision/Revoke, and a
// wedged master backend (e.g. a failed-over primary still accepting connections
// but never completing the handshake) would otherwise pin the provisioning
// worker forever. Fail fast so the worker can surface the error and move on
// rather than hang on a dead backend.
const connectTimeout = 10

// insecureDBATLSAllowed reports whether the operator has explicitly opted into
// disabling TLS verification on the DBA connection. When a connector wants to
// honour a non-verifying override it must gate on this; if it returns false the
// connector keeps the secure default and Warns that the override was ignored.
func insecureDBATLSAllowed() bool {
	return envBoolDefault(envAllowInsecureDBATLS, false)
}

// warnInsecureDBATLS emits the auditable Warn for a DBA connection whose cert
// verification has been disabled. host lets an auditor pin which backend is
// affected; reason distinguishes an honoured opt-out from an ignored override.
func warnInsecureDBATLS(backend, host, knob, value, reason string) {
	slog.Warn("dba_tls_verification_disabled",
		slog.String("backend", backend),
		slog.String("host", host),
		slog.String("knob", knob),
		slog.String("value", value),
		slog.String("reason", reason),
	)
}

// envBoolDefault reads a boolean operator override from the environment,
// returning def when the var is unset or unparseable. Used for the TLS opt-out
// knobs (PORTAL_MYSQL_TLS / PORTAL_MONGO_TLS) and the insecure-TLS gate
// (PORTAL_ALLOW_INSECURE_DBA_TLS) so the secure default holds unless an
// operator explicitly relaxes it. The portal's config package keeps its env
// helpers unexported, so we read os.Getenv inline here.
func envBoolDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
