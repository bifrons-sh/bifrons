package postgres

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/xdg-go/scram"
)

// serverEndpointBinding computes a PostgreSQL-compliant
// tls-server-end-point channel binding (RFC 5929 §4) from a *server-side*
// *tls.Conn and the leaf certificate that server presented to the client.
//
// Why we roll our own instead of scram.NewTLSServerEndpointBinding:
// xdg-go/scram pulls the leaf cert from tls.ConnectionState.PeerCertificates,
// which on the server side of a non-mTLS handshake is empty. We therefore
// thread the server's own leaf cert from the tls.Config through the handler
// and hash it here with the algorithm RFC 5929 prescribes.
//
// leaf may come from tls.Config.Certificates[0] parsed at handler init, or
// from a per-connection GetCertificate hook. If leaf is nil, we fall back to
// the xdg-go helper (useful on the client side of a pair, for symmetry in
// unit tests).
func serverEndpointBinding(conn *tls.Conn, leaf *x509.Certificate) (scram.ChannelBinding, error) {
	if leaf == nil {
		state := conn.ConnectionState()
		return scram.NewTLSServerEndpointBinding(&state)
	}
	h, err := hashForCertSigAlg(leaf.SignatureAlgorithm)
	if err != nil {
		return scram.ChannelBinding{}, err
	}
	h.Write(leaf.Raw)
	return scram.ChannelBinding{
		Type: scram.ChannelBindingTLSServerEndpoint,
		Data: h.Sum(nil),
	}, nil
}

// hashForCertSigAlg selects the hash per RFC 5929 §4.1: MD5/SHA-1 upgrade to
// SHA-256; anything else maps to the native hash of the signature algorithm.
// Unknown algorithms are an error rather than a silent SHA-256 fallback so we
// surface provisioning mistakes loudly.
func hashForCertSigAlg(alg x509.SignatureAlgorithm) (hash.Hash, error) {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return sha256.New(), nil
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS, x509.PureEd25519:
		return sha256.New(), nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384.New(), nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512.New(), nil
	default:
		return nil, fmt.Errorf("tls-server-end-point: unsupported cert signature algorithm %v", alg)
	}
}

// parseLeaf extracts the first leaf x509 certificate from a tls.Certificate,
// parsing DER if the caller did not pre-populate Leaf. Returns nil if the
// chain is empty — caller decides whether that is fatal.
func parseLeaf(c *tls.Certificate) (*x509.Certificate, error) {
	if c == nil || len(c.Certificate) == 0 {
		return nil, nil
	}
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// fingerprintShort returns a short hex prefix of a cert SHA-256 for logging
// without leaking the full hash. Used only for debug breadcrumbs; the full
// cb-data stays redacted.
func fingerprintShort(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:4])
}
