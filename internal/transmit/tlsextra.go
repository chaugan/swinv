package transmit

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// loadClientCertificate loads the certificate/key pair, decrypting the key
// when a passphrase was supplied.
//
// The un-encrypted path is exactly tls.LoadX509KeyPair. The encrypted path
// decrypts to a PrivateKeyInfo, re-encodes it as an ordinary PKCS#8 PEM in
// memory, and hands both PEMs to tls.X509KeyPair - so the stdlib still does
// all pairing validation and this file never grows its own opinion about
// whether a key matches a certificate.
func loadClientCertificate(certFile, keyFile string, passphrase []byte) (tls.Certificate, error) {
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304 -- operator-supplied path, by design
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transmit: reading the client key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("transmit: %s contains no PEM block", keyFile)
	}

	if block.Type != "ENCRYPTED PRIVATE KEY" && len(block.Headers) == 0 {
		// An ordinary unencrypted key. A passphrase alongside it is a
		// configuration that believes something untrue about this key, and
		// proceeding would leave that belief standing.
		if len(passphrase) > 0 {
			return tls.Certificate{}, fmt.Errorf("transmit: a key passphrase was supplied but the "+
				"key at %s is not encrypted; remove the passphrase, or encrypt the key with "+
				"`openssl pkcs8 -topk8 -v2 aes-256-cbc`", keyFile)
		}
		return tls.LoadX509KeyPair(certFile, keyFile)
	}

	if procType, ok := block.Headers["Proc-Type"]; ok && strings.Contains(procType, "ENCRYPTED") {
		// RFC 1423 "traditional" encrypted PEM: an MD5-based KDF and CBC with
		// no integrity check, deprecated out of the standard library. Not
		// supported on purpose; the fix is one openssl command away.
		return tls.Certificate{}, fmt.Errorf("transmit: the key at %s uses the legacy RFC 1423 "+
			"encryption; re-wrap it with `openssl pkcs8 -topk8 -v2 aes-256-cbc -in %s -out new.key`",
			keyFile, keyFile)
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return tls.Certificate{}, fmt.Errorf("transmit: %s holds a %q block, which is not a private key",
			keyFile, block.Type)
	}
	if len(passphrase) == 0 {
		return tls.Certificate{}, fmt.Errorf("transmit: the key at %s is encrypted; supply the "+
			"passphrase via --transmit-key-passphrase-file, a systemd credential, or $%s",
			keyFile, "SWINV_TRANSMIT_KEY_PASSPHRASE")
	}

	keyDER, err := decryptPKCS8(block.Bytes, passphrase)
	if err != nil {
		return tls.Certificate{}, err
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil {
		return tls.Certificate{}, fmt.Errorf("transmit: the decrypted key does not parse (%w); "+
			"the passphrase is probably wrong", err)
	}

	certPEM, err := os.ReadFile(certFile) // #nosec G304 -- operator-supplied path, by design
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transmit: reading the client certificate: %w", err)
	}
	plainPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, plainPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("transmit: pairing the certificate with its key: %w", err)
	}
	return cert, nil
}

// parsePins validates SPKI pins: standard base64 of a SHA-256, 32 bytes each.
func parsePins(pins []string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(pins))
	for _, p := range pins {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("transmit: pin %q is not base64: %w", p, err)
		}
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf("transmit: pin %q decodes to %d bytes; an SPKI pin is the "+
				"base64 SHA-256 of the SubjectPublicKeyInfo (32 bytes)", p, len(raw))
		}
		var pin [32]byte
		copy(pin[:], raw)
		out = append(out, pin)
	}
	return out, nil
}

// SPKIPin computes the pin of a certificate, exported so --transmit-check can
// print the pin it observed - which is exactly the string an operator needs
// to copy into the flag.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// pinVerifier verifies the peer by public key alone.
//
// Any certificate in the presented chain may match, so a site can pin its
// internal CA's key and rotate leaves freely. Chain validation is deliberately
// not also required: the flag exists precisely for the site whose CA cannot be
// made valid on this host, and "pin AND a chain you cannot have" would send
// them straight back to --transmit-insecure.
func pinVerifier(pins [][32]byte) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var observed []string
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			for _, pin := range pins {
				if sum == pin {
					return nil
				}
			}
			observed = append(observed, SPKIPin(cert))
		}
		// The observed pins are printed so a first deployment is two steps:
		// run once, copy the pin the error names, run again.
		return fmt.Errorf("transmit: no certificate in the server's chain matches a pinned key; "+
			"the server presented: %s", strings.Join(observed, ", "))
	}
}

// parseTLSMin maps the flag's spelling to the constant. Only 1.2 and 1.3
// exist on purpose: there is no flag spelling that lowers the floor.
func parseTLSMin(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("transmit: TLS minimum %q is not supported; use 1.2 or 1.3", v)
	}
}
