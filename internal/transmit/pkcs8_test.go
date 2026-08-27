package transmit

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures were written by OpenSSL 3.5, not by this code, so these tests
// prove the decrypt against what a CA toolchain actually hands out:
//
//	openssl pkcs8 -topk8 -v2 aes-256-cbc          (the modern default)
//	openssl pkcs8 -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA1
//	openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA512
//	openssl ec -aes256                            (legacy RFC 1423, refused)

const fixturePass = "correct-horse"

func decodeFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s holds no PEM block", name)
	}
	return block.Bytes
}

func TestDecryptPKCS8OpenSSLVariants(t *testing.T) {
	for _, name := range []string{"enc-aes256.key", "enc-aes128-sha1.key", "enc-sha512.key"} {
		der, err := decryptPKCS8(decodeFixture(t, name), []byte(fixturePass))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Errorf("%s decrypted to something that is not a key: %v", name, err)
			continue
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			t.Errorf("%s: got %T, want *ecdsa.PrivateKey", name, key)
		}
	}
}

func TestDecryptPKCS8RSA(t *testing.T) {
	der, err := decryptPKCS8(decodeFixture(t, "enc-rsa.key"), []byte(fixturePass))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatalf("got %T, want *rsa.PrivateKey", key)
	}
}

func TestDecryptPKCS8WrongPassphrase(t *testing.T) {
	_, err := decryptPKCS8(decodeFixture(t, "enc-aes256.key"), []byte("wrong"))
	if err == nil {
		t.Fatal("a wrong passphrase decrypted successfully")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("the error does not point at the passphrase: %v", err)
	}
}

func TestLoadClientCertificateEncrypted(t *testing.T) {
	cert, err := loadClientCertificate(
		filepath.Join("testdata", "client.crt"),
		filepath.Join("testdata", "enc-aes256.key"),
		[]byte(fixturePass))
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate loaded")
	}
}

func TestLoadClientCertificateEncryptedNeedsPassphrase(t *testing.T) {
	_, err := loadClientCertificate(
		filepath.Join("testdata", "client.crt"),
		filepath.Join("testdata", "enc-aes256.key"), nil)
	if err == nil {
		t.Fatal("an encrypted key with no passphrase was accepted")
	}
	if !strings.Contains(err.Error(), "--transmit-key-passphrase-file") {
		t.Errorf("the error does not name the flag that fixes it: %v", err)
	}
}

// The legacy format is refused with the command that re-wraps the key, not
// supported: its MD5-based KDF was deprecated out of the standard library.
func TestLoadClientCertificateRefusesRFC1423(t *testing.T) {
	_, err := loadClientCertificate(
		filepath.Join("testdata", "client.crt"),
		filepath.Join("testdata", "enc-rfc1423.key"),
		[]byte(fixturePass))
	if err == nil {
		t.Fatal("an RFC 1423 key was accepted")
	}
	if !strings.Contains(err.Error(), "openssl pkcs8 -topk8") {
		t.Errorf("the error does not say how to re-wrap the key: %v", err)
	}
}

func TestLoadClientCertificateUnencryptedWithPassphrase(t *testing.T) {
	_, err := loadClientCertificate(
		filepath.Join("testdata", "client.crt"),
		filepath.Join("testdata", "plain.key"),
		[]byte(fixturePass))
	if err == nil {
		t.Fatal("a passphrase against an unencrypted key was silently ignored")
	}
}

func TestLoadClientCertificateUnencrypted(t *testing.T) {
	cert, err := loadClientCertificate(
		filepath.Join("testdata", "client.crt"),
		filepath.Join("testdata", "plain.key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate loaded")
	}
}
