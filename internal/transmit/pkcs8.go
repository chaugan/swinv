package transmit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 -- PBKDF2's default PRF per RFC 8018, not a signature
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// This file decrypts PKCS#8 encrypted private keys (RFC 5958 wrapping, PBES2
// from RFC 8018) - the "BEGIN ENCRYPTED PRIVATE KEY" PEM that
// `openssl pkcs8 -topk8 -v2 aes-256-cbc` writes, which is what a CA-running
// estate actually hands out.
//
// It exists because the standard library declines to: x509.ParsePKCS8PrivateKey
// does not decrypt, and x509.DecryptPEMBlock handles only the legacy RFC 1423
// format and was deprecated in Go 1.16 for being built on MD5 with no
// integrity check. Implementing PBES2 here is ~200 lines over encoding/asn1
// and stdlib crypto, and it removes the alternative nobody should pick:
// telling operators to strip the passphrase from their key.
//
// Deliberately narrow: PBKDF2 with HMAC-SHA1/224/256/384/512, AES-CBC
// 128/192/256. That covers every key modern OpenSSL and every mainstream CA
// toolchain emits. Legacy schemes (RC2, DES, 3DES, scrypt) are refused by
// name, with the command that re-wraps the key.

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivation algorithmIdentifier
	Encryption    algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	// KeyLength is optional in the spec; when absent the cipher decides.
	KeyLength int                 `asn1:"optional"`
	PRF       algorithmIdentifier `asn1:"optional"`
}

// decryptPKCS8 turns the DER of an EncryptedPrivateKeyInfo into the DER of
// the PrivateKeyInfo inside it.
func decryptPKCS8(der, passphrase []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("transmit: parsing the encrypted key: %w", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("transmit: parsing the encrypted key: %d trailing byte(s)", len(rest))
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("transmit: the key is encrypted with %v, not PBES2; re-wrap it with "+
			"`openssl pkcs8 -topk8 -v2 aes-256-cbc`", info.Algorithm.Algorithm)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("transmit: parsing the PBES2 parameters: %w", err)
	}
	if !params.KeyDerivation.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("transmit: the key derivation is %v, not PBKDF2 (scrypt is not "+
			"supported); re-wrap the key with `openssl pkcs8 -topk8 -v2 aes-256-cbc`",
			params.KeyDerivation.Algorithm)
	}

	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivation.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("transmit: parsing the PBKDF2 parameters: %w", err)
	}
	if kdf.IterationCount < 1 {
		return nil, fmt.Errorf("transmit: PBKDF2 iteration count %d is not usable", kdf.IterationCount)
	}

	prf, err := prfHash(kdf.PRF)
	if err != nil {
		return nil, err
	}

	keyLen, err := cipherKeyLen(params.Encryption.Algorithm)
	if err != nil {
		return nil, err
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != keyLen {
		return nil, fmt.Errorf("transmit: the PBKDF2 key length %d disagrees with the cipher's %d",
			kdf.KeyLength, keyLen)
	}

	var iv []byte
	if _, err := asn1.Unmarshal(params.Encryption.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("transmit: parsing the cipher IV: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("transmit: the cipher IV is %d bytes, want %d", len(iv), aes.BlockSize)
	}
	if len(info.EncryptedData) == 0 || len(info.EncryptedData)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("transmit: the encrypted key is %d bytes, not a whole number of blocks",
			len(info.EncryptedData))
	}

	key := pbkdf2.Key(passphrase, kdf.Salt, kdf.IterationCount, keyLen, prf)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("transmit: building the cipher: %w", err)
	}
	plain := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, info.EncryptedData)

	unpadded, ok := stripPKCS7(plain)
	if !ok {
		// CBC has no integrity check, so a wrong passphrase surfaces as
		// garbage padding. Say what it almost certainly means.
		return nil, fmt.Errorf("transmit: decrypting the key failed; the passphrase is probably wrong")
	}
	return unpadded, nil
}

func prfHash(prf algorithmIdentifier) (func() hash.Hash, error) {
	switch {
	case prf.Algorithm == nil, prf.Algorithm.Equal(oidHMACSHA1):
		// Absent means hmacWithSHA1, per RFC 8018.
		return sha1.New, nil
	case prf.Algorithm.Equal(oidHMACSHA224):
		return sha256.New224, nil
	case prf.Algorithm.Equal(oidHMACSHA256):
		return sha256.New, nil
	case prf.Algorithm.Equal(oidHMACSHA384):
		return sha512.New384, nil
	case prf.Algorithm.Equal(oidHMACSHA512):
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("transmit: unsupported PBKDF2 PRF %v", prf.Algorithm)
	}
}

func cipherKeyLen(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, nil
	case oid.Equal(oidAES192CBC):
		return 24, nil
	case oid.Equal(oidAES256CBC):
		return 32, nil
	default:
		return 0, fmt.Errorf("transmit: the key is encrypted with cipher %v; only AES-CBC is "+
			"supported - re-wrap it with `openssl pkcs8 -topk8 -v2 aes-256-cbc`", oid)
	}
}

// stripPKCS7 removes and validates the padding in constant time over the pad
// bytes. The constant time is cheap to have and CBC padding oracles are a
// famous enough failure that not having it would need explaining.
func stripPKCS7(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, false
	}
	good := 1
	for _, c := range b[len(b)-n:] {
		good &= subtle.ConstantTimeByteEq(c, byte(n))
	}
	if good != 1 {
		return nil, false
	}
	return b[:len(b)-n], true
}
