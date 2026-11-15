package sshclient

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyParser provides SSH key parsing functionality
// Supports all major key formats: RSA, Ed25519, ECDSA, DSA
// Supports PEM, PKCS#8, and OpenSSH private key formats
type KeyParser struct{}

// NewKeyParser creates a new SSH key parser instance
func NewKeyParser() *KeyParser {
	return &KeyParser{}
}

// ParseKey parses a private key and returns information about it
// Supports multiple formats:
//   - PKCS#1 RSA: -----BEGIN RSA PRIVATE KEY-----
//   - PKCS#8:     -----BEGIN PRIVATE KEY-----
//   - OpenSSH:    -----BEGIN OPENSSH PRIVATE KEY-----
//   - ECDSA:      -----BEGIN EC PRIVATE KEY-----
//   - DSA:        -----BEGIN DSA PRIVATE KEY-----
func (p *KeyParser) ParseKey(keyContent, passphrase string) (*KeyInfo, error) {
	keyContent = strings.TrimSpace(keyContent)

	// Decode PEM block
	block, _ := pem.Decode([]byte(keyContent))
	if block == nil {
		return nil, newError(ErrKeyInvalid, "failed to decode PEM block from key content")
	}

	// Check if key is encrypted - note: keyBytes not needed, we parse with ssh library directly
	var err error

	if x509.IsEncryptedPEMBlock(block) {
		// Legacy encrypted PEM (PKCS#1/PKCS#5)
		if passphrase == "" {
			return &KeyInfo{HasPassphrase: true}, newError(ErrKeyInvalid, "key is encrypted but no passphrase provided")
		}
		// Decryption will be handled by ssh.ParsePrivateKeyWithPassphrase
	}

	// Try parsing with passphrase first for OpenSSH format
	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(keyContent), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(keyContent))
	}

	if err != nil {
		// Check if it's a passphrase error
		if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "passphrase") {
			return &KeyInfo{HasPassphrase: true}, newError(ErrKeyInvalid, "key requires passphrase")
		}
		return nil, wrapError(ErrKeyInvalid, err)
	}

	// Extract key information
	info := &KeyInfo{
		PublicKey:     string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
		HasPassphrase: passphrase != "",
	}

	// Trim newline from public key
	info.PublicKey = strings.TrimSpace(info.PublicKey)

	info.Format, info.Bits = describeKey(signer.PublicKey())

	return info, nil
}

// describeKey names a public key's type and size, using the KeyInfo.Format /
// KeyInspection.KeyType vocabulary.
func describeKey(pub ssh.PublicKey) (string, int) {
	switch pub.Type() {
	case ssh.KeyAlgoRSA:
		if cp, ok := pub.(ssh.CryptoPublicKey); ok {
			if rsaKey, ok := cp.CryptoPublicKey().(*rsa.PublicKey); ok {
				return "RSA", rsaKey.N.BitLen()
			}
		}
		return "RSA", 0
	case ssh.KeyAlgoED25519:
		return "Ed25519", 256
	case ssh.KeyAlgoECDSA256:
		return "ECDSA", 256
	case ssh.KeyAlgoECDSA384:
		return "ECDSA", 384
	case ssh.KeyAlgoECDSA521:
		return "ECDSA", 521
	case ssh.KeyAlgoDSA:
		return "DSA", 1024
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return "SecurityKey", 256
	default:
		return "Unknown", 0
	}
}

// opensshCiphers are the private-key ciphers x/crypto/ssh can decrypt.
var opensshCiphers = map[string]bool{"none": true, "aes256-ctr": true, "aes256-cbc": true}

// InspectKey reports what a private key is and whether connecting with it can
// work, without needing its passphrase. It never fails: problems are reported
// in Unsupported, worded for showing to the user.
//
// The answer matches what Connect does with the key: a key without an
// Unsupported reason loads with ParsePrivateKey[WithPassphrase].
func (p *KeyParser) InspectKey(keyContent string) *KeyInspection {
	keyContent = strings.TrimSpace(keyContent)
	ki := &KeyInspection{Container: "Unknown", KeyType: "Unknown"}

	if strings.HasPrefix(keyContent, "PuTTY-User-Key-File-") {
		ki.Container = "PuTTY"
		header, _, _ := strings.Cut(keyContent, "\n")
		if _, algo, ok := strings.Cut(header, ":"); ok {
			ki.KeyType = algoKeyType(strings.TrimSpace(algo))
		}
		ki.Encrypted = !strings.Contains(keyContent, "Encryption: none")
		ki.Unsupported = "PuTTY .ppk keys aren't supported. In PuTTYgen use Conversions → Export OpenSSH key"
		return ki
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyContent)); err == nil {
		return publicKeyInspection(ki, pub)
	}

	block, _ := pem.Decode([]byte(keyContent))
	if block == nil {
		ki.Unsupported = "Unrecognized key format"
		return ki
	}

	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return inspectOpenSSH(ki, block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		ki.Container = "PKCS8-Encrypted"
		ki.Encrypted = true
		ki.Unsupported = "Encrypted PKCS#8 keys aren't supported. Convert with: ssh-keygen -p -f <keyfile>"
		return ki
	case "SSH2 PUBLIC KEY", "PUBLIC KEY":
		ki.Container = "PublicKey"
		ki.Unsupported = publicKeyMistake
		return ki
	case "RSA PRIVATE KEY":
		ki.Container, ki.KeyType = "PKCS1", "RSA"
	case "EC PRIVATE KEY":
		ki.Container, ki.KeyType = "SEC1", "ECDSA"
	case "DSA PRIVATE KEY":
		ki.Container, ki.KeyType = "DSA", "DSA"
	case "PRIVATE KEY":
		ki.Container = "PKCS8"
	default:
		ki.Unsupported = fmt.Sprintf("Unsupported key type %q", block.Type)
		return ki
	}

	// Legacy PEM encryption hides everything, public key included, until decrypted
	if x509.IsEncryptedPEMBlock(block) {
		ki.Encrypted = true
		return ki
	}
	signer, err := ssh.ParsePrivateKey([]byte(keyContent))
	if err != nil {
		if ki.Container == "PKCS8" {
			// x509 rejects PKCS#8 algorithms SSH can't use (DSA, Ed448, ...)
			ki.Unsupported = "Unsupported PKCS#8 key algorithm. Use an Ed25519, ECDSA or RSA key"
		} else {
			ki.Unsupported = "Invalid key: " + err.Error()
		}
		return ki
	}
	ki.KeyType, ki.Bits = describeKey(signer.PublicKey())
	ki.Fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
	return ki
}

const publicKeyMistake = "This is a public key. Paste the private key instead (e.g. ~/.ssh/id_ed25519, not id_ed25519.pub)"

func publicKeyInspection(ki *KeyInspection, pub ssh.PublicKey) *KeyInspection {
	ki.Container = "PublicKey"
	ki.KeyType, ki.Bits = describeKey(pub)
	ki.Fingerprint = ssh.FingerprintSHA256(pub)
	ki.Unsupported = publicKeyMistake
	return ki
}

func algoKeyType(algo string) string {
	switch {
	case algo == ssh.KeyAlgoRSA:
		return "RSA"
	case algo == ssh.KeyAlgoED25519:
		return "Ed25519"
	case strings.HasPrefix(algo, "ecdsa-sha2-"):
		return "ECDSA"
	case algo == ssh.KeyAlgoDSA:
		return "DSA"
	case strings.HasPrefix(algo, "sk-"):
		return "SecurityKey"
	default:
		return "Unknown"
	}
}

// inspectOpenSSH reads the openssh-key-v1 header: magic, cipher, kdf, kdf
// options, key count, then the public key, which is never encrypted.
func inspectOpenSSH(ki *KeyInspection, data []byte) *KeyInspection {
	ki.Container = "OpenSSH"
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(data, []byte(magic)) {
		ki.Unsupported = "Key data is corrupted"
		return ki
	}
	var hdr struct {
		Cipher  string
		Kdf     string
		KdfOpts string
		NumKeys uint32
		PubKey  []byte
		Rest    []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data[len(magic):], &hdr); err != nil || hdr.NumKeys != 1 {
		ki.Unsupported = "Key data is corrupted"
		return ki
	}
	ki.Encrypted = hdr.Cipher != "none"

	pub, err := ssh.ParsePublicKey(hdr.PubKey)
	if err != nil {
		var w struct {
			Algo string
			Rest []byte `ssh:"rest"`
		}
		if ssh.Unmarshal(hdr.PubKey, &w) == nil {
			ki.KeyType = algoKeyType(w.Algo)
			ki.Unsupported = fmt.Sprintf("Unsupported key algorithm %q", w.Algo)
		} else {
			ki.Unsupported = "Key data is corrupted"
		}
		return ki
	}
	ki.KeyType, ki.Bits = describeKey(pub)
	ki.Fingerprint = ssh.FingerprintSHA256(pub)

	switch {
	case ki.KeyType == "SecurityKey":
		ki.Unsupported = "FIDO security keys need the hardware token and can't be used here"
	case ki.KeyType == "DSA":
		ki.Unsupported = "DSA keys in OpenSSH format aren't supported (DSA is deprecated; use Ed25519)"
	case !opensshCiphers[hdr.Cipher]:
		ki.Unsupported = fmt.Sprintf("Key encryption %q isn't supported. Re-encrypt with: ssh-keygen -p -Z aes256-ctr -f <keyfile>", hdr.Cipher)
	case !ki.Encrypted:
		// Catch damage in the private half, which the header doesn't cover
		if _, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: data})); err != nil {
			ki.Unsupported = "Invalid key: " + err.Error()
		}
	}
	return ki
}

// GetSupportedFormats returns a list of supported key formats
func (p *KeyParser) GetSupportedFormats() []string {
	return []string{
		"RSA (PKCS#1 PEM)",
		"RSA (PKCS#8 PEM)",
		"Ed25519 (OpenSSH)",
		"ECDSA P-256/P-384/P-521",
		"DSA (legacy)",
		"OpenSSH encrypted",
	}
}

// ValidateKey validates if the key content is a valid SSH private key
func (p *KeyParser) ValidateKey(keyContent string) error {
	_, err := p.ParseKey(keyContent, "")
	if err != nil {
		return err
	}
	return nil
}

// IsEncrypted checks if a private key is encrypted
func (p *KeyParser) IsEncrypted(keyContent string) bool {
	keyContent = strings.TrimSpace(keyContent)

	block, _ := pem.Decode([]byte(keyContent))
	if block == nil {
		return false
	}

	// Check for legacy PEM encryption
	if x509.IsEncryptedPEMBlock(block) {
		return true
	}

	// Check for OpenSSH format encryption
	if block.Type == "OPENSSH PRIVATE KEY" {
		// Try parsing without passphrase
		_, err := ssh.ParsePrivateKey([]byte(keyContent))
		if err != nil {
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "passphrase") {
				return true
			}
		}
	}

	return false
}

// DetectKeyFormat detects the format of the private key
func (p *KeyParser) DetectKeyFormat(keyContent string) string {
	keyContent = strings.TrimSpace(keyContent)

	// Check for PEM header
	if strings.Contains(keyContent, "-----BEGIN") {
		switch {
		case strings.Contains(keyContent, "-----BEGIN OPENSSH PRIVATE KEY"):
			return "OpenSSH"
		case strings.Contains(keyContent, "-----BEGIN RSA PRIVATE KEY"):
			return "RSA-PKCS1"
		case strings.Contains(keyContent, "-----BEGIN EC PRIVATE KEY"):
			return "ECDSA"
		case strings.Contains(keyContent, "-----BEGIN DSA PRIVATE KEY"):
			return "DSA"
		case strings.Contains(keyContent, "-----BEGIN PRIVATE KEY"):
			return "PKCS8"
		case strings.Contains(keyContent, "-----BEGIN ENCRYPTED PRIVATE KEY"):
			return "PKCS8-Encrypted"
		}
	}

	return "Unknown"
}

// ConvertToPKCS8 converts a private key to PKCS#8 format
// Useful for compatibility with some systems
func (p *KeyParser) ConvertToPKCS8(keyContent, passphrase string) (string, error) {
	keyContent = strings.TrimSpace(keyContent)

	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(keyContent), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(keyContent))
	}

	if err != nil {
		return "", wrapError(ErrKeyInvalid, err)
	}

	// Get the underlying crypto private key
	cryptoPub := signer.PublicKey().(ssh.CryptoPublicKey)
	cryptoKey := cryptoPub.CryptoPublicKey()

	// Get the private key using reflection on the signer
	// This is a bit tricky, but we can use the x509 package

	// Actually, let's parse the key differently
	block, _ := pem.Decode([]byte(keyContent))
	if block == nil {
		return "", newError(ErrKeyInvalid, "failed to decode PEM block")
	}

	var keyBytes []byte
	if x509.IsEncryptedPEMBlock(block) {
		if passphrase == "" {
			return "", newError(ErrKeyInvalid, "key is encrypted but no passphrase provided")
		}
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return "", wrapError(ErrKeyInvalid, err)
		}
	} else if block.Type == "OPENSSH PRIVATE KEY" {
		// For OpenSSH format, we already have the parsed key
		// Generate a new PKCS#8 PEM
		_ = cryptoKey // We'll use the public key info
		// This is complex for OpenSSH, skip for now
		return "", newError(ErrKeyInvalid, "OpenSSH format conversion not yet supported")
	} else {
		keyBytes = block.Bytes
	}

	// Try to parse as various key types
	var privKey interface{}

	// Try PKCS#1 RSA
	if privKey, err = x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		// Convert to PKCS#8
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return "", wrapError(ErrKeyInvalid, err)
		}
		var buf bytes.Buffer
		err = pem.Encode(&buf, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		})
		if err != nil {
			return "", wrapError(ErrKeyInvalid, err)
		}
		return buf.String(), nil
	}

	// Try ECDSA
	if privKey, err = x509.ParseECPrivateKey(keyBytes); err == nil {
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return "", wrapError(ErrKeyInvalid, err)
		}
		var buf bytes.Buffer
		err = pem.Encode(&buf, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		})
		if err != nil {
			return "", wrapError(ErrKeyInvalid, err)
		}
		return buf.String(), nil
	}

	// Try PKCS#8
	if privKey, err = x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		// Already PKCS#8, just re-encode
		var buf bytes.Buffer
		err = pem.Encode(&buf, &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err != nil {
			return "", wrapError(ErrKeyInvalid, err)
		}
		return buf.String(), nil
	}

	return "", newError(ErrKeyInvalid, "unsupported key format for conversion")
}

// GenerateKeyPair generates a new SSH key pair
// keyType: "rsa", "ed25519", "ecdsa"
// bits: key size (for RSA: 2048 or 4096, for ECDSA: 256, 384, or 521)
func (p *KeyParser) GenerateKeyPair(keyType string, bits int, comment string) (*KeyPairResult, error) {
	var pubKey ssh.PublicKey
	var signer ssh.Signer
	var privateKey string

	switch strings.ToLower(keyType) {
	case "rsa":
		if bits != 2048 && bits != 4096 {
			bits = 4096
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, wrapError(ErrKeyInvalid, err)
		}
		signer, err = ssh.NewSignerFromKey(rsaKey)
		if err != nil {
			return nil, wrapError(ErrKeyInvalid, err)
		}
		pubKey = signer.PublicKey()

		// Encode in PEM format (PKCS#1)
		privBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		var privBuf bytes.Buffer
		pem.Encode(&privBuf, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		})
		privateKey = privBuf.String()

	case "ed25519":
		// For Ed25519, we use the OpenSSH format
		// This requires using the ssh package's native support
		_, priv, err := p.generateEd25519Key()
		if err != nil {
			return nil, wrapError(ErrKeyInvalid, err)
		}
		return &KeyPairResult{PrivateKey: priv, PublicKey: ""}, nil

	case "ecdsa":
		// ECDSA generation not implemented in this version
		return nil, newError(ErrKeyInvalid, "ECDSA key generation not yet implemented")

	default:
		return nil, newError(ErrKeyInvalid, fmt.Sprintf("unsupported key type: %s", keyType))
	}

	// Format public key
	pubKeyStr := string(ssh.MarshalAuthorizedKey(pubKey))
	if comment != "" {
		pubKeyStr = fmt.Sprintf("%s %s\n", strings.TrimSpace(pubKeyStr), comment)
	}

	return &KeyPairResult{PrivateKey: privateKey, PublicKey: pubKeyStr}, nil
}

// generateEd25519Key generates an Ed25519 key in OpenSSH format
func (p *KeyParser) generateEd25519Key() (publicKey, privateKey string, err error) {
	// For simplicity, return an error indicating this should be done via ssh-keygen
	return "", "", newError(ErrKeyInvalid, "Ed25519 key generation: please use ssh-keygen -t ed25519")
}

// CalculateFingerprint calculates the SHA256 fingerprint of a public key
func (p *KeyParser) CalculateFingerprint(publicKey string) (string, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return "", wrapError(ErrKeyInvalid, err)
	}
	return ssh.FingerprintSHA256(pubKey), nil
}

// ExtractPublicKey extracts the public key from a private key
func (p *KeyParser) ExtractPublicKey(privateKey, passphrase string) (string, error) {
	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(privateKey))
	}

	if err != nil {
		return "", wrapError(ErrKeyInvalid, err)
	}

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// Helper: base64 encode for fingerprints
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Helper: SHA256 hash
func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
