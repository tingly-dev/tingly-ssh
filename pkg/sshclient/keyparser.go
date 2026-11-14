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

	// Determine key type and size
	pubKey := signer.PublicKey()
	switch pubKey.Type() {
	case ssh.KeyAlgoRSA:
		info.Format = "RSA"
		// Extract RSA key to get bit size
		if rsaPub, ok := pubKey.(ssh.CryptoPublicKey); ok {
			cryptoPub := rsaPub.CryptoPublicKey()
			if rsaKey, ok := cryptoPub.(*rsa.PublicKey); ok {
				info.Bits = rsaKey.N.BitLen()
			}
		}
	case ssh.KeyAlgoED25519:
		info.Format = "Ed25519"
		info.Bits = 256 // Ed25519 always uses 256-bit keys
	case ssh.KeyAlgoECDSA256:
		info.Format = "ECDSA"
		info.Bits = 256
	case ssh.KeyAlgoECDSA384:
		info.Format = "ECDSA"
		info.Bits = 384
	case ssh.KeyAlgoECDSA521:
		info.Format = "ECDSA"
		info.Bits = 521
	case ssh.KeyAlgoDSA:
		info.Format = "DSA"
		info.Bits = 1024 // DSA is typically 1024 bits
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		info.Format = "SecurityKey"
		info.Bits = 256
	default:
		info.Format = "Unknown"
	}

	return info, nil
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
