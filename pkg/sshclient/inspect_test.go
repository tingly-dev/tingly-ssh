package sshclient

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pemString(t *testing.T, b *pem.Block, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(b))
}

func TestInspectKey(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _ := ssh.NewPublicKey(edKey.Public())
	ecPub, _ := ssh.NewPublicKey(ecKey.Public())
	rsaPub, _ := ssh.NewPublicKey(rsaKey.Public())

	openssh := func(k any) string {
		b, err := ssh.MarshalPrivateKey(k, "c")
		return pemString(t, b, err)
	}
	opensshEnc := func(k any) string {
		b, err := ssh.MarshalPrivateKeyWithPassphrase(k, "c", []byte("pw"))
		return pemString(t, b, err)
	}
	pkcs8 := func(k any) string {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		return pemString(t, &pem.Block{Type: "PRIVATE KEY", Bytes: der}, err)
	}
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	//lint:ignore SA1019 legacy PEM encryption is what old keys use
	legacyEnc, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), []byte("pw"), x509.PEMCipherAES128)

	tests := []struct {
		name, key, container, keyType string
		bits                          int
		encrypted                     bool
		fp                            ssh.PublicKey // nil: no fingerprint expected
		unsupported                   string        // substring; "" means usable
	}{
		{"openssh ed25519", openssh(edKey), "OpenSSH", "Ed25519", 256, false, edPub, ""},
		{"openssh ed25519 encrypted", opensshEnc(edKey), "OpenSSH", "Ed25519", 256, true, edPub, ""},
		{"openssh ecdsa", openssh(ecKey), "OpenSSH", "ECDSA", 384, false, ecPub, ""},
		{"openssh rsa encrypted", opensshEnc(rsaKey), "OpenSSH", "RSA", 2048, true, rsaPub, ""},
		{"pkcs8 ed25519", pkcs8(edKey), "PKCS8", "Ed25519", 256, false, edPub, ""},
		{"pkcs8 ecdsa", pkcs8(ecKey), "PKCS8", "ECDSA", 384, false, ecPub, ""},
		{"pkcs8 rsa", pkcs8(rsaKey), "PKCS8", "RSA", 2048, false, rsaPub, ""},
		{"pkcs1 rsa", pemString(t, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, nil), "PKCS1", "RSA", 2048, false, rsaPub, ""},
		{"pkcs1 rsa legacy encrypted", pemString(t, legacyEnc, err), "PKCS1", "RSA", 0, true, nil, ""},
		{"sec1 ecdsa", pemString(t, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}, nil), "SEC1", "ECDSA", 384, false, ecPub, ""},
		{"pkcs8 encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n", "PKCS8-Encrypted", "Unknown", 0, true, nil, "PKCS#8"},
		{"putty", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n", "PuTTY", "Ed25519", 0, false, nil, "PuTTY"},
		{"public key", string(ssh.MarshalAuthorizedKey(edPub)), "PublicKey", "Ed25519", 256, false, edPub, "public key"},
		{"garbage", "hello", "Unknown", "Unknown", 0, false, nil, "Unrecognized"},
	}

	p := NewKeyParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ki := p.InspectKey(tt.key)
			if ki.Container != tt.container || ki.KeyType != tt.keyType || ki.Bits != tt.bits || ki.Encrypted != tt.encrypted {
				t.Errorf("got %+v, want container=%s type=%s bits=%d encrypted=%v", ki, tt.container, tt.keyType, tt.bits, tt.encrypted)
			}
			if tt.fp != nil && ki.Fingerprint != ssh.FingerprintSHA256(tt.fp) {
				t.Errorf("fingerprint %q, want %q", ki.Fingerprint, ssh.FingerprintSHA256(tt.fp))
			}
			if tt.unsupported == "" && ki.Unsupported != "" {
				t.Errorf("unexpectedly unsupported: %s", ki.Unsupported)
			}
			if tt.unsupported != "" && !strings.Contains(ki.Unsupported, tt.unsupported) {
				t.Errorf("Unsupported = %q, want it to mention %q", ki.Unsupported, tt.unsupported)
			}
			// Whatever InspectKey accepts, Connect's parser must load
			if ki.Unsupported == "" {
				var err error
				if ki.Encrypted {
					_, err = ssh.ParsePrivateKeyWithPassphrase([]byte(tt.key), []byte("pw"))
				} else {
					_, err = ssh.ParsePrivateKey([]byte(tt.key))
				}
				if err != nil {
					t.Errorf("accepted key does not load: %v", err)
				}
			}
		})
	}
}
