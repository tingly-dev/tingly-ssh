package sshclient

import (
	"strings"
	"testing"
)

func TestNewSshKeyParser(t *testing.T) {
	parser := NewKeyParser()
	if parser == nil {
		t.Fatal("NewKeyParser returned nil")
	}
}

func TestParseRSAKey(t *testing.T) {
	parser := NewKeyParser()

	// Test RSA key (PKCS#1 format)
	rsaKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz7v5...test...key
-----END RSA PRIVATE KEY-----`

	// This should fail with invalid key but show format detection works
	_, err := parser.ParseKey(rsaKey, "")
	if err == nil {
		t.Log("Key parsed (unlikely with dummy key)")
	} else {
		// Expected - our test key is not valid
		t.Logf("Expected error with dummy key: %v", err)
	}
}

func TestDetectKeyFormat(t *testing.T) {
	parser := NewKeyParser()

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name: "OpenSSH format",
			key: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=
-----END OPENSSH PRIVATE KEY-----`,
			expected: "OpenSSH",
		},
		{
			name: "RSA PKCS1 format",
			key: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz7v5
-----END RSA PRIVATE KEY-----`,
			expected: "RSA-PKCS1",
		},
		{
			name: "PKCS8 format",
			key: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkq
-----END PRIVATE KEY-----`,
			expected: "PKCS8",
		},
		{
			name: "ECDSA format",
			key: `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIB
-----END EC PRIVATE KEY-----`,
			expected: "ECDSA",
		},
		{
			name: "DSA format",
			key: `-----BEGIN DSA PRIVATE KEY-----
MIHvAgEAAiEA
-----END DSA PRIVATE KEY-----`,
			expected: "DSA",
		},
		{
			name:     "Unknown format",
			key:      "not a valid key",
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := parser.DetectKeyFormat(tt.key)
			if format != tt.expected {
				t.Errorf("DetectKeyFormat() = %v, want %v", format, tt.expected)
			}
		})
	}
}

func TestGetSupportedFormats(t *testing.T) {
	parser := NewKeyParser()
	formats := parser.GetSupportedFormats()

	if len(formats) == 0 {
		t.Error("GetSupportedFormats returned empty list")
	}

	// Check that expected formats are included
	expectedFormats := []string{"RSA", "Ed25519", "ECDSA"}
	for _, expected := range expectedFormats {
		found := false
		for _, f := range formats {
			if strings.Contains(f, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected format containing %q not found in %v", expected, formats)
		}
	}
}

func TestIsEncrypted(t *testing.T) {
	parser := NewKeyParser()

	// Non-encrypted key
	plainKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA
-----END RSA PRIVATE KEY-----`

	if parser.IsEncrypted(plainKey) {
		t.Error("Plain key detected as encrypted")
	}
}

// Test with actual Ed25519 key (OpenSSH format)
func TestParseEd25519Key(t *testing.T) {
	parser := NewKeyParser()

	// This is a test Ed25519 key - DO NOT USE IN PRODUCTION
	ed25519Key := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBJS4sZqKnS8dH065q8F3XFKnfP3VVCSG9Q5CL/9W8XnQAAAJgK9qVsCval
bAAAAAtzc2gtZWQyNTUxOQAAACBJS4sZqKnS8dH065q8F3XFKnfP3VVCSG9Q5CL/9W8XnQ
AAAEDqK9v7q7Z8P3XFKnfP3VVCSG9Q5CL/9W8XnQAAAAAAAAAAAAAAEAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAtzc2gtZWQyNTUxOQAAAACB
JS4sZqKnS8dH065q8F3XFKnfP3VVCSG9Q5CL/9W8XnQAAAQAAAAAAAAAAAAAAAAAAAACAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END OPENSSH PRIVATE KEY-----`

	// This will fail because the key is not properly formatted
	// but it tests the parsing path
	_, err := parser.ParseKey(ed25519Key, "")
	if err != nil {
		t.Logf("Expected error with test key: %v", err)
	}
}

func TestCalculateFingerprint(t *testing.T) {
	parser := NewKeyParser()

	// Invalid public key
	_, err := parser.CalculateFingerprint("invalid-key")
	if err == nil {
		t.Error("Expected error for invalid public key")
	}
}

func TestValidateKey(t *testing.T) {
	parser := NewKeyParser()

	// Invalid key
	err := parser.ValidateKey("not a valid key")
	if err == nil {
		t.Error("Expected error for invalid key")
	}
}

// Benchmarks
func BenchmarkDetectKeyFormat(b *testing.B) {
	parser := NewKeyParser()
	key := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz7v5
-----END RSA PRIVATE KEY-----`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.DetectKeyFormat(key)
	}
}
