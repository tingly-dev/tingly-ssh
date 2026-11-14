package sshclient

import "testing"

func TestError(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "error with message",
			err:      &Error{Code: ErrConnectionFailed, Message: "connection timeout"},
			expected: "connection timeout",
		},
		{
			name:     "error without message",
			err:      &Error{Code: ErrAuthFailed},
			expected: errorMessages[ErrAuthFailed],
		},
		{
			name:     "unknown error code",
			err:      &Error{Code: 999},
			expected: errorMessages[ErrUnknown],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg != tt.expected {
				t.Errorf("Error() = %v, want %v", msg, tt.expected)
			}
		})
	}
}

func TestErrorFields(t *testing.T) {
	err := &Error{Code: ErrAuthFailed, Message: "auth failed"}

	// Test field access directly (gomobile auto-generates getters)
	if err.Code != ErrAuthFailed {
		t.Error("Code field access failed")
	}

	if err.Message != "auth failed" {
		t.Error("Message field access failed")
	}
}

func TestNewError(t *testing.T) {
	err := newError(ErrConnectionFailed, "test message")
	if err.Code != ErrConnectionFailed {
		t.Error("Error code mismatch")
	}
	if err.Message != "test message" {
		t.Error("Error message mismatch")
	}
}

func TestNewErrorf(t *testing.T) {
	err := newErrorf(ErrTimeout, "timeout after %d seconds", 30)
	if err.Code != ErrTimeout {
		t.Error("Error code mismatch")
	}
	if err.Message != "timeout after 30 seconds" {
		t.Errorf("Error message mismatch: %s", err.Message)
	}
}

func TestWrapError(t *testing.T) {
	// nil error
	if wrapError(ErrConnectionFailed, nil) != nil {
		t.Error("wrapError with nil should return nil")
	}

	// regular error
	err := wrapError(ErrAuthFailed, &Error{Code: ErrTimeout, Message: "timeout"})
	if err.Code != ErrTimeout {
		t.Error("Should preserve existing Error code")
	}
}

func TestKeyInfoFields(t *testing.T) {
	info := &KeyInfo{
		Format:        "RSA",
		Bits:          4096,
		Fingerprint:   "SHA256:abc123",
		PublicKey:     "ssh-rsa AAAA...",
		Comment:       "test@example.com",
		HasPassphrase: true,
	}

	// Test field access directly (gomobile auto-generates getters)
	if info.Format != "RSA" {
		t.Error("Format field access failed")
	}

	if info.Bits != 4096 {
		t.Error("Bits field access failed")
	}

	if info.Fingerprint != "SHA256:abc123" {
		t.Error("Fingerprint field access failed")
	}

	if info.PublicKey != "ssh-rsa AAAA..." {
		t.Error("PublicKey field access failed")
	}

	if info.Comment != "test@example.com" {
		t.Error("Comment field access failed")
	}

	if !info.HasPassphrase {
		t.Error("HasPassphrase field access failed")
	}
}

func TestKeyInfoString(t *testing.T) {
	info := &KeyInfo{
		Format:      "RSA",
		Bits:        4096,
		Fingerprint: "SHA256:abc123",
	}

	expected := "RSA-4096 SHA256:abc123"
	if info.String() != expected {
		t.Errorf("String() = %v, want %v", info.String(), expected)
	}
}
