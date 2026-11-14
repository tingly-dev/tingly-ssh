package sshclient

import "fmt"

// Error codes for SSH operations
const (
	ErrUnknown          = 0
	ErrConnectionFailed = 1
	ErrAuthFailed       = 2
	ErrKeyInvalid       = 3
	ErrTunnelFailed     = 4
	ErrTimeout          = 5
	ErrNotConnected     = 6
	ErrAlreadyConnected = 7
	ErrInvalidConfig    = 8
)

// Error messages for each error code
var errorMessages = map[int]string{
	ErrUnknown:          "Unknown error",
	ErrConnectionFailed: "Connection failed",
	ErrAuthFailed:       "Authentication failed",
	ErrKeyInvalid:       "Invalid SSH key",
	ErrTunnelFailed:     "Tunnel operation failed",
	ErrTimeout:          "Connection timeout",
	ErrNotConnected:     "Not connected to SSH server",
	ErrAlreadyConnected: "Already connected to SSH server",
	ErrInvalidConfig:    "Invalid configuration",
}

// Error represents an error from SSH operations
// This is exported for gomobile and accessible from Kotlin/Swift
type Error struct {
	Code    int
	Message string
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if msg, ok := errorMessages[e.Code]; ok {
		return msg
	}
	return errorMessages[ErrUnknown]
}

// newError creates a new Error with code and message
func newError(code int, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// newErrorf creates a new Error with formatted message
func newErrorf(code int, format string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// wrapError wraps a Go error into an Error
func wrapError(code int, err error) *Error {
	if err == nil {
		return nil
	}
	if sshErr, ok := err.(*Error); ok {
		return sshErr
	}
	return &Error{
		Code:    code,
		Message: err.Error(),
	}
}
