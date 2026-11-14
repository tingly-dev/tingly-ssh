// Package sshclient is a TCP SSH client with port forwarding (local, remote,
// SOCKS5) and key utilities. It is the shared SSH core for tingly-ssh
// consumers; mobile apps wrap it with a thin gomobile shell.
//
// The exported API deliberately sticks to gomobile-friendly shapes (basic
// types, pointer structs, callback interfaces, at most two return values) so
// that a shell can re-export it without reimplementing anything.
package sshclient
