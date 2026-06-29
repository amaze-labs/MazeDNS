//go:build !unix

package resolver

import "syscall"

// reusePortControl is a no-op where SO_REUSEPORT isn't available; the server then
// runs with a single UDP socket (the first bind succeeds, extras fail and are
// skipped).
func reusePortControl(_, _ string, _ syscall.RawConn) error { return nil }
