//go:build unix

package resolver

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortControl enables SO_REUSEPORT (and SO_REUSEADDR) on the socket before
// bind, so multiple UDP sockets can share the same port and the kernel spreads
// inbound packets across them — parallelizing the otherwise single-threaded read
// loop across cores.
//
// SO_REUSEPORT lives in golang.org/x/sys/unix (the std syscall package omits it on
// Linux), so we use that for portability across linux/darwin/bsd.
func reusePortControl(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
			sockErr = e
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
