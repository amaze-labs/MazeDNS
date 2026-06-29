//go:build unix

package resolver

import "syscall"

// reusePortControl enables SO_REUSEPORT (and SO_REUSEADDR) on the socket before
// bind, so multiple UDP sockets can share the same port and the kernel spreads
// inbound packets across them — parallelizing the otherwise single-threaded read
// loop across cores.
func reusePortControl(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); e != nil {
			sockErr = e
			return
		}
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
