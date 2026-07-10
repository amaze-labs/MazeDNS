// Package version carries the application build version, stamped at compile
// time. This identifies the RUNNING BINARY (for now the shortened sha of the
// container image build) — it is unrelated to the replicated rules-config hash
// that agents report on config polls.
package version

import "strings"

// Version is set via
//
//	-ldflags "-X github.com/IPMaze/MazeDNS/internal/version.Version=<v>"
//
// The container build passes the git sha (or the release tag); local builds
// default to "dev".
var Version = "dev"

// Short returns the display form of the version: CI stamps images with
// "sha-<40-hex>", which is shortened to the familiar 12-character commit prefix.
// Tags and "dev" pass through unchanged.
func Short() string {
	v := Version
	if rest, ok := strings.CutPrefix(v, "sha-"); ok && len(rest) >= 12 && isHex(rest) {
		return rest[:12]
	}
	return v
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
