// Package version carries the application's release version. This identifies
// the RUNNING BINARY's release — it is unrelated to the replicated rules-config
// hash that agents report on config polls.
//
// A release rebuilds only the image whose code changed. The other image is the
// previous release's, stamped with the new version through the environment, so
// both images of a release always report the same version.
package version

import (
	"os"
	"strings"
)

// Version is set via
//
//	-ldflags "-X github.com/IPMaze/MazeDNS/internal/version.Version=<v>"
//
// The container build passes the release version; local builds default to
// "dev". MAZEDNS_IMAGE_VERSION, set by the release pipeline on an image it
// didn't rebuild, overrides it.
var Version = "dev"

// AgentBuild is the release whose agent code ships with this release: the
// release itself when the agent was rebuilt, an earlier one when only the
// control plane changed. Agents reporting this release or a later one run
// current code. Set like Version (-X …/version.AgentBuild=<v>, or
// MAZEDNS_AGENT_BUILD on a stamped image); empty when unknown (local builds),
// and then only an agent on the control plane's own version counts as current.
var AgentBuild = ""

func init() { fromEnv(os.Getenv) }

// fromEnv applies the release pipeline's stamps over the compiled-in values.
func fromEnv(getenv func(string) string) {
	if v := strings.TrimSpace(getenv("MAZEDNS_IMAGE_VERSION")); v != "" {
		Version = v
	}
	if v := strings.TrimSpace(getenv("MAZEDNS_AGENT_BUILD")); v != "" {
		AgentBuild = v
	}
}

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
