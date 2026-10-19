package version

import "testing"

func TestShort(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	for in, want := range map[string]string{
		"dev":    "dev",
		"v1.2.3": "v1.2.3",
		"sha-0123456789abcdef0123456789abcdef01234567": "0123456789ab", // CI image stamp -> short commit
		"sha-not-hex": "sha-not-hex", // unrecognized shape passes through
	} {
		Version = in
		if got := Short(); got != want {
			t.Errorf("Short(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFromEnv(t *testing.T) {
	origV, origA := Version, AgentBuild
	t.Cleanup(func() { Version, AgentBuild = origV, origA })

	Version, AgentBuild = "0.136.4", "0.136.4"
	fromEnv(func(string) string { return "" })
	if Version != "0.136.4" || AgentBuild != "0.136.4" {
		t.Fatalf("no stamp changed the build: %q %q", Version, AgentBuild)
	}

	env := map[string]string{"MAZEDNS_IMAGE_VERSION": "0.137.0", "MAZEDNS_AGENT_BUILD": " 0.136.4 "}
	Version, AgentBuild = "0.136.4", ""
	fromEnv(func(k string) string { return env[k] })
	if Version != "0.137.0" || AgentBuild != "0.136.4" {
		t.Fatalf("stamp: got %q %q, want 0.137.0 0.136.4", Version, AgentBuild)
	}
}
