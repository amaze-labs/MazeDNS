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
