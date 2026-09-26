package store

import "testing"

// LocalConfigVersion always equals a fresh ConfigVersion, whatever changed the
// agent's tables, and reuses the persisted value only while they are intact.
func TestLocalConfigVersionTracksTables(t *testing.T) {
	s := openTestStore(t)
	check := func(stage string) {
		t.Helper()
		got, err := s.LocalConfigVersion()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := s.ConfigVersion()
		if got != want {
			t.Fatalf("%s: LocalConfigVersion = %q, ConfigVersion = %q", stage, got, want)
		}
	}
	check("empty")

	rules := []Rule{{Action: "deny", Domain: "ads.example.lan", Category: "ads", Enabled: true}}
	rws := []Rewrite{{Domain: "nas.example.lan", RRType: "A", Value: "192.0.2.10", Enabled: true}}
	if err := s.ApplySnapshot(rules, rws); err != nil {
		t.Fatal(err)
	}
	check("apply")

	if err := s.SetClusterForwarders([]ForwardSpec{{Suffix: "corp.example.lan", Upstreams: []string{"192.0.2.53:53"}}}); err != nil {
		t.Fatal(err)
	}
	check("forwarders only")

	// Same row counts, different content: MAX(id) still moves.
	if err := s.ApplySnapshot([]Rule{{Action: "deny", Domain: "other.example.lan", Category: "ads", Enabled: true}}, rws); err != nil {
		t.Fatal(err)
	}
	check("same counts")

	if err := s.ApplySnapshot(nil, nil); err != nil {
		t.Fatal(err)
	}
	check("emptied")

	// Recorded after an apply, the value is reused while the tables are intact.
	if err := s.ApplySnapshot(rules, nil); err != nil {
		t.Fatal(err)
	}
	v, err := s.RecordLocalConfigVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(localVersionMeta, "persisted"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LocalConfigVersion(); got != "persisted" {
		t.Fatalf("intact tables should reuse the persisted version, got %q (fresh %q)", got, v)
	}
	// A half-written record (fingerprint cleared) never validates.
	if err := s.SetMeta(localFingerprintMeta, ""); err != nil {
		t.Fatal(err)
	}
	check("cleared fingerprint")
}
