package store

import "testing"

// DeleteMeta removes only the named key and is a no-op for a missing one.
func TestDeleteMeta(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetMeta("gone", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta("kept", "v"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMeta("gone"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteMeta("never-set"); err != nil {
		t.Fatalf("delete missing key: %v", err)
	}
	if v, err := s.GetMeta("gone"); err != nil || v != "" {
		t.Errorf("deleted key = %q, %v; want empty", v, err)
	}
	if v, err := s.GetMeta("kept"); err != nil || v != "v" {
		t.Errorf("other key = %q, %v; want %q", v, err, "v")
	}
}
