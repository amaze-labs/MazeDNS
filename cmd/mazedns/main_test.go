package main

import "testing"

func TestListCategory(t *testing.T) {
	cases := map[string]string{
		"blocklist.hosts":              "blocklist",
		"/etc/mazedns/stevenblack.txt": "stevenblack",
		"OISD.hosts":                   "oisd",
		"no-ext":                       "no-ext",
		"":                             "blocklist",
		".hidden":                      "hidden",
	}
	for in, want := range cases {
		if got := listCategory(in); got != want {
			t.Errorf("listCategory(%q) = %q, want %q", in, got, want)
		}
	}
}
