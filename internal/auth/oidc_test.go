package auth

import "testing"

// The bootstrap admin email (chosen in setup) is granted admin on login even when
// an admin group is configured and the user isn't in it — solving SSO bootstrap.
func TestRoleForBootstrapAdmin(t *testing.T) {
	cases := []struct {
		name       string
		adminGroup string
		adminEmail string
		email, sub string
		groups     []string
		want       string
	}{
		{"no group -> all admin", "", "", "u@x", "s1", nil, "admin"},
		{"group gates non-member", "ops", "", "u@x", "s1", []string{"other"}, "readonly"},
		{"group member is admin", "ops", "", "u@x", "s1", []string{"ops"}, "admin"},
		{"bootstrap email elevates non-member", "ops", "op@x", "op@x", "s1", []string{"other"}, "admin"},
		{"bootstrap email case-insensitive", "ops", "op@x", "OP@X", "s1", nil, "admin"},
		{"bootstrap falls back to subject", "ops", "sub-123", "", "sub-123", nil, "admin"},
		{"non-bootstrap stays readonly", "ops", "op@x", "someone@x", "s1", nil, "readonly"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &OIDCProvider{adminGroup: c.adminGroup, adminEmail: c.adminEmail}
			if got := p.roleFor(c.email, c.sub, c.groups); got != c.want {
				t.Fatalf("roleFor(%q,%q,%v) = %q, want %q", c.email, c.sub, c.groups, got, c.want)
			}
		})
	}
}
