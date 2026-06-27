package auth

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/IPMaze/MazeDNS/internal/config"
)

// OIDCProvider wraps OIDC discovery, token exchange, and id_token verification.
type OIDCProvider struct {
	oauth       *oauth2.Config
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
	adminGroup  string
}

// OIDCClaims is the subset of id_token claims MazeDNS uses.
type OIDCClaims struct {
	Subject  string
	Username string
	Email    string
	Role     string
	Picture  string // avatar URL (profile_picture / picture claim)
}

// NewOIDC performs discovery against the issuer and builds the provider.
func NewOIDC(ctx context.Context, cfg config.OIDC) (*OIDCProvider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("oidc: issuer and client_id are required")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	scopes := append([]string{oidc.ScopeOpenID, "profile", "email"}, cfg.Scopes...)
	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	return &OIDCProvider{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		groupsClaim: groupsClaim,
		adminGroup:  cfg.AdminGroup,
	}, nil
}

// AuthCodeURL returns the provider's authorization URL for the given state.
func (p *OIDCProvider) AuthCodeURL(state string) string {
	return p.oauth.AuthCodeURL(state)
}

// RedirectURL returns the configured redirect_uri (the value sent to the
// provider; it must match what's registered there exactly).
func (p *OIDCProvider) RedirectURL() string {
	return p.oauth.RedirectURL
}

// Exchange swaps an authorization code for verified id_token claims.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*OIDCClaims, error) {
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("oidc: no id_token in token response")
	}
	idToken, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	username, _ := claims["preferred_username"].(string)
	if username == "" {
		username = email
	}
	if username == "" {
		username = sub
	}
	// Avatar: prefer Authentik's "profile_picture", fall back to the standard
	// OIDC "picture" claim.
	picture, _ := claims["profile_picture"].(string)
	if picture == "" {
		picture, _ = claims["picture"].(string)
	}

	role := "admin" // no admin group configured -> all SSO users are admins
	if p.adminGroup != "" {
		role = "readonly"
		for _, g := range toStringSlice(claims[p.groupsClaim]) {
			if g == p.adminGroup {
				role = "admin"
				break
			}
		}
	}
	return &OIDCClaims{Subject: sub, Username: username, Email: email, Role: role, Picture: picture}, nil
}

func toStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
