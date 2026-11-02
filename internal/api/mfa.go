package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/IPMaze/MazeDNS/internal/auth"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// TOTP two-factor sign-in for local accounts.
//
// A correct password no longer always starts a session. When the account has
// MFA on, /api/auth/login answers with a "verify" challenge; when the policy
// (CPSettings.RequireMFA) requires MFA and the account has none yet, with a
// "setup" challenge. The challenge is a single-use bearer token, valid for
// mfaChallengeTTL and mfaMaxAttempts code guesses, that the browser sends back
// with the code (/mfa/verify) or while enrolling (/mfa/setup, /mfa/enable). A
// session starts only once a code is accepted. SSO accounts and API tokens are
// not affected.

const (
	mfaIssuer       = "MazeDNS"
	mfaChallengeTTL = 5 * time.Minute
	mfaMaxAttempts  = 5
	// Code checks made with a session (turning MFA off, new recovery codes) are
	// limited per account whatever the login rate limit is set to, since a
	// session alone must not be enough to brute-force a code.
	mfaCodeLimit  = 10
	mfaCodeWindow = 5 * time.Minute
)

// mfaEnabled reports whether the account has two-factor sign-in on.
func (s *Server) mfaEnabled(userID int64) bool {
	m, err := s.store.GetMFA(userID)
	return err == nil && m != nil && m.Secret != ""
}

// passwordLoginNeedsMFA answers a correct password with an MFA challenge when
// one is due, and reports whether it did (the caller then starts no session).
func (s *Server) passwordLoginNeedsMFA(w http.ResponseWriter, r *http.Request, u *store.User) bool {
	kind := ""
	switch {
	case s.mfaEnabled(u.ID):
		kind = "verify"
	case s.store.LoadCPSettings(cpSettingsDefaults()).RequireMFA:
		kind = "setup"
	default:
		return false
	}
	token, err := auth.NewToken()
	if err == nil {
		err = s.store.CreateMFAChallenge(token, u.ID, kind, time.Now().Add(mfaChallengeTTL).Unix())
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start sign-in")
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mfa": kind, "challenge": token, "expires_in": int(mfaChallengeTTL.Seconds()),
	})
	return true
}

// startSession signs u in: a session cookie and the user as JSON.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *store.User) {
	token, user, err := s.auth.StartSession(u.ID, u.Username, u.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start session")
		return
	}
	s.auth.SetCookie(w, r, token)
	writeJSON(w, http.StatusOK, user)
}

// checkCode checks a TOTP code or, when allowRecovery is set and the input
// isn't shaped like one, a recovery code. Either is spent on success. It returns
// whether the code was good and, for a recovery code, how many remain (-1 for a
// TOTP code).
func (s *Server) checkCode(userID int64, code string, allowRecovery bool) (ok bool, recoveryLeft int, err error) {
	m, err := s.store.GetMFA(userID)
	if err != nil || m == nil || m.Secret == "" {
		return false, -1, err
	}
	if auth.LooksLikeTOTP(code) {
		step, match := auth.VerifyTOTP(m.Secret, code, time.Now())
		if !match {
			return false, -1, nil
		}
		used, err := s.store.UseTOTPStep(userID, step)
		return used, -1, err
	}
	if !allowRecovery {
		return false, -1, nil
	}
	return s.store.UseRecoveryCode(userID, auth.HashRecoveryCode(code))
}

type mfaCodeIn struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
	Password  string `json:"password"`
}

func decodeMFA(w http.ResponseWriter, r *http.Request) (mfaCodeIn, bool) {
	var in mfaCodeIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return in, false
	}
	return in, true
}

// challengeUser spends one attempt on the challenge and returns its account,
// or writes the error and returns nil.
func (s *Server) challengeUser(w http.ResponseWriter, token, kind string) (*store.User, *store.MFAChallenge) {
	c, err := s.store.MFAChallengeAttempt(token, mfaMaxAttempts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, nil
	}
	if c == nil || c.Kind != kind {
		writeError(w, http.StatusUnauthorized, "sign-in expired or too many attempts; sign in again")
		return nil, nil
	}
	u, err := s.store.GetUserByID(c.UserID)
	if err != nil || u == nil || u.Source != "local" {
		_ = s.store.DeleteMFAChallenge(token)
		writeError(w, http.StatusUnauthorized, "sign-in expired; sign in again")
		return nil, nil
	}
	return u, c
}

// wrongCode answers a rejected code, saying how many tries the challenge has
// left (none for a session-based check).
func wrongCode(w http.ResponseWriter, c *store.MFAChallenge) {
	msg := "that code didn't work"
	if c != nil {
		if left := mfaMaxAttempts - c.Attempts; left > 0 {
			msg += fmt.Sprintf(" (%d left)", left)
		} else {
			msg += "; sign in again"
		}
	}
	writeError(w, http.StatusUnauthorized, msg)
}

// mfaVerify completes a password sign-in with a TOTP or recovery code.
func (s *Server) mfaVerify(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeMFA(w, r)
	if !ok {
		return
	}
	u, c := s.challengeUser(w, in.Challenge, "verify")
	if u == nil {
		return
	}
	good, left, err := s.checkCode(u.ID, in.Code, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !good {
		slog.Warn("mfa code rejected", "remote", clientIP(r), "user", u.Username)
		wrongCode(w, c)
		return
	}
	_ = s.store.DeleteMFAChallenge(in.Challenge)
	if left >= 0 {
		_ = s.store.AppendAudit(store.AuditEntry{
			User: u.Username, Action: "auth.mfa.recovery_code",
			Detail: fmt.Sprintf("signed in with a recovery code, %d left", left),
		})
	}
	s.startSession(w, r, u)
}

// mfaAccount resolves the account a setup step is for: the signed-in local user,
// or the one a "setup" challenge belongs to. Showing a new secret spends no
// attempt (peek); confirming it does.
func (s *Server) mfaAccount(w http.ResponseWriter, r *http.Request, challenge string, spend bool) (*store.User, *store.MFAChallenge) {
	if challenge != "" {
		if spend {
			return s.challengeUser(w, challenge, "setup")
		}
		c, err := s.store.PeekMFAChallenge(challenge)
		if err != nil || c == nil || c.Kind != "setup" {
			writeError(w, http.StatusUnauthorized, "sign-in expired; sign in again")
			return nil, nil
		}
		u, err := s.store.GetUserByID(c.UserID)
		if err != nil || u == nil || u.Source != "local" {
			writeError(w, http.StatusUnauthorized, "sign-in expired; sign in again")
			return nil, nil
		}
		return u, c
	}
	if !s.authEnabled {
		writeError(w, http.StatusNotFound, "authentication is disabled")
		return nil, nil
	}
	p, ok := s.auth.UserFromRequest(r)
	if !ok || p.Kind == auth.KindToken {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil
	}
	u, err := s.store.GetUserByID(p.ID)
	if err != nil || u == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil
	}
	if u.Source != "local" {
		writeError(w, http.StatusBadRequest, "two-factor sign-in for SSO accounts is set up at your identity provider")
		return nil, nil
	}
	return u, nil
}

// mfaSetup starts enrollment: a new secret (pending until confirmed) and its
// otpauth URI for the QR code.
func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeMFA(w, r)
	if !ok {
		return
	}
	u, _ := s.mfaAccount(w, r, in.Challenge, false)
	if u == nil {
		return
	}
	if s.mfaEnabled(u.ID) {
		writeError(w, http.StatusConflict, "two-factor sign-in is already on; turn it off first")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err == nil {
		err = s.store.SetTOTPPending(u.ID, secret)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start setup")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret, "uri": auth.TOTPURI(mfaIssuer, u.Username, secret),
	})
}

// mfaEnable confirms enrollment with a code from the app, turns MFA on and
// returns the recovery codes (shown once). Through a setup challenge it also
// signs in.
func (s *Server) mfaEnable(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeMFA(w, r)
	if !ok {
		return
	}
	if in.Challenge == "" && !s.allowCodeCheck(w, r) {
		return
	}
	u, c := s.mfaAccount(w, r, in.Challenge, true)
	if u == nil {
		return
	}
	m, err := s.store.GetMFA(u.ID)
	if err != nil || m == nil {
		writeError(w, http.StatusInternalServerError, "could not read the account")
		return
	}
	if m.Pending == "" {
		writeError(w, http.StatusConflict, "no setup in progress; start again")
		return
	}
	step, match := auth.VerifyTOTP(m.Pending, in.Code, time.Now())
	if !match {
		wrongCode(w, c)
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make recovery codes")
		return
	}
	applied, err := s.store.EnableTOTP(u.ID, m.Pending, step, hashes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !applied {
		writeError(w, http.StatusConflict, "setup was restarted elsewhere; scan the new code")
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: u.Username, Action: "auth.mfa.enabled", Detail: "two-factor sign-in turned on"})
	out := map[string]any{"recovery_codes": codes}
	if c != nil {
		// Enrolling during sign-in: this completes it.
		_ = s.store.DeleteMFAChallenge(in.Challenge)
		token, user, err := s.auth.StartSession(u.ID, u.Username, u.Role)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not start session")
			return
		}
		s.auth.SetCookie(w, r, token)
		out["user"] = user
	}
	writeJSON(w, http.StatusOK, out)
}

// allowCodeCheck applies the per-account limit on session-based code checks.
func (s *Server) allowCodeCheck(w http.ResponseWriter, r *http.Request) bool {
	p, ok := s.auth.UserFromRequest(r)
	if !ok {
		return true // mfaAccount answers 401
	}
	if !s.loginRate.allow("mfa:"+strconv.FormatInt(p.ID, 10), mfaCodeLimit, mfaCodeWindow) {
		w.Header().Set("Retry-After", strconv.Itoa(int(mfaCodeWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many code attempts; try again in a few minutes")
		return false
	}
	return true
}

// mfaDisable turns the signed-in user's MFA off. It takes the password and a
// current code (or recovery code), and is refused while the policy requires MFA.
func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeMFA(w, r)
	if !ok || !s.allowCodeCheck(w, r) {
		return
	}
	u, _ := s.mfaAccount(w, r, "", false)
	if u == nil {
		return
	}
	if s.store.LoadCPSettings(cpSettingsDefaults()).RequireMFA {
		writeError(w, http.StatusForbidden, "two-factor sign-in is required for local accounts here; an admin can reset it")
		return
	}
	if okPw, _ := auth.VerifyPassword(u.PasswordHash, in.Password); !okPw {
		writeError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	good, _, err := s.checkCode(u.ID, in.Code, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !good {
		wrongCode(w, nil)
		return
	}
	if err := s.store.DisableTOTP(u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: u.Username, Action: "auth.mfa.disabled", Detail: "two-factor sign-in turned off"})
	w.WriteHeader(http.StatusNoContent)
}

// mfaRegenerateCodes replaces the signed-in user's recovery codes; it takes a
// current TOTP code (not a recovery code: losing those is why one asks).
func (s *Server) mfaRegenerateCodes(w http.ResponseWriter, r *http.Request) {
	in, ok := decodeMFA(w, r)
	if !ok || !s.allowCodeCheck(w, r) {
		return
	}
	u, _ := s.mfaAccount(w, r, "", false)
	if u == nil {
		return
	}
	good, _, err := s.checkCode(u.ID, in.Code, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !good {
		wrongCode(w, nil)
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err == nil {
		err = s.store.SetRecoveryCodes(u.ID, hashes)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make recovery codes")
		return
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: u.Username, Action: "auth.mfa.recovery_codes", Detail: "recovery codes replaced"})
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// resetUserMFA (admin) turns another account's MFA off and signs it out
// everywhere, for someone who lost their authenticator and recovery codes. With
// the policy on, they set it up again at their next sign-in.
func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if cur, ok := s.principal(r); ok && cur.ID == id {
		writeError(w, http.StatusBadRequest, "turn off your own two-factor sign-in from your account page")
		return
	}
	target, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.Source != "local" {
		writeError(w, http.StatusBadRequest, "SSO accounts use their identity provider's two-factor sign-in")
		return
	}
	if err := s.store.DisableTOTP(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.DeleteMFAChallengesForUser(id)
	_ = s.store.DeleteSessionsForUser(id)
	_ = s.store.AppendAudit(store.AuditEntry{
		User: auditUser(s, r), Action: "user.mfa_reset", Detail: "two-factor sign-in reset for " + target.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}
