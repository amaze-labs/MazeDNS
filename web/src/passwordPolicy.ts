// passwordPolicyError mirrors the server's auth.PasswordStrengthError so the GUI
// can show the real rule before submit rather than only a post-submit error. Keep
// in sync with internal/auth/password.go.
export const PASSWORD_RULE = 'At least 10 characters, mixing letters with digits or symbols'

export function passwordPolicyError(pw: string): string {
  if (pw.length < 10) return 'password must be at least 10 characters'
  const hasLetter = /[a-zA-Z]/.test(pw)
  const hasOther = /[^a-zA-Z]/.test(pw)
  if (!hasLetter || !hasOther) return 'password must mix letters with digits or symbols'
  return ''
}
