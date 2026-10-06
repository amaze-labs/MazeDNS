// passwordPolicyError mirrors the server's auth.PasswordStrengthError so the GUI
// can show the real rule before submit rather than only a post-submit error. Keep
// in sync with internal/auth/password.go: the length is counted in UTF-8 bytes
// (Go's len), "letters" are ASCII a-z/A-Z only, and anything else (digits,
// symbols, spaces, accented letters) counts as "other".
export const PASSWORD_RULE = 'At least 10 characters, mixing letters with digits or symbols'

const byteLength = (s: string) => new TextEncoder().encode(s).length

export function passwordPolicyError(pw: string): string {
  if (byteLength(pw) < 10) return 'Password must be at least 10 characters'
  const hasLetter = /[a-zA-Z]/.test(pw)
  const hasOther = /[^a-zA-Z]/.test(pw)
  if (!hasLetter || !hasOther) return 'Password must mix letters with digits or symbols'
  return ''
}

export type PasswordStrength = {
  // weak: the server rejects it. ok / strong: accepted; strong is only advice.
  level: 'weak' | 'ok' | 'strong'
  label: string
  // 0..1 fill for a meter.
  fill: number
}

// passwordStrength drives the live meter. "weak" is exactly the set the server
// rejects, so a password the meter accepts is never refused on submit.
export function passwordStrength(pw: string): PasswordStrength {
  const err = passwordPolicyError(pw)
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(pw)).length
  const n = [...pw].length
  if (err) return { level: 'weak', label: err, fill: Math.min(0.3, n / 30) }
  const desc = `${n} characters, ${kinds} kind${kinds === 1 ? '' : 's'}`
  if (n >= 14 && kinds >= 3) return { level: 'strong', label: `Strong: ${desc}`, fill: 1 }
  return { level: 'ok', label: `Good: ${desc}. Longer is stronger.`, fill: 0.62 }
}
