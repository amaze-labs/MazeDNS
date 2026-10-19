#!/usr/bin/env sh
# Prints the release notes (markdown) for the commits in FROM..TO, grouped by
# their conventional-commit type, for the GitHub release of a version:
#
#   release-notes.sh <previous-tag-or-empty> [<to>]
#
# "feat" -> Features, "fix" -> Fixes, "perf" -> Performance, a "!" -> Breaking
# changes, anything else -> Other changes. The type prefix is dropped and a
# scope becomes a bold lead-in ("**api:** …"). Merge commits are skipped.
# The control plane shows these notes as the changelog of an update.
set -eu

from="${1:-}"
to="${2:-HEAD}"
if [ -n "$from" ]; then range="${from}..${to}"; else range="$to"; fi

tmp="${TMPDIR:-/tmp}/notes.$$"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT
: > "$tmp/breaking"; : > "$tmp/feat"; : > "$tmp/fix"; : > "$tmp/perf"; : > "$tmp/other"

git log --reverse --no-merges --format='%s' "$range" | while IFS= read -r subject; do
  [ -n "$subject" ] || continue
  # type, optional (scope), optional !, then ": "
  type=$(printf '%s' "$subject" | sed -nE 's/^([A-Za-z]+)(\([^)]*\))?!?: .*/\1/p' | tr 'A-Z' 'a-z')
  scope=$(printf '%s' "$subject" | sed -nE 's/^[A-Za-z]+\(([^)]*)\)!?: .*/\1/p')
  text=$(printf '%s' "$subject" | sed -E 's/^[A-Za-z]+(\([^)]*\))?!?: //')
  if [ -n "$scope" ]; then line="- **${scope}:** ${text}"; else line="- ${text}"; fi
  if printf '%s' "$subject" | grep -Eq '^[A-Za-z]+(\([^)]*\))?!: '; then
    echo "$line" >> "$tmp/breaking"
  else
    case "$type" in
      feat) echo "$line" >> "$tmp/feat" ;;
      fix) echo "$line" >> "$tmp/fix" ;;
      perf) echo "$line" >> "$tmp/perf" ;;
      *) echo "$line" >> "$tmp/other" ;;
    esac
  fi
done

section() {
  if [ -s "$2" ]; then
    printf '### %s\n\n' "$1"
    cat "$2"
    printf '\n'
  fi
}
section "Breaking changes" "$tmp/breaking"
section "Features" "$tmp/feat"
section "Fixes" "$tmp/fix"
section "Performance" "$tmp/perf"
section "Other changes" "$tmp/other"

# CP_BUILD / AGENT_BUILD (from the release workflow) name the release each
# image's code comes from; one older than this release means that image only got
# the new version stamped, and its line says so.
if [ -n "$from" ]; then
  v="${RELEASE_VERSION:-$to}"
  image() {  # $1 = name, $2 = the release its code comes from
    if [ -n "$2" ] && [ "$2" != "$v" ]; then
      printf -- '- `ghcr.io/amaze-labs/mazedns-%s:%s` (unchanged since %s)\n' "$1" "$v" "$2"
    else
      printf -- '- `ghcr.io/amaze-labs/mazedns-%s:%s`\n' "$1" "$v"
    fi
  }
  printf '**Images:**\n\n'
  image control-plane "${CP_BUILD:-}"
  image agent "${AGENT_BUILD:-}"
fi
