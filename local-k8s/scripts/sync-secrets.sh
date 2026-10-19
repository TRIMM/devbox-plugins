#!/usr/bin/env bash
#
# Merge protected values from the TRIMM Platform Vault into local .env files.
#
# A project reaches its secrets in two hops; only the second one is this
# script's job:
#
#   1. `menu` -> "Setup/update" logs the developer in with SSO and appends the
#      project.yaml:secrets entries to the project .env (process_secrets in
#      init.sh). For most projects that is VAULT_ROLE_SECRET, which together
#      with the VAULT_ROLE_ID already in .env forms the project's AppRole.
#   2. Logging in with that AppRole yields a token scoped to the project's own
#      secrets -- the same ones its in-cluster workloads read. This script
#      merges those into the per-service .env files listed under
#      project.yaml:role_secrets:
#
#        role_secrets:
#          - path: platform/<customer>/<env>/<secret>
#            file: services/<service>/.env
#
# Services run locally (DDEV, a dev server) read their own .env rather than the
# injected cluster environment, which is the gap this closes.
#
# Each Vault path owns a marked block at the end of its target file:
#
#   # >>> vault:platform/<customer>/<env>/<secret> >>>
#   KEY=value
#   # <<< vault <<<
#
# The block is rewritten whole on every run, so a key dropped from the Vault
# secret disappears from .env too -- which an in-place upsert could never do.
# Nothing outside the block is touched, with one exception: a definition of a
# key the block owns is commented out, because two live definitions of the
# same key differ only by which one the reader happens to take last.
#
# Usage:
#   devbox run secrets:sync              # sync every entry
#   devbox run secrets:sync --dry-run    # report what would change, write nothing
#   devbox run secrets:sync <filter>     # only entries whose path or file match

set -euo pipefail
umask 077

DRY_RUN=false
FILTER=""

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run) DRY_RUN=true ;;
    -h|--help)    sed -n '2,41p' "$0" | sed 's/^#\{1,2\} \{0,1\}//'; exit 0 ;;
    -*)           echo "Unknown option: $1" >&2; exit 2 ;;
    *)            FILTER="$1" ;;
  esac
  shift
done

ROOT="${DEVBOX_PROJECT_ROOT:-$PWD}"
cd "$ROOT"

die ()  { printf '\nError: %s\n' "$1" >&2; exit 1; }
warn () { printf 'Warning: %s\n' "$1" >&2; FAILED=true; }

for tool in bao yq; do
  command -v "$tool" >/dev/null 2>&1 || \
    die "\`$tool\` not found. Run this from the devbox shell: devbox run secrets:sync"
done

[ -f project.yaml ] || die "no project.yaml in $ROOT"

export VAULT_ADDR="${VAULT_ADDR:-https://vault.platform.trimm.net}"

BLOCK_END='# <<< vault <<<'

# Read a single value out of a .env file without sourcing it -- a project .env
# may use `;` comments, which a shell would choke on. Last definition wins,
# matching how the file is read back.
env_get () {
  [ -f "$1" ] || return 0
  local raw
  raw="$(sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?$2=(.*)$/\2/p" "$1" | tail -n 1)"
  case "$raw" in
    '"'*'"')
      raw="${raw#\"}"; raw="${raw%\"}"
      raw="${raw//\\\"/\"}"; raw="${raw//\\\\/\\}"
      ;;
    "'"*"'")
      raw="${raw#\'}"; raw="${raw%\'}"
      ;;
  esac
  printf '%s' "$raw"
}

# Quote only when the value needs it, so the common case stays readable.
env_quote () {
  case "$1" in
    *[!A-Za-z0-9_@%+=:,./-]*|"")
      local v="$1"
      v="${v//\\/\\\\}"
      v="${v//\"/\\\"}"
      printf '"%s"' "$v"
      ;;
    *) printf '%s' "$1" ;;
  esac
}

# The KEY=value lines of the block a given Vault path owns in a file.
block_get () {
  [ -f "$1" ] || return 0
  BLOCK_START="# >>> vault:$2 >>>" BLOCK_END="$BLOCK_END" awk '
    BEGIN { s = ENVIRON["BLOCK_START"]; e = ENVIRON["BLOCK_END"] }
    $0 == s   { inb = 1; next }
    inb && $0 == e { inb = 0; next }
    inb && /^#/ { next }
    inb { print }
  ' "$1"
}

# Replace (or append) the block a Vault path owns, and comment out any live
# definition of a key the block now owns. Keeps the file's mode and inode.
block_write () {
  local file="$1" path="$2" body="$3" keys="$4" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/sync-secrets.XXXXXX")"
  BLOCK_START="# >>> vault:$path >>>" BLOCK_END="$BLOCK_END" BODY="$body" KEYS=" $keys " awk '
    function opens_multiline(v,   i, c, esc) {
      if (substr(v, 1, 1) != "\"") return 0
      for (i = 2; i <= length(v); i++) {
        c = substr(v, i, 1)
        if (esc)       { esc = 0; continue }
        if (c == "\\") { esc = 1; continue }
        if (c == "\"") return 0
      }
      return 1
    }
    function closes_multiline(line,   i, c, esc) {
      for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (esc)       { esc = 0; continue }
        if (c == "\\") { esc = 1; continue }
        if (c == "\"") return 1
      }
      return 0
    }
    function emit_block() {
      print s
      print "# Written by `devbox run secrets:sync`. Edits here are overwritten, and"
      print "# keys dropped from the Vault secret are dropped here."
      printf "%s", body
      print e
    }
    BEGIN {
      s = ENVIRON["BLOCK_START"]; e = ENVIRON["BLOCK_END"]
      body = ENVIRON["BODY"]; keys = ENVIRON["KEYS"]
    }
    # Our own block: regenerate it where it already sits.
    $0 == s  { emit_block(); found = 1; ours = 1; next }
    ours     { if ($0 == e) ours = 0; next }
    # Another path`s block: not ours to touch.
    /^# >>> vault:/ { other = 1; print; next }
    other    { if ($0 == e) other = 0; print; next }
    # Continuation lines of a duplicate we are commenting out.
    dup      { print "# " $0; if (closes_multiline($0)) dup = 0; next }
    {
      if (match($0, /^[ \t]*(export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=/)) {
        name = substr($0, RSTART, RLENGTH)
        sub(/^[ \t]*(export[ \t]+)?/, "", name)
        sub(/=$/, "", name)
        if (index(keys, " " name " ") > 0) {
          print "# [secrets:sync] superseded by the vault block below:"
          print "# " $0
          printf "  ! %s commented out (it is now owned by the block)\n", name > "/dev/stderr"
          if (opens_multiline(substr($0, RSTART + RLENGTH))) dup = 1
          next
        }
      }
      print
    }
    END { if (!found) { print ""; emit_block() } }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"   # preserves the target`s mode and inode
  rm -f "$tmp"
}

# The KEY= prefix of a block line, for comparing old against new.
line_key () { printf '%s' "${1%%=*}"; }

role_id="${VAULT_ROLE_ID:-$(env_get .env VAULT_ROLE_ID)}"
role_secret="${VAULT_ROLE_SECRET:-$(env_get .env VAULT_ROLE_SECRET)}"

[ -n "$role_id" ] || die "VAULT_ROLE_ID is missing from $ROOT/.env (copy it from .env.example)"
[ -n "$role_secret" ] || die "VAULT_ROLE_SECRET is missing from $ROOT/.env.
It is fetched with your personal SSO login by the setup step:

    devbox run init     # or: menu -> Setup/update"

entries="$(yq -r '.role_secrets // [] | .[] | .path + "\t" + .file' project.yaml)"
[ -n "$entries" ] || die "project.yaml has no role_secrets entries"

echo "Logging in to $VAULT_ADDR with the project AppRole..."
token="$(printf '%s' "$role_secret" \
  | bao write -field=token auth/approle/login role_id="$role_id" secret_id=- 2>&1)" || \
  die "AppRole login failed:
$token

A rotated VAULT_ROLE_SECRET is the usual cause. Remove it from $ROOT/.env and
re-run \`devbox run init\` to fetch a fresh one with SSO."
export BAO_TOKEN="$token" VAULT_TOKEN="$token"

total_changed=0
FAILED=false

while IFS="$(printf '\t')" read -r path file; do
  [ -n "$path" ] || continue
  if [ -n "$FILTER" ]; then
    case "$path$file" in *"$FILTER"*) ;; *) continue ;; esac
  fi

  echo
  echo "$path -> $file"

  if [ ! -f "$file" ]; then
    warn "$file does not exist yet -- skipped. Create it first (cp .env.example .env in that repo)."
    continue
  fi

  if ! json="$(bao kv get -format=json "$path" 2>&1)"; then
    warn "cannot read $path -- skipped:
$json"
    continue
  fi

  # KV v2 nests the data a level deeper than v1; accept either. Sorted so the
  # block has a stable order and only real changes show up in a diff.
  pairs="$(printf '%s' "$json" \
    | yq -p json -r '(.data.data // .data) | to_entries[] | .key + " " + (.value | @base64)' \
    | sort)"

  new_body=""
  keys=""
  while read -r key encoded; do
    [ -n "$key" ] || continue
    case "$key" in
      [A-Za-z_]*) ;;
      *) warn "  $key is not a valid env var name -- skipped"; continue ;;
    esac
    value="$(printf '%s' "$encoded" | base64 -d)"
    new_body="${new_body}${key}=$(env_quote "$value")"$'\n'
    keys="$keys $key"
  done <<EOF
$pairs
EOF

  old_body="$(block_get "$file" "$path")"

  # Report against the block as it stands: identical line = unchanged, same
  # key with a different value = updated, absent from Vault now = removed.
  changed=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="$(line_key "$line")"
    if printf '%s\n' "$old_body" | grep -qxF "$line"; then
      echo "  = $key (unchanged)"
    elif printf '%s\n' "$old_body" | grep -q "^$key="; then
      echo "  ~ $key updated"
      changed=$((changed + 1))
    else
      echo "  + $key added"
      changed=$((changed + 1))
    fi
  done <<EOF
$new_body
EOF

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="$(line_key "$line")"
    case "$keys " in
      *" $key "*) ;;
      *) echo "  - $key removed (gone from Vault)"; changed=$((changed + 1)) ;;
    esac
  done <<EOF
$old_body
EOF

  [ "$DRY_RUN" = true ] || block_write "$file" "$path" "$new_body" "$keys"

  total_changed=$((total_changed + changed))
done <<EOF
$entries
EOF

echo
if [ "$DRY_RUN" = true ]; then
  echo "Dry run: $total_changed change(s) pending. Nothing was written."
elif [ "$total_changed" -eq 0 ]; then
  echo "Everything already up to date."
else
  echo "Done: $total_changed change(s) written."
  echo "Restart the affected service so it reads them."
fi

# Non-zero on a skipped entry so a caller can tell a clean run from a partial
# one; `setup` deliberately ignores it and leaves the warnings on screen.
[ "$FAILED" = true ] && exit 1
exit 0
