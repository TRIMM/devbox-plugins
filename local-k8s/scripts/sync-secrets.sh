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
#      merges those, key for key, into the per-service .env files listed under
#      project.yaml:role_secrets:
#
#        role_secrets:
#          - path: platform/<customer>/<env>/<secret>
#            file: services/<service>/.env
#
# Services run locally (DDEV, a dev server) read their own .env rather than the
# injected cluster environment, which is the gap this closes.
#
# Re-runnable by design: every key is upserted in place, so rotating a value in
# Vault and running this again is enough. Keys that are not in Vault are left
# untouched, as is everything else in the file.
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
    -h|--help)    sed -n '2,33p' "$0" | sed 's/^#\{1,2\} \{0,1\}//'; exit 0 ;;
    -*)           echo "Unknown option: $1" >&2; exit 2 ;;
    *)            FILTER="$1" ;;
  esac
  shift
done

ROOT="${DEVBOX_PROJECT_ROOT:-$PWD}"
cd "$ROOT"

die () { printf '\nError: %s\n' "$1" >&2; exit 1; }
warn () { printf 'Warning: %s\n' "$1" >&2; FAILED=true; }

for tool in bao yq; do
  command -v "$tool" >/dev/null 2>&1 || \
    die "\`$tool\` not found. Run this from the devbox shell: devbox run secrets:sync"
done

[ -f project.yaml ] || die "no project.yaml in $ROOT"

export VAULT_ADDR="${VAULT_ADDR:-https://vault.platform.trimm.net}"

# Read a single value out of a .env file without sourcing it -- the workspace
# .env uses `;` comments, which a shell would choke on. Last definition wins,
# matching how the file is read when it is appended to.
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

# Upsert KEY=VALUE in FILE, in place, keeping the file's permissions, inode and
# the existing entry's position. A quoted value spanning several lines is
# replaced whole: phpdotenv reads it back as one value, so overwriting only its
# first line would leave the tail behind as stray lines.
env_set () {
  local file="$1" key="$2" value="$3" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/sync-secrets.XXXXXX")"
  KEY="$key" VALUE="$(env_quote "$value")" awk '
    function opens_multiline(v,   i, c, esc) {
      if (substr(v, 1, 1) != "\"") return 0
      for (i = 2; i <= length(v); i++) {
        c = substr(v, i, 1)
        if (esc)        { esc = 0; continue }
        if (c == "\\")  { esc = 1; continue }
        if (c == "\"")  return 0
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
    BEGIN { key = ENVIRON["KEY"]; value = ENVIRON["VALUE"]; pattern = "^[[:space:]]*(export[[:space:]]+)?" key "=" }
    skipping { if (closes_multiline($0)) skipping = 0; next }
    !replaced && $0 ~ pattern {
      rest = $0
      sub(pattern, "", rest)
      prefix = ($0 ~ /^[[:space:]]*export[[:space:]]/) ? "export " : ""
      print prefix key "=" value
      replaced = 1
      if (opens_multiline(rest)) skipping = 1
      next
    }
    { print }
    END { if (!replaced) print key "=" value }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"   # preserves the target's mode and inode
  rm -f "$tmp"
}

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

  # KV v2 nests the data a level deeper than v1; accept either.
  pairs="$(printf '%s' "$json" | yq -p json -r '(.data.data // .data) | to_entries[] | .key + " " + (.value | @base64)')"
  [ -n "$pairs" ] || { echo "  (secret is empty, nothing to merge)"; continue; }

  changed=0
  while read -r key encoded; do
    [ -n "$key" ] || continue
    case "$key" in
      [A-Za-z_]*) ;;
      *) echo "  skipped $key (not a valid env var name)"; continue ;;
    esac

    value="$(printf '%s' "$encoded" | base64 -d)"
    before="$(env_get "$file" "$key")"

    if [ "$before" = "$value" ]; then
      echo "  = $key (unchanged)"
      continue
    fi

    if [ "$DRY_RUN" = true ]; then
      if [ -n "$before" ]; then echo "  ~ $key would be updated"; else echo "  + $key would be added"; fi
    else
      env_set "$file" "$key" "$value"
      if [ -n "$before" ]; then echo "  ~ $key updated"; else echo "  + $key added"; fi
    fi
    changed=$((changed + 1))
  done <<EOF
$pairs
EOF

  total_changed=$((total_changed + changed))
done <<EOF
$entries
EOF

echo
if [ "$DRY_RUN" = true ]; then
  echo "Dry run: $total_changed value(s) would change. Nothing was written."
elif [ "$total_changed" -eq 0 ]; then
  echo "Everything already up to date."
else
  echo "Done: $total_changed value(s) written."
  echo "Restart the affected service so it reads them."
fi

# Non-zero on a skipped entry so a caller can tell a clean run from a partial
# one; `setup` deliberately ignores it and leaves the warnings on screen.
[ "$FAILED" = true ] && exit 1
exit 0
