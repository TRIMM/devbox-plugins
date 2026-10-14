#!/bin/bash

# Port the OIDC flow listens on for its callback.
VAULT_OIDC_PORT=8250

# True when this shell has no browser of its own, so the OIDC callback on
# localhost:$VAULT_OIDC_PORT cannot be reached.
#
# The SSH_* variables alone are not a reliable signal: JetBrains Remote
# Development starts its backend over SSH and terminals spawned from the IDE do
# not consistently inherit them. On macOS ask launchd instead -- only a real GUI
# login session reports "Aqua".
is_headless () {
  if [ -n "$SSH_CONNECTION" ] || [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
    return 0
  fi

  if [ "$(uname)" = "Darwin" ] && [ "$(launchctl managername 2>/dev/null)" != "Aqua" ]; then
    return 0
  fi

  return 1
}

# Any failure of `bao token lookup` means we cannot use Vault yet: no token, an
# expired one, or a 403. Matching only the literal string "permission denied"
# reported every other failure as a successful login.
if bao token lookup > /dev/null 2>&1; then
    echo "Authenticated to TRIMM Platform Vault"
    exit 0
fi

echo "Note: Login to Vault, using SSO."

if is_headless; then
    echo "No local browser available (SSH or remote development session)."
    echo "Open the URL below in your local browser. The callback needs port $VAULT_OIDC_PORT"
    echo "forwarded (ssh -L $VAULT_OIDC_PORT:localhost:$VAULT_OIDC_PORT); without it, paste a"
    echo "token instead with: bao login -"
    bao login -method=oidc skip_browser=true
else
    bao login -method=oidc
fi
