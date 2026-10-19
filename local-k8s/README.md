# Local kubernetes

This Devbox plugin install the tools required to run local environments in Kubernetes

## Installation

Add this plugin as an include to your devbox.json file.

```json
{
  "$schema": "https://raw.githubusercontent.com/jetify-com/devbox/0.16.0/.schema/devbox.schema.json",
  "include": ["github:trimm/devbox-plugins/main?dir=local-k8s"]
}
```

## Secrets

Two kinds of secrets are read from the Platform Vault, and they differ in who
authenticates and where the value lands.

### `secrets` — fetched with the developer's SSO login

Listed in `project.yaml` and appended to the **project** `.env` by
*Setup/update*:

```yaml
secrets:
  - path: platform/<customer>/local-development
    field: VAULT_ROLE_SECRET
    env: VAULT_ROLE_SECRET
```

Typically just the AppRole secret. This step refuses to overwrite values that
are already in `.env` — remove them and re-run to refresh.

### `role_secrets` — fetched with the project's AppRole

Services that run locally (DDEV, a dev server) read their own `.env` instead of
the environment injected into their cluster workload, so values such as
Keycloak client secrets never reach them. List the Vault secret and the target
file:

```yaml
role_secrets:
  - path: platform/<customer>/<env>/<secret>
    file: services/<service>/.env
```

Then:

```sh
devbox run secrets:sync
```

It logs in with `VAULT_ROLE_ID` + `VAULT_ROLE_SECRET` from the project `.env`
and writes **every** key of each secret into a block the Vault path owns at
the end of the target file:

```sh
# >>> vault:platform/<customer>/<env>/<secret> >>>
# Written by `devbox run secrets:sync`. Edits here are overwritten, and
# keys dropped from the Vault secret are dropped here.
KEYCLOAK_ADMIN_PANEL_CLIENT_SECRET=…
# <<< vault <<<
```

*Setup/update* runs it too, and the menu has a **Secrets** entry for it.

The block is rewritten whole on every run, which is what makes the sync
re-runnable in both directions: a rotated value is replaced, and a key dropped
from the Vault secret disappears from `.env` instead of lingering. Nothing
outside the block is touched — `APP_KEY`, local database settings, comments
and ordering all survive, as do the file's permissions.

- **One exception:** a live definition of a key the block owns is commented
  out, with a note saying why. Two definitions of one key differ only by which
  the reader happens to take last, so the block would otherwise silently
  shadow the placeholder a `.env.example` ships with.
- `devbox run secrets:sync -- --dry-run` reports changes and writes nothing.
- A positional argument filters entries by path or file.
- A target `.env` that does not exist yet is reported and skipped, so the
  setup of a freshly cloned project is not blocked by it.
- Dropping an entry from `role_secrets` leaves its block behind; delete it by
  hand.
