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
and merges **every** key of each secret into the target file. *Setup/update*
runs it too, and the menu has a **Secrets** entry for it.

Unlike `secrets`, this is re-runnable: keys are upserted in place, keeping
their position in the file, so a rotated value only needs another sync. Keys
that are not in Vault — `APP_KEY`, local database settings — are never
touched, and the file's permissions are preserved.

- `devbox run secrets:sync -- --dry-run` reports changes and writes nothing.
- A positional argument filters entries by path or file.
- A target `.env` that does not exist yet is reported and skipped, so the
  setup of a freshly cloned project is not blocked by it.
