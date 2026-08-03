# hubtel-projects secrets engine

A Hubtel-internal builtin secrets engine that makes AQUA's product vault
first-class inside OpenBao: projects, versioned secrets, scheduled rotation,
signed webhook fan-out, and CCI membership reconciliation — no sidecar
service.

This package is a **downstream fork addition** and must never be contributed
upstream (see the repo's `CLAUDE.md` policy: upstream rejects AI-generated
contributions). The full fork diff is intentionally tiny:

- `internal/builtin/logical/hubtelprojects/` (this package, all new files)
- `internal/helper/builtinplugins/registry.go` (one import + one map entry)
- `internal/helper/builtinplugins/registry_test.go` (secrets count 9→10, allow
  hyphenated names in the gen_openapi regex)
- `scripts/gen_openapi.sh` (one `bao secrets enable` line)

To rebase onto a new upstream release: `git fetch upstream && git rebase` —
conflicts are effectively limited to the registry map.

## Enable

```bash
bao secrets enable hubtel-projects
```

## Engine configuration — `hubtel-projects/config`

| Field | Meaning |
|---|---|
| `cci_url` | Base URL of the CCI API (`{cci_url}/productteams` is paged with `Page`/`PageSize`) |
| `cci_authorization` | Authorization header value for CCI calls (write-only) |
| `sync_interval` | Reconciliation interval, default 5m |
| `create_projects_from_cci` | Create missing projects during sync (default: update-only) |
| `webhook_signing_secret` | HMAC-SHA256 key for rotation webhooks (write-only) |
| `enforce_membership` | Require the caller's identity entity to resolve to a member email |
| `default_environments` | Environments for new projects, default `dev,staging,prod` |

## API

```
LIST   hubtel-projects/projects
POST   hubtel-projects/projects/:project              (display_name, environments, members)
GET    hubtel-projects/projects/:project
DELETE hubtel-projects/projects/:project              (removes all secret data)
GET/POST hubtel-projects/projects/:project/members
GET/POST hubtel-projects/projects/:project/webhooks   (urls)

LIST   hubtel-projects/projects/:project/:env/secrets
POST   hubtel-projects/projects/:project/:env/secrets/:name        (value | generate=true, optional cas=N)
GET    hubtel-projects/projects/:project/:env/secrets/:name        (optional ?version=N)
DELETE hubtel-projects/projects/:project/:env/secrets/:name
GET    hubtel-projects/projects/:project/:env/secrets/:name/history
GET/POST hubtel-projects/projects/:project/:env/secrets/:name/config  (auto_rotate, rotation_period, max_versions)
POST   hubtel-projects/projects/:project/:env/secrets/:name/rotate    (optional value for external creds)

GET/POST hubtel-projects/sync    (read last CCI reconciliation / trigger one now)
```

Every write creates a new retained version (KV-v2 style, pruned beyond
`max_versions`, default 10), so consumers holding the previous credential keep
working through a rotation.

## Rotation

- On-demand via `/rotate`; scheduled via `auto_rotate` + `rotation_period`,
  executed by OpenBao's periodic callback (~1 minute granularity).
- Generated values are 256-bit random, URL-safe base64.
- After every rotation the project's webhook URLs receive a **value-free**
  JSON event (`secret.rotated`, project, environment, secret, version,
  rotated_at) signed with `X-Rotation-Signature: sha256=<hex HMAC>`.
  Delivery is best-effort; failures surface as response warnings (interactive)
  or server logs (scheduled).
- External credentials (DB passwords, cloud keys) must be regenerated at the
  source and passed via `value`.

## Access model

Two layers:

1. Standard OpenBao ACL policies on the paths above.
2. With `enforce_membership=true`, secret operations additionally require the
   caller's identity entity (e.g. from the `jwt` auth method backed by Azure
   AD) to have an alias or metadata email matching the project's member list,
   which the periodic CCI reconciliation keeps current. Tokens without an
   entity are denied.

## Standalone mode (no Azure, no CCI)

The engine does not require Azure or CCI. `scripts/hubtel/standalone-setup.sh`
provisions a self-contained deployment on any running OpenBao server:
`userpass` auth (username = engineer email), the engineer policy, the engine
mount, and `enforce_membership=true`. Creating a project automatically seeds
the creator's email as its first member (taken from the caller's identity
entity), so self-service projects are immediately usable; additional teammates
are added via `projects/:project/members`. Configuring `cci_url` later
upgrades membership management to automatic CCI reconciliation without any
data migration, and the `jwt` auth method can be added alongside userpass for
Azure logins — the engine only ever sees identity entities.

## Tests

```bash
go test ./internal/builtin/logical/hubtelprojects/
```
