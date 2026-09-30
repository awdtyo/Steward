# Steward

Always-on AI operator for a Raspberry Pi 5 (4 GB RAM, ARM64) homelab.
Monitors Docker services, diagnoses with NVIDIA Nemotron models, fixes safe
issues automatically, and asks approval for risky ones.

Status: monitoring + dashboard + diagnosis + action layer implemented,
with per-service health checks.

## Quickstart

```sh
cp .env.example .env          # fill in LLM + SMTP settings
cp services.example.yaml services.yaml   # adjust to your homelab
make test                     # run tests
make dry-run                  # mock events/logs, touch nothing real
docker compose up --build
```

## Dashboard

Pages (served from `src/steward/app.py`, bound to `127.0.0.1:$PORT`):

- `/` — live status: host RAM/CPU/temperature/disk, service health,
  pushed over Server-Sent Events (`/events`) via htmx, no JS build step.
- `/incidents` — open and recently resolved incidents.
- `/incidents/{key}` — incident detail (the target of alert email links).
- `/trace/{key}` — agent trace: diagnosis plus every step, tool
  call, model, tokens, and redaction counts.
- `/approvals` — pending and decided action approvals.

## Actions (Tier 1 auto, Tier 2 approved)

- **Tier 1** (`restart_container`, `clear_cache`): reversible and automatic,
  but only for services in `TIER1_ALLOW_SERVICES`. Every step audit-logged.
- **Tier 2** (`restore_snapshot`, `config_change`): needs a human approval
  on `/approvals`, a pre-action snapshot (compose file + redacted config
  copy), and a stored rollback plan covering volume backups. Approved
  restores execute at once; `config_change` is proposal-only (a human
  performs the change manually). Executed Tier-2 actions can be rolled back
  from their approval page.
- Vaultwarden is rejected in code on every path, even if allowlisted.
- The audit log table is append-only (enforced by SQLite triggers).
- Approval POSTs need CSRF token + confirm checkbox + an identity matching
  `ALLOWED_APPROVER`, taken from the `Tailscale-User-Login` header that
  `tailscale serve` injects (configurable via `TAILSCALE_USER_HEADER`).
  Direct access has no header, so approvals fail closed. The agent can
  never approve its own requests (rejected in code, not just UI).

All rendered content is redacted (IPs, hostnames, tokens, emails, secrets)
and HTML-escaped; raw logs are never stored or shown.

## Services

Per-service support lives in `services.yaml` (gitignored local topology;
copy from `services.example.yaml`). Each service declares `checks`
(`container`, `http`, `tls_expiry`, `backup`), `log_hints` (regex → label
pairs surfaced to the diagnosis agent), and `allowed_actions` (a subset of
Tier-1 tools enforced when proposing actions). First-class services:
Jellyfin, Nextcloud, Tailscale, Vaultwarden, and Uptime Kuma. Absent file =
built-in defaults.

**Vaultwarden is monitor-only, enforced in code**: only container up/down,
certificate expiry, and backup checks; no log hints; no allowed actions;
its logs, env, and paths never reach the LLM — alerts carry fixed titles
only. The backup verifier (`VAULTWARDEN_BACKUP_DIR`) checks that a recent
(< `max_age_hours`, default 26), non-empty, verifiably encrypted (`.age` /
`.gpg` / `.enc` or age header) backup exists, reading directory listings
plus a few header bytes. Missing backup = critical, stale/empty/
unencrypted = warning.

## Hand-logged incident memory

```sh
steward incident add --symptom "..." --cause "..." --fix "..." \
    [--service NAME] [--tags a,b]
steward incident list [--limit N]
steward incident search <text>
```

### Exposing it on your tailnet with `tailscale serve`

The dashboard listens on loopback only. To reach it from your other
Tailscale devices (no public internet — do **not** use Funnel for this):

```sh
# Serve local port 8000 over your tailnet (run on the Pi):
tailscale serve --bg http://127.0.0.1:8000

# Check what is being served:
tailscale serve status

# Open from another tailnet device:
# https://<pi-tailnet-name>.<tailnet>.ts.net/
```

To stop: `tailscale serve --bg off` (or `tailscale serve reset`).
Funnel (`tailscale funnel`) would publish the dashboard to the public
internet — never use it for steward; `serve` stays inside your tailnet.

See `AGENTS.md` for project rules.
