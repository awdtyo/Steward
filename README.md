# Steward

Always-on AI operator for a Raspberry Pi 5 (4 GB RAM, ARM64) homelab.
Monitors Docker services, diagnoses with NVIDIA Nemotron models, fixes safe
issues automatically, and asks approval for risky ones.

Status: monitoring layer + dashboard implemented; diagnosis/fixes aspirational.

## Quickstart

```sh
cp .env.example .env   # fill in LLM + SMTP settings
make test              # run tests
make dry-run           # run with mock events/logs (touches nothing real)
docker compose up --build
```

## Dashboard

Pages (served from `src/steward/app.py`, bound to `127.0.0.1:$PORT`):

- `/` — live status: host RAM/CPU/temperature/disk, service health,
  pushed over Server-Sent Events (`/events`) via htmx, no JS build step.
- `/incidents` — open and recently resolved incidents.
- `/incidents/{key}` — incident detail (the target of alert email links).

All rendered content is redacted (IPs, hostnames, tokens, emails, secrets)
and HTML-escaped; raw logs are never stored or shown.

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
