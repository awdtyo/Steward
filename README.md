# Steward

Always-on AI operator for a Raspberry Pi 5 (4 GB RAM, ARM64) homelab.
Monitors Docker services, diagnoses with NVIDIA Nemotron models, fixes safe
issues automatically, and asks approval for risky ones.

Status: repo skeleton only — no features implemented yet.

## Quickstart

```sh
cp .env.example .env   # fill in LLM + SMTP settings
make test              # run tests
make dry-run           # run with mock events/logs (touches nothing real)
docker compose up --build
```

See `AGENTS.md` for project rules.
