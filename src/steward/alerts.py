"""Email alerts via smtplib. No LLM calls.

Policy: critical incidents mail immediately; warning/info roll into a daily
digest; resolved incidents get one recovery mail. Bodies are short, redacted,
link to the dashboard incident page, and never contain raw logs -- only the
templated incident title plus a link.
"""

from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from .config import Settings
from .redact import redact
from .rules import Incident

# Captures mails instead of sending (dry-run mode and tests).
OUTBOX: list[EmailMessage] = []


@dataclass
class Email:
    to: str
    subject: str
    body: str

    def as_message(self, sender: str) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = self.to
        msg["Subject"] = self.subject
        msg.set_content(self.body)
        return msg


def incident_url(settings: Settings, key: str) -> str:
    return f"{settings.dashboard_base_url.rstrip('/')}/incidents/{key}"


def _line(settings: Settings, incident: Incident) -> str:
    # Title is redacted (it may carry metric labels); the dashboard URL is
    # operator-configured, not untrusted content, so it stays intact.
    return (f"[{incident.severity}] {redact(incident.title)}\n"
            f"  {incident_url(settings, incident.key)}")


def critical_email(settings: Settings, incident: Incident) -> Email:
    title = redact(incident.title)
    body = (f"Steward alert: {title}\n\n"
            f"{_line(settings, incident)}\n")
    return Email(settings.alert_to, f"[steward CRITICAL] {title}", body)


def recovery_email(settings: Settings, incident: Incident) -> Email:
    title = redact(incident.title)
    body = (f"Steward recovery: {title} has cleared.\n\n"
            f"{_line(settings, incident)}\n")
    return Email(settings.alert_to, f"[steward RECOVERED] {title}", body)


def digest_email(settings: Settings,
                 incidents: list[Incident]) -> Email | None:
    """Daily digest of non-critical incidents. None when there is nothing."""
    rest = [i for i in incidents if i.severity in {"warning", "info"}]
    if not rest:
        return None
    lines = "\n".join(_line(settings, i) for i in sorted(
        rest, key=lambda i: (i.severity != "warning", i.service, i.key)))
    body = (f"Steward daily digest: {len(rest)} open "
            f"warning(s)/info(s).\n\n{lines}\n")
    return Email(settings.alert_to,
                 f"[steward digest] {len(rest)} open warnings", body)


def row_to_incident(row) -> Incident:
    return Incident(key=row["key"], service=row["service"], rule=row["rule"],
                    title=row["title"], severity=row["severity"],
                    observed_ts=row["last_seen"])


def send_email(settings: Settings, email: Email) -> bool:
    """Send one mail. Dry-run (or unconfigured SMTP) captures to OUTBOX."""
    if settings.dry_run or not settings.smtp_host or not email.to:
        OUTBOX.append(email.as_message(settings.smtp_from or "steward"))
        return True
    msg = email.as_message(settings.smtp_from)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port,
                           timeout=15) as smtp:
            smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError):
        return False
    return True


__all__ = [
    "OUTBOX",
    "Email",
    "critical_email",
    "digest_email",
    "incident_url",
    "recovery_email",
    "row_to_incident",
    "send_email",
]
