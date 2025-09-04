from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import json
import os
import ipaddress
import hashlib

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

import requests

# -----------------------------
# Models (kept simple on purpose)
# -----------------------------

@dataclass
class DetectionLike:
    """A pared-down version of the Detection model used in Day 2.

    We avoid importing the project Pydantic model directly to keep this alerting
    module decoupled from the detection engine. It consumes JSON that matches
    these fields and ignores the rest.
    """
    rule_id: str
    severity: str
    ts_first: datetime
    ts_last: datetime
    count: int
    summary: str
    src_ip: Optional[str] = None
    evidence: List[str] = field(default_factory=list)

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "DetectionLike":
        def parse_dt(v: Any) -> datetime:
            if isinstance(v, datetime):
                return v
            # Expect ISO 8601 strings from Day 2 (UTC); fallback to naive parsing.
            return datetime.fromisoformat(str(v).replace('Z', '+00:00')).astimezone(timezone.utc)
        return DetectionLike(
            rule_id=str(obj.get("rule_id", "")),
            severity=str(obj.get("severity", "low")),
            ts_first=parse_dt(obj.get("ts_first")),
            ts_last=parse_dt(obj.get("ts_last")),
            count=int(obj.get("count", 1)),
            summary=str(obj.get("summary", "")),
            src_ip=obj.get("src_ip"),
            evidence=list(obj.get("evidence") or []),
        )


# -----------------------------
# Config structures
# -----------------------------

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass
class RouteFilter:
    """Optional filters per route."""
    include_rules: List[str] = field(default_factory=list)  # allowlist rule ids (supports simple '*' suffix)
    exclude_rules: List[str] = field(default_factory=list)  # blocklist rule ids
    min_severity: str = "low"                               # per-route threshold
    src_cidrs: List[str] = field(default_factory=list)      # e.g. ["10.0.0.0/8", "192.168.0.0/16"]

    def matches(self, det: DetectionLike) -> bool:
        # Severity gate
        if _SEV_ORDER.get(det.severity, 1) < _SEV_ORDER.get(self.min_severity, 1):
            return False
        # Rule allow/block
        if self.include_rules:
            if not any(_rule_match(det.rule_id, pat) for pat in self.include_rules):
                return False
        if self.exclude_rules:
            if any(_rule_match(det.rule_id, pat) for pat in self.exclude_rules):
                return False
        # src_ip CIDR filter
        if self.src_cidrs and det.src_ip:
            try:
                ip = ipaddress.ip_address(det.src_ip)
                if not any(ip in ipaddress.ip_network(c, strict=False) for c in self.src_cidrs):
                    return False
            except ValueError:
                # If src_ip isn't an IP, skip CIDR filter.
                return False
        return True


def _rule_match(value: str, pattern: str) -> bool:
    # Very simple glob: supports trailing '*' only
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


@dataclass
class Route:
    """Represents a destination and its settings."""
    name: str
    type: str                             # 'console' | 'email_smtp' | 'slack_webhook' | 'teams_webhook' | 'http_webhook'
    filter: RouteFilter = field(default_factory=RouteFilter)
    # Generic webhook fields
    url: Optional[str] = None
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)

    # Email fields
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    use_tls: bool = True
    username: Optional[str] = None
    password: Optional[str] = None  # recommend env vars
    mail_from: Optional[str] = None
    mail_to: List[str] = field(default_factory=list)
    subject_template: Optional[str] = None

    # Slack/Teams: use 'url'

    # Rendering
    template_path: Optional[str] = None    # Jinja2 template path (optional)


@dataclass
class AlertingConfig:
    min_severity: str = "low"              # Global threshold
    dedup_minutes: int = 15                # Min time between identical alerts
    rate_limit_per_rule: int = 50          # Max alerts per rule in a window
    rate_limit_window_minutes: int = 60    # Window for the above
    routes: List[Route] = field(default_factory=list)


# -----------------------------
# State storage (file-based)
# -----------------------------

@dataclass
class State:
    last_sent: Dict[str, float] = field(default_factory=dict)         # fingerprint -> epoch seconds
    sent_counters: Dict[str, List[float]] = field(default_factory=dict)  # rule_id -> [epoch seconds]

    @staticmethod
    def load(path: str) -> "State":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            return State(**raw)
        except FileNotFoundError:
            return State()
        except Exception:
            # Corrupt state? Start fresh rather than crashing alerting.
            return State()

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"last_sent": self.last_sent, "sent_counters": self.sent_counters}, fh)
        os.replace(tmp, path)


# -----------------------------
# Template rendering
# -----------------------------

def _load_env_template(template_path: Optional[str]) -> Environment:
    if template_path:
        # Use provided directory as loader root
        loader_dir = os.path.dirname(template_path) or "."
        return Environment(loader=FileSystemLoader(loader_dir), autoescape=select_autoescape())
    # Fallback loader that looks into ./templates
    return Environment(loader=FileSystemLoader(["templates", "."]), autoescape=select_autoescape())


_DEFAULT_SUBJECT = "[{severity}] {rule_id} x{count}"
_DEFAULT_BODY = """\
# Security Alert

**Rule:** {{ det.rule_id }}
**Severity:** {{ det.severity }}
**Count:** {{ det.count }}
**Window UTC:** {{ det.ts_first.isoformat() }} → {{ det.ts_last.isoformat() }}
**Source IP:** {{ det.src_ip or "-" }}

**Summary:**
{{ det.summary }}

{% if det.evidence %}
**Evidence (first 5 lines):**
{% for ev in det.evidence[:5] %}
- {{ ev }}
{% endfor %}
{% endif %}
"""

def render_subject(route: Route, det: DetectionLike) -> str:
    tpl = route.subject_template or _DEFAULT_SUBJECT
    return tpl.format(
        severity=det.severity.upper(),
        rule_id=det.rule_id,
        count=det.count,
    )

def render_body(route: Route, det: DetectionLike) -> str:
    env = _load_env_template(route.template_path)
    template_name = os.path.basename(route.template_path) if route.template_path else None
    if template_name and os.path.exists(route.template_path):
        template = env.get_template(template_name)
        return template.render(det=det)
    # Use default inline template
    template = env.from_string(_DEFAULT_BODY)
    return template.render(det=det)


# -----------------------------
# Transport implementations
# -----------------------------

def _expand_env(value: Optional[str]) -> Optional[str]:
    """Expand ${VAR} from env to avoid committing secrets."""
    if not value:
        return value
    if value.startswith("${") and value.endswith("}"):
        key = value[2:-1]
        return os.getenv(key)
    return value

def _send_console(route: Route, det: DetectionLike, body: str, subject: str) -> None:
    print("=" * 80)
    print(f"[Console route: {route.name}] {subject}")
    print(body)

def _send_email(route: Route, det: DetectionLike, body: str, subject: str) -> None:
    # Use Python's stdlib 'smtplib' so we don't add heavy deps.
    import smtplib
    from email.message import EmailMessage

    host = route.smtp_host
    if not host:
        raise RuntimeError("smtp_host is required for email_smtp route")
    port = route.smtp_port or 587
    username = _expand_env(route.username)
    password = _expand_env(route.password)

    msg = EmailMessage()
    mail_from = route.mail_from or (username or "security-log-analyzer@example")
    msg["From"] = mail_from
    msg["To"] = ", ".join(route.mail_to or [])
    msg["Subject"] = subject
    msg.set_content(body)

    if route.use_tls:
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            if username and password:
                s.login(username, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port) as s:
            if username and password:
                s.login(username, password)
            s.send_message(msg)

def _send_webhook_json(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None, method: str = "POST") -> None:
    method = (method or "POST").upper()
    headers = headers or {}
    if method == "POST":
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
    elif method == "PUT":
        resp = requests.put(url, json=payload, headers=headers, timeout=10)
    else:
        # Default to POST for safety
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
    resp.raise_for_status()

def _send_slack(route: Route, det: DetectionLike, body: str, subject: str) -> None:
    if not route.url:
        raise RuntimeError("url is required for slack_webhook route")
    payload = {"text": f"*{subject}*\n{body}"}
    _send_webhook_json(route.url, payload)

def _send_teams(route: Route, det: DetectionLike, body: str, subject: str) -> None:
    if not route.url:
        raise RuntimeError("url is required for teams_webhook route")
    payload = {"text": f"{subject}\n{body}"}
    _send_webhook_json(route.url, payload)

def _send_http(route: Route, det: DetectionLike, body: str, subject: str) -> None:
    if not route.url:
        raise RuntimeError("url is required for http_webhook route")
    payload = {
        "subject": subject,
        "body": body,
        "rule_id": det.rule_id,
        "severity": det.severity,
        "count": det.count,
        "src_ip": det.src_ip,
        "ts_first": det.ts_first.isoformat(),
        "ts_last": det.ts_last.isoformat(),
        "summary": det.summary,
        "evidence": det.evidence[:5],
    }
    _send_webhook_json(route.url, payload, headers=route.headers, method=route.method)


# -----------------------------
# Alert engine
# -----------------------------

def _fingerprint(det: DetectionLike) -> str:
    # Stable hash for deduplication keys
    key = f"{det.rule_id}|{det.src_ip or '-'}|{det.severity}|{det.summary}|{det.count}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def _global_threshold_ok(det: DetectionLike, cfg: AlertingConfig) -> bool:
    return _SEV_ORDER.get(det.severity, 1) >= _SEV_ORDER.get(cfg.min_severity, 1)

def _within_dedup_window(fp: str, now: float, state: State, dedup_minutes: int) -> bool:
    last = state.last_sent.get(fp)
    if last is None:
        return False
    return (now - last) < (dedup_minutes * 60)

def _rate_limited(rule_id: str, now: float, state: State, max_per_window: int, window_minutes: int) -> bool:
    bucket = state.sent_counters.get(rule_id, [])
    cutoff = now - window_minutes * 60
    bucket = [t for t in bucket if t >= cutoff]
    state.sent_counters[rule_id] = bucket
    return len(bucket) >= max_per_window

def _record_sent(fp: str, rule_id: str, now: float, state: State) -> None:
    state.last_sent[fp] = now
    bucket = state.sent_counters.setdefault(rule_id, [])
    bucket.append(now)

def _load_config(path: str) -> AlertingConfig:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    routes = []
    for r in raw.get("routes", []):
        filt = r.get("filter") or {}
        route = Route(
            name=r.get("name") or r.get("type"),
            type=r.get("type"),
            filter=RouteFilter(
                include_rules=filt.get("include_rules") or [],
                exclude_rules=filt.get("exclude_rules") or [],
                min_severity=filt.get("min_severity") or "low",
                src_cidrs=filt.get("src_cidrs") or [],
            ),
            url=r.get("url"),
            method=r.get("method") or "POST",
            headers=r.get("headers") or {},
            smtp_host=r.get("smtp_host"),
            smtp_port=r.get("smtp_port") or 587,
            use_tls=bool(r.get("use_tls", True)),
            username=r.get("username"),
            password=r.get("password"),
            mail_from=r.get("mail_from"),
            mail_to=r.get("mail_to") or [],
            subject_template=r.get("subject_template"),
            template_path=r.get("template_path"),
        )
        routes.append(route)
    return AlertingConfig(
        min_severity=raw.get("min_severity") or "low",
        dedup_minutes=int(raw.get("dedup_minutes") or 15),
        rate_limit_per_rule=int(raw.get("rate_limit_per_rule") or 50),
        rate_limit_window_minutes=int(raw.get("rate_limit_window_minutes") or 60),
        routes=routes
    )

def _iter_detections_from_jsonl(path: str) -> Iterable[DetectionLike]:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield DetectionLike.from_json(obj)
            except Exception:
                continue

def route_alerts(
    detections_jsonl: str,
    config_yaml: str,
    state_path: str,
    dry_run: bool = False,
) -> Tuple[int, int, int]:
    """Main entry point. Returns (total_read, sent, suppressed)."""
    cfg = _load_config(config_yaml)
    state = State.load(state_path)
    now = datetime.now(tz=timezone.utc).timestamp()

    total, sent, suppressed = 0, 0, 0
    for det in _iter_detections_from_jsonl(detections_jsonl):
        total += 1
        if not _global_threshold_ok(det, cfg):
            suppressed += 1
            continue

        fp = _fingerprint(det)
        if _within_dedup_window(fp, now, state, cfg.dedup_minutes):
            suppressed += 1
            continue

        if _rate_limited(det.rule_id, now, state, cfg.rate_limit_per_rule, cfg.rate_limit_window_minutes):
            suppressed += 1
            continue

        # Route to each destination that matches filters
        delivered_any = False
        for route in cfg.routes:
            if not route.filter.matches(det):
                continue
            subject = render_subject(route, det)
            body = render_body(route, det)
            if dry_run:
                _send_console(route, det, body, subject)
                delivered_any = True
                continue

            try:
                if route.type == "console":
                    _send_console(route, det, body, subject)
                elif route.type == "email_smtp":
                    _send_email(route, det, body, subject)
                elif route.type == "slack_webhook":
                    _send_slack(route, det, body, subject)
                elif route.type == "teams_webhook":
                    _send_teams(route, det, body, subject)
                elif route.type == "http_webhook":
                    _send_http(route, det, body, subject)
                else:
                    # Unknown route type: skip but don't crash.
                    continue
                delivered_any = True
            except Exception as e:
                # Fail-open: we count as suppressed to avoid state update.
                print(f"[WARN] Route '{route.name}' failed to send: {e}")

        if delivered_any:
            _record_sent(fp, det.rule_id, now, state)
            sent += 1
        else:
            suppressed += 1

    # Persist state
    state.save(state_path)
    return total, sent, suppressed
