from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import json
import os
import ipaddress
import hashlib
import subprocess
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from alerts.engine import DetectionLike, _SEV_ORDER  
from alerts.engine import render_body as render_alert_body, render_subject  # for notify actions
from alerts.engine import Route, RouteFilter, _send_slack, _send_http, _send_email, _expand_env

# --------------------------
# Config structures
# --------------------------

@dataclass
class PlaybookFilter:
    include_rules: List[str] = field(default_factory=list)
    exclude_rules: List[str] = field(default_factory=list)
    min_severity: str = "low"
    src_cidrs: List[str] = field(default_factory=list)  

    def matches(self, det: DetectionLike) -> bool:
        if _SEV_ORDER.get(det.severity, 1) < _SEV_ORDER.get(self.min_severity, 1):
            return False
        if self.include_rules and not any(_rule_match(det.rule_id, pat) for pat in self.include_rules):
            return False
        if self.exclude_rules and any(_rule_match(det.rule_id, pat) for pat in self.exclude_rules):
            return False
        if self.src_cidrs and det.src_ip:
            try:
                ip = ipaddress.ip_address(det.src_ip)
                if not any(ip in ipaddress.ip_network(c, strict=False) for c in self.src_cidrs):
                    return False
            except ValueError:
                return False
        return True

def _rule_match(value: str, pattern: str) -> bool:
    return value.startswith(pattern[:-1]) if pattern.endswith("*") else (value == pattern)

@dataclass
class Action:
    type: str
    # for notify:
    route: Optional[str] = None           
    template_path: Optional[str] = None   # for ticket rendering
    path: Optional[str] = None            # for write_ticket
    # for containment:
    ttl_minutes: int = 1440               # default 24h

@dataclass
class Playbook:
    name: str
    filter: PlaybookFilter
    actions: List[Action]

@dataclass
class RespondConfig:
    min_severity: str = "low"
    cooldown_minutes: int = 30
    auto_cleanup_on_start: bool = True
    never_block_cidrs: List[str] = field(default_factory=list)
    playbooks: List[Playbook] = field(default_factory=list)
    # For notify actions, reuse alert routes from alerting.yaml
    alert_routes: Dict[str, Route] = field(default_factory=dict)

# --------------------------
# State file
# --------------------------

@dataclass
class RespondState:
    # Tracks last time we executed (action_type, target_key) to enforce cooldown
    last_action: Dict[str, float] = field(default_factory=dict)
    # Tracks containment entries with expiry: key -> {"rule_name": str, "expires": float}
    containment: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @staticmethod
    def load(path: str) -> "RespondState":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            return RespondState(**raw)
        except FileNotFoundError:
            return RespondState()
        except Exception:
            return RespondState()

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"last_action": self.last_action, "containment": self.containment}, fh)
        os.replace(tmp, path)

# --------------------------
# Utilities
# --------------------------

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

def _cooldown_key(action_type: str, det: DetectionLike) -> str:
    # Keep it simple: action per rule_id + src_ip
    base = f"{action_type}|{det.rule_id}|{det.src_ip or '-'}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def _within_cooldown(key: str, now: float, st: RespondState, cooldown_minutes: int) -> bool:
    last = st.last_action.get(key)
    return (last is not None) and (now - last < cooldown_minutes * 60)

def _record_action(key: str, now: float, st: RespondState) -> None:
    st.last_action[key] = now

def _is_public_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False

def _in_cidrs(ip_str: str, cidrs: List[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in ipaddress.ip_network(c, strict=False) for c in cidrs)
    except Exception:
        return False

# --------------------------
# Load configs (respond + alert routes)
# --------------------------

def _load_alert_routes(alerting_yaml: str) -> Dict[str, Route]:
    # Reuse loader to get Route objects
    from alerts.engine import _load_config as _load_alert_cfg
    cfg = _load_alert_cfg(alerting_yaml)
    # index by name
    return {r.name: r for r in cfg.routes}

def _load_respond_config(path: str, alerting_yaml: str) -> RespondConfig:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    playbooks: List[Playbook] = []
    for pb in raw.get("playbooks", []):
        f = pb.get("filter") or {}
        actions = [Action(**a) for a in pb.get("actions", [])]
        playbooks.append(
            Playbook(
                name=pb.get("name", "playbook"),
                filter=PlaybookFilter(
                    include_rules=f.get("include_rules") or [],
                    exclude_rules=f.get("exclude_rules") or [],
                    min_severity=f.get("min_severity") or "low",
                    src_cidrs=f.get("src_cidrs") or [],
                ),
                actions=actions,
            )
        )
    return RespondConfig(
        min_severity=raw.get("min_severity", "low"),
        cooldown_minutes=int(raw.get("cooldown_minutes", 30)),
        auto_cleanup_on_start=bool(raw.get("auto_cleanup_on_start", True)),
        never_block_cidrs=raw.get("never_block_cidrs") or [],
        playbooks=playbooks,
        alert_routes=_load_alert_routes(alerting_yaml),
    )

# --------------------------
# Actions
# --------------------------

def _render_ticket(template_path: Optional[str], det: DetectionLike, actions_taken: List[str]) -> str:
    env = Environment(loader=FileSystemLoader(["templates", "."]), autoescape=select_autoescape())
    name = os.path.basename(template_path) if template_path else None
    if name and os.path.exists(template_path):
        tpl = env.get_template(name)
        return tpl.render(det=det, actions_taken=actions_taken)
    # fallback trivial template
    tpl = env.from_string("Incident: {{ det.rule_id }} {{ det.severity }} {{ det.src_ip }}\nActions: {{ actions_taken|join(', ') }}\n")
    return tpl.render(det=det, actions_taken=actions_taken)

def _powershell(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    # Executes a PowerShell command on Windows. We assume Windows 11 + PowerShell.
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, check=check)

def _unique_rule_name(prefix: str, det: DetectionLike) -> str:
    # Keep rule names short; Windows netsh has length limits
    h = hashlib.sha1(f"{det.rule_id}|{det.src_ip}".encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{det.rule_id}-{h}"

def _action_block_ip(det: DetectionLike, cfg: RespondConfig, st: RespondState, ttl_minutes: int, dry_run: bool) -> Tuple[bool, str]:
    # Guardrails
    if not det.src_ip:
        return False, "skip: no src_ip"
    if not _is_public_ip(det.src_ip):
        return False, f"skip: non-public ip {det.src_ip}"
    if cfg.never_block_cidrs and _in_cidrs(det.src_ip, cfg.never_block_cidrs):
        return False, f"skip: in never_block_cidrs {det.src_ip}"

    rule_name = _unique_rule_name("SLA-Block", det)
    expires = (datetime.now(tz=timezone.utc) + timedelta(minutes=ttl_minutes)).timestamp()
    key = f"block_ip|{det.src_ip}"

    if dry_run:
        return True, f"DRY-RUN block_ip {det.src_ip} via Windows Firewall rule '{rule_name}' ttl={ttl_minutes}m"

    # Create inbound block rule for remote IP
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={det.src_ip}'
    try:
        res = _powershell(cmd)
        if res.returncode != 0:
            return False, f"block_ip failed: {res.stderr.strip() or res.stdout.strip()}"
    except subprocess.CalledProcessError as e:
        return False, f"block_ip failed: {e.stderr or str(e)}"

    st.containment[key] = {"rule_name": rule_name, "expires": expires}
    return True, f"blocked {det.src_ip} with rule '{rule_name}' until {datetime.fromtimestamp(expires, tz=timezone.utc).isoformat()}"

def _cleanup_expired_containment(st: RespondState, dry_run: bool) -> List[str]:
    messages = []
    now = datetime.now(tz=timezone.utc).timestamp()
    to_delete = []
    for key, info in st.containment.items():
        if now >= float(info.get("expires", 0)):
            rule_name = info.get("rule_name", "")
            if dry_run:
                messages.append(f"DRY-RUN cleanup: would delete firewall rule '{rule_name}'")
            else:
                try:
                    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                    res = _powershell(cmd, check=False)
                    if res.returncode == 0:
                        messages.append(f"cleanup: deleted firewall rule '{rule_name}'")
                except Exception as e:
                    messages.append(f"cleanup failed for '{rule_name}': {e}")
            to_delete.append(key)
    for k in to_delete:
        st.containment.pop(k, None)
    return messages

def _action_slack(det: DetectionLike, rt: Route, dry_run: bool) -> Tuple[bool, str]:
    subject = render_subject(rt, det)
    body = render_alert_body(rt, det)

    # Expand ${ENV} in route.url
    url = rt.url or ""
    if url.startswith("${") and url.endswith("}"):
        envv = os.getenv(url[2:-1])
        if not envv:
            return False, f"slack_notify failed: env var {url} not set"
        rt = Route(**{**rt.__dict__, "url": envv})

    if dry_run:
        return True, f"DRY-RUN slack_notify to route '{rt.name}': {subject}"
    try:
        _send_slack(rt, det, body, subject)
        return True, f"slack_notify sent via '{rt.name}'"
    except Exception as e:
        return False, f"slack_notify failed: {e}"


def _action_email(det: DetectionLike, rt: Route, dry_run: bool) -> Tuple[bool, str]:
    subject = render_subject(rt, det)
    body = render_alert_body(rt, det)
    if dry_run:
        return True, f"DRY-RUN email_notify via '{rt.name}': {subject}"
    try:
        _send_email(rt, det, body, subject)
        return True, f"email_notify sent via '{rt.name}'"
    except Exception as e:
        return False, f"email_notify failed: {e}"

def _action_webhook(det: DetectionLike, rt: Route, dry_run: bool) -> Tuple[bool, str]:
    subject = render_subject(rt, det)
    body = render_alert_body(rt, det)

    url = rt.url or ""
    if url.startswith("${") and url.endswith("}"):
        envv = os.getenv(url[2:-1])
        if not envv:
            return False, f"http_webhook failed: env var {url} not set"
        rt = Route(**{**rt.__dict__, "url": envv})

    # Expand ${ENV} in headers too
    headers = {}
    for k, v in (rt.headers or {}).items():
        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
            vv = os.getenv(v[2:-1])
            if vv is None:
                return False, f"http_webhook failed: header {k} requires env {v}"
            headers[k] = vv
        else:
            headers[k] = v
    rt = Route(**{**rt.__dict__, "headers": headers})

    if dry_run:
        return True, f"DRY-RUN http_webhook via '{rt.name}': {subject}"
    try:
        _send_http(rt, det, body, subject)
        return True, f"http_webhook sent via '{rt.name}'"
    except Exception as e:
        return False, f"http_webhook failed: {e}"

def _action_write_ticket(det: DetectionLike, path: str, template_path: Optional[str], actions_taken: List[str], dry_run: bool) -> Tuple[bool, str]:
    content = _render_ticket(template_path, det, actions_taken)
    if dry_run:
        return True, f"DRY-RUN write_ticket to '{path}'"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(content + "\n\n---\n\n")
    return True, f"ticket appended to '{path}'"

# --------------------------
# Engine
# --------------------------

def run_responder(
    detections_jsonl: str,
    responding_yaml: str,
    alerting_yaml: str,
    state_path: str,
    dry_run: bool = False,
) -> Tuple[int, int, int]:
    """
    Returns: (total_detections, actions_executed, actions_suppressed)
    """
    cfg = _load_respond_config(responding_yaml, alerting_yaml)
    state = RespondState.load(state_path)
    now = datetime.now(tz=timezone.utc).timestamp()

    # Optional auto-cleanup
    if cfg.auto_cleanup_on_start:
        msgs = _cleanup_expired_containment(state, dry_run)
        for m in msgs:
            print(m)

    total_dets, executed, suppressed = 0, 0, 0
    for det in _iter_detections_from_jsonl(detections_jsonl):
        total_dets += 1
        if _SEV_ORDER.get(det.severity, 1) < _SEV_ORDER.get(cfg.min_severity, 1):
            continue

        # Match playbooks
        pbs = [pb for pb in cfg.playbooks if pb.filter.matches(det)]
        if not pbs:
            continue

        for pb in pbs:
            actions_taken_labels: List[str] = []
            for a in pb.actions:
                # Enforce cooldown per action + det target
                key = _cooldown_key(a.type, det)
                if _within_cooldown(key, now, state, cfg.cooldown_minutes):
                    suppressed += 1
                    continue

                ok, msg = False, "no-op"
                if a.type == "block_ip":
                    ok, msg = _action_block_ip(det, cfg, state, a.ttl_minutes, dry_run)
                    if ok:
                        actions_taken_labels.append("block_ip")
                elif a.type == "slack_notify":
                    rt = cfg.alert_routes.get(a.route or "")
                    if rt:
                        ok, msg = _action_slack(det, rt, dry_run)
                        if ok:
                            actions_taken_labels.append(f"slack:{rt.name}")
                    else:
                        ok, msg = False, f"route '{a.route}' not found"
                elif a.type == "email_notify":
                    rt = cfg.alert_routes.get(a.route or "")
                    if rt:
                        ok, msg = _action_email(det, rt, dry_run)
                        if ok:
                            actions_taken_labels.append(f"email:{rt.name}")
                    else:
                        ok, msg = False, f"route '{a.route}' not found"
                elif a.type == "http_webhook":
                    rt = cfg.alert_routes.get(a.route or "")
                    if rt:
                        ok, msg = _action_webhook(det, rt, dry_run)
                        if ok:
                            actions_taken_labels.append(f"webhook:{rt.name}")
                    else:
                        ok, msg = False, f"route '{a.route}' not found"
                elif a.type == "write_ticket":
                    if not a.path:
                        ok, msg = False, "write_ticket requires 'path'"
                    else:
                        ok, msg = _action_write_ticket(det, a.path, a.template_path, actions_taken_labels, dry_run)
                        if ok:
                            actions_taken_labels.append("ticket")
                else:
                    ok, msg = False, f"unknown action '{a.type}'"

                print(f"[{pb.name}] {a.type}: {msg}")
                if ok:
                    executed += 1
                    # Do not mutate state during dry-run
                    if not dry_run:
                        _record_action(key, now, state)


    state.save(state_path)
    return total_dets, executed, suppressed
