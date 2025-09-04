from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Iterable
from datetime import datetime, timedelta
import json
import regex as re
import yaml

from models import LogRecord, Detection

@dataclass
class RegexRule:
    id: str
    description: str
    severity: str
    target: str          # 'path' | 'ua' | 'referer' | 'raw'
    pattern: Optional[str] = None
    any_of: Optional[List[str]] = None
    any_of_ci: Optional[List[str]] = None

@dataclass
class AggregationFilter:
    status_in: Optional[List[int]] = None
    path_contains_any: Optional[List[str]] = None
    method_in: Optional[List[str]] = None

@dataclass
class AggregationRule:
    id: str
    description: str
    severity: str
    window_minutes: int
    threshold: int
    filter: AggregationFilter

@dataclass
class RulesConfig:
    regex_rules: List[RegexRule] = field(default_factory=list)
    aggregation_rules: List[AggregationRule] = field(default_factory=list)

def load_rules(path: str) -> RulesConfig:
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    regex_rules = [RegexRule(**r) for r in data.get('regex_rules', [])]
    agg_rules = []
    for r in data.get('aggregation_rules', []):
        filt = AggregationFilter(**r.get('filter', {}))
        agg_rules.append(AggregationRule(
            id=r['id'],
            description=r['description'],
            severity=r['severity'],
            window_minutes=r['window_minutes'],
            threshold=r['threshold'],
            filter=filt
        ))
    return RulesConfig(regex_rules=regex_rules, aggregation_rules=agg_rules)

def _get_target_value(rec: LogRecord, target: str) -> str:
    return {
        'path': rec.path or '',
        'ua': rec.ua or '',
        'referer': rec.referer or '',
        'raw': rec.raw,
    }.get(target, '')

def run_regex_rules(recs: Iterable[LogRecord], rules: List[RegexRule]) -> List[Detection]:
    detections: List[Detection] = []
    compiled = {r.id: re.compile(r.pattern) for r in rules if r.pattern}
    for rec in recs:
        for rule in rules:
            val = _get_target_value(rec, rule.target)
            matched = False
            if rule.pattern and compiled[rule.id].search(val):
                matched = True
            if rule.any_of and any(tok in val for tok in rule.any_of):
                matched = True
            if rule.any_of_ci and any(tok.lower() in val.lower() for tok in rule.any_of_ci):
                matched = True
            if matched:
                detections.append(Detection(
                    rule_id=rule.id,
                    severity=rule.severity,
                    ts_first=rec.ts,
                    ts_last=rec.ts,
                    src_ip=str(rec.src_ip),
                    count=1,
                    summary=f"{rule.id}: {rule.description}",
                    evidence=[rec.raw],
                ))
    return detections

def _filter_rec(rec: LogRecord, f: AggregationFilter) -> bool:
    if f.status_in is not None and rec.status not in f.status_in:
        return False
    if f.method_in is not None and (rec.method is None or rec.method not in f.method_in):
        return False
    if f.path_contains_any is not None:
        path = rec.path or ''
        if not any(tok in path for tok in f.path_contains_any):
            return False
    return True

def _group_by_ip(recs: Iterable[LogRecord], f: AggregationFilter) -> Dict[str, List[LogRecord]]:
    groups: Dict[str, List[LogRecord]] = {}
    for rec in recs:
        if _filter_rec(rec, f):
            groups.setdefault(str(rec.src_ip), []).append(rec)
    for ip in groups:
        groups[ip].sort(key=lambda r: r.ts)
    return groups

def run_aggregation_rules(recs: Iterable[LogRecord], rules: List[AggregationRule]) -> List[Detection]:
    detections: List[Detection] = []
    rec_list = list(recs)
    for rule in rules:
        groups = _group_by_ip(rec_list, rule.filter)
        win = timedelta(minutes=rule.window_minutes)
        for ip, events in groups.items():
            i, n = 0, len(events)
            while i < n:
                j = i
                while j < n and (events[j].ts - events[i].ts) <= win:
                    j += 1
                count = j - i
                if count >= rule.threshold:
                    window_events = events[i:j]
                    # top 5 paths as "evidence"
                    path_counts: Dict[str, int] = {}
                    for ev in window_events:
                        p = ev.path or '-'
                        path_counts[p] = path_counts.get(p, 0) + 1
                    top_paths = sorted(path_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
                    evidence = [f"{p} x{c}" for p, c in top_paths]
                    detections.append(Detection(
                        rule_id=rule.id,
                        severity=rule.severity,
                        ts_first=events[i].ts,
                        ts_last=events[j-1].ts,
                        src_ip=ip,
                        count=count,
                        summary=f"{rule.id}: {rule.description}",
                        evidence=evidence,
                    ))
                    i = j     # avoid duplicates
                else:
                    i += 1
    return detections

def parse_jsonl(path_or_stream) -> Iterable[LogRecord]:
    if isinstance(path_or_stream, str):
        fh = open(path_or_stream, 'r', encoding='utf-8')
        close = True
    elif hasattr(path_or_stream, 'read'):
        fh = path_or_stream
        close = False
    else:
        raise TypeError('Unsupported input')
    try:
        for line in fh:
            if not line.strip():
                continue
            d = json.loads(line)
            try:
                yield LogRecord(**d)
            except Exception:
                continue
    finally:
        if close:
            fh.close()

def detect_from_jsonl(input_path: str, rules_path: str) -> List[Detection]:
    rules = load_rules(rules_path)
    recs = list(parse_jsonl(input_path))
    out: List[Detection] = []
    out.extend(run_regex_rules(recs, rules.regex_rules))
    out.extend(run_aggregation_rules(recs, rules.aggregation_rules))
    out.sort(key=lambda d: d.ts_first)
    return out
