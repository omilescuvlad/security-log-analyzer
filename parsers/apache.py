from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
import regex as re
from models import LogRecord

# Apache/Nginx "combined" log format:
# %h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-agent}i"

# Exemplu:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/5.0"

_COMBINED_RE = re.compile(
    r'(?P<host>\S+)\s'
    r'(?P<ident>\S+)\s'
    r'(?P<authuser>\S+)\s'
    r'\[(?P<time>[^\]]+)\]\s'
    r'"(?P<request>[^"]*)"\s'
    r'(?P<status>\d{3})\s'
    r'(?P<size>\S+)'
    r'(?:\s"(?P<referer>[^"]*)"\s"(?P<agent>[^"]*)")?'
)

def _parse_time(s: str) -> datetime:
    # ex: 10/Oct/2000:13:55:36 -0700
    dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)

def parse_apache_combined(line: str) -> Optional[LogRecord]:
    m = _COMBINED_RE.match(line.strip())
    if not m:
        return None

    gd = m.groupdict()
    # request: "METHOD PATH PROTO" sau "-"
    req = gd.get("request") or ""
    method, path, proto = None, None, None
    if req and req != "-":
        parts = req.split()
        if len(parts) == 3:
            method, path, proto = parts
        elif len(parts) == 2:
            method, path = parts
        elif len(parts) == 1:
            method = parts[0]

    status = int(gd["status"]) if gd.get("status") else None
    size = None if (gd.get("size") in (None, "-", "")) else int(gd["size"])
    referer = gd.get("referer") or None
    agent = gd.get("agent") or None

    try:
        ts = _parse_time(gd["time"])
    except Exception:
        return None  # linie corupta

    return LogRecord(
        ts=ts,
        src_ip=gd["host"],
        method=method,
        path=path,
        protocol=proto,
        status=status,
        bytes=size,
        referer=referer,
        ua=agent,
        raw=line.rstrip("\n"),
    )
