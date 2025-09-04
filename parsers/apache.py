from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
import regex as re
from models import LogRecord

# Apache/Nginx "combined" log format:
# %h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-agent}i"

_COMBINED_RE = re.compile(
    r'(?P<host>\S+)\s'
    r'(?P<ident>\S+)\s'
    r'(?P<authuser>\S+)\s'
    r'\[(?P<time>[^\]]+)\]\s'
    r'"(?P<request>[^"]*)"\s'
    r'(?P<status>\d{3})\s'
    r'(?P<size>\S+)\s'
    r'"(?P<referer>[^"]*)"\s'
    r'"(?P<agent>[^"]*)"'
)

# Example: 10/Oct/2000:13:55:36 -0700
def _parse_time(ts_str: str) -> Optional[datetime]:
    try:
        dt = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def parse_apache_combined(line: str) -> Optional[LogRecord]:
    m = _COMBINED_RE.match(line.rstrip('\n'))
    if not m:
        return None
    gd = m.groupdict()
    ts = _parse_time(gd['time'])
    if ts is None:
        return None

    req = gd.get('request', '')
    method = path = proto = None
    if req:
        parts = req.split()
        if len(parts) == 3:
            method, path, proto = parts
        elif len(parts) == 2:
            method, path = parts[0], parts[1]

    try:
        status = int(gd['status'])
    except Exception:
        status = None

    size = None
    if gd['size'] not in ('-', ''):
        try:
            size = int(gd['size'])
        except Exception:
            size = None

    referer = gd.get('referer') or None
    agent = gd.get('agent') or None

    return LogRecord(
        ts=ts,
        src_ip=gd['host'],
        method=method,
        path=path,
        protocol=proto,
        status=status,
        bytes=size,
        referer=referer,
        ua=agent,
        raw=line.rstrip('\n')
    )
