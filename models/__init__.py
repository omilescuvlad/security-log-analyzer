from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, IPvAnyAddress, Field

class LogRecord(BaseModel):
    ts: datetime = Field(..., description="Timestamp UTC")
    src_ip: IPvAnyAddress
    method: Optional[str] = None
    path: Optional[str] = None
    protocol: Optional[str] = None
    status: Optional[int] = None
    bytes: Optional[int] = None
    referer: Optional[str] = None
    ua: Optional[str] = None
    raw: str

    def model_dump_jsonl(self) -> str:
        # serialize cu tz UTC ISO 8601
        d = self.model_dump()
        d["ts"] = self.ts.astimezone(timezone.utc).isoformat()
        # convertim IP-ul la string (altfel json.dumps arunca TypeError)
        d["src_ip"] = str(d["src_ip"])
        import json
        return json.dumps(d, ensure_ascii=False)
