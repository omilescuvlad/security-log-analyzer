from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, List
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
        d = self.model_dump()
        d["ts"] = self.ts.astimezone(timezone.utc).isoformat()
        d["src_ip"] = str(d["src_ip"])
        import json
        return json.dumps(d, ensure_ascii=False)

class Detection(BaseModel):
    rule_id: str
    severity: str
    ts_first: datetime
    ts_last: datetime
    src_ip: Optional[str] = None
    count: int
    summary: str
    evidence: List[str] = []

    def model_dump_jsonl(self) -> str:
        d = self.model_dump()
        d["ts_first"] = self.ts_first.astimezone(timezone.utc).isoformat()
        d["ts_last"] = self.ts_last.astimezone(timezone.utc).isoformat()
        import json
        return json.dumps(d, ensure_ascii=False)
