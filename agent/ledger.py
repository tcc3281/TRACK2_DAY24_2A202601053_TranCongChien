"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Hash chain: `hash` của dòng n tính từ toàn
bộ nội dung dòng đó (bao gồm prev_hash = hash của dòng n-1), nên sửa/xoá/
chèn bất kỳ dòng nào giữa file sẽ làm chuỗi gãy và verify() trả False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_GENESIS_HASH = "0" * 64


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False)


def _last_hash(path: Path) -> str:
    if not path.exists():
        return _GENESIS_HASH
    last = ""
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if not last:
        return _GENESIS_HASH
    try:
        return json.loads(last)["hash"]
    except (json.JSONDecodeError, KeyError):
        return _GENESIS_HASH


def append(entry: dict, path: Path) -> dict:
    record = {k: v for k, v in entry.items() if k not in ("prev_hash", "hash")}
    record["prev_hash"] = _last_hash(path)
    record["hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    if not path.exists():
        return False
    prev_hash = _GENESIS_HASH
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False
            if not record.get("reason"):
                return False
            if record.get("prev_hash") != prev_hash:
                return False
            stored_hash = record.get("hash")
            recomputed = hashlib.sha256(
                _canonical({k: v for k, v in record.items() if k != "hash"}).encode("utf-8")
            ).hexdigest()
            if stored_hash != recomputed:
                return False
            prev_hash = stored_hash
    return True
