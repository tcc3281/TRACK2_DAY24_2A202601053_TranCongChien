"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex-first cho tiếng Việt (Presidio mặc định chỉ hỗ trợ "en"):
    EMAIL            local@domain.tld
    VN_BANK_ACCOUNT  8-16 chữ số, đi kèm "STK"/"số tài khoản"
    VN_CCCD          12 chữ số liên tiếp (không thuộc ngữ cảnh STK)
    VN_PHONE         0 + 9 chữ số, có thể có dấu cách/gạch ngang

Thứ tự nhận diện quan trọng để tránh chồng lấn: một số 12 chữ số đứng sau
"STK" là tài khoản (VN_BANK_ACCOUNT), đứng ngoài ngữ cảnh đó mới là CCCD.
detect() trả entity theo offset slice Python [start:end); redact() thay từ
cuối văn bản về đầu để offset không bị lệch.
"""
from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

_BANK_RE = re.compile(
    r"(?:STK|số\s*tài\s*khoản|tai\s*khoan|so\s*tai\s*khoan)\s*[:\-]?\s*(\d{8,16})",
    re.IGNORECASE,
)

_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

_PHONE_RE = re.compile(r"(?<!\d)0(?:[ .\-]?\d){8,9}(?!\d)")


def _overlaps(a: dict, b: dict) -> bool:
    return a["start"] < b["end"] and b["start"] < a["end"]


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    for m in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    for m in _BANK_RE.finditer(text):
        start = m.start(1)
        entities.append(
            {"type": "VN_BANK_ACCOUNT", "start": start, "end": start + len(m.group(1))}
        )

    for m in _CCCD_RE.finditer(text):
        candidate = {"type": "VN_CCCD", "start": m.start(), "end": m.end()}
        if any(_overlaps(candidate, e) for e in entities):
            continue
        entities.append(candidate)

    for m in _PHONE_RE.finditer(text):
        candidate = {"type": "VN_PHONE", "start": m.start(), "end": m.end()}
        if any(_overlaps(candidate, e) for e in entities):
            continue
        entities.append(candidate)

    return entities


def redact(text: str) -> str:
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        placeholder = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + placeholder + text[entity["end"] :]
    return text
