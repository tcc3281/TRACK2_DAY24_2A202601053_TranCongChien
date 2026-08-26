"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành các run riêng biệt, KHÔNG run nào cầm cả
3 chân của lethal trifecta cùng lúc:

    Run A (untrusted): search_docs. Trả về ticket_id trích từ TÊN FILE —
            một typed value, không phải free text. Chỉ thị injection tìm
            thấy trong nội dung document CHỈ được ghi ledger để audit,
            tuyệt đối không dùng customer_id/URL nó trả về.
    Run B (private data): với mỗi ticket_id từ Run A, tra NGUỒN TIN CẬY
            `related_tickets` trong data/customers.json để suy ra
            customer_id, rồi mới read_customer. Free text của attacker
            không bao giờ đi qua cửa này.
    Run E (egress): mọi ý định gọi http_post đi qua policy.check() với
            egress_enabled=True + dữ liệu restricted → DENY. Sink chỉ
            còn trên giấy — trong ledger.

Containment, không phải mitigation: attacker viết lại chỉ thị thế nào
(biến thể 5) cũng vô nghĩa, vì Run B không ĐỌC free text để quyết định
gọi ai.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger as ledger_mod
from agent import tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_ID_RE = re.compile(r"ticket-(\d+)")
_CUSTOMERS_PATH = Path(__file__).resolve().parent.parent / "data" / "customers.json"

AGENT_ID = "lab24-agent"


def _run_id(message: str) -> str:
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()[:12]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"run-{ts}-{digest}"


def _args_hash(args: dict) -> str:
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _ticket_to_customers() -> dict[int, list[str]]:
    """Nguồn tin cậy: map ticket number -> customer_id từ related_tickets."""
    customers = json.loads(_CUSTOMERS_PATH.read_text(encoding="utf-8"))
    mapping: dict[int, list[str]] = {}
    for customer in customers:
        for ticket in customer.get("related_tickets", []):
            mapping.setdefault(int(ticket), []).append(customer["customer_id"])
    return mapping


def _audit(
    path: Path, run_id: str, run: str, tool: str, ctx: PolicyContext, args: dict
) -> tuple[bool, str]:
    allow, reason = check(ctx)
    ledger_mod.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": AGENT_ID,
            "run_id": f"{run_id}/{run}",
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": ctx.data_classification,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        },
        path,
    )
    return allow, reason


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    rid = _run_id(message)

    # ── Run A: untrusted content ─────────────────────────────────────────
    ctx_a = PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner=f"{AGENT_ID}/run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_a, _ = _audit(
        ledger_path, rid, "run-a", "search_docs", ctx_a, {"query": message}
    )
    if not allow_a:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Phát hiện injection chỉ để LOG — customer_ids/url trả về bị bỏ đi.
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # Typed handoff A -> B: chỉ tên file -> số nguyên ticket id.
    ticket_ids: list[int] = []
    for doc in docs:
        m = _TICKET_ID_RE.match(doc["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # ── Run B: private data, suy customer_id từ nguồn tin cậy ───────────
    mapping = _ticket_to_customers()
    customer_ids: list[str] = []
    for tid in sorted(set(ticket_ids)):
        for cid in mapping.get(tid, []):
            if cid not in customer_ids:
                customer_ids.append(cid)

    records = []
    ctx_b = PolicyContext(
        data_classification="restricted",
        request_purpose="reconciliation",
        agent_owner=f"{AGENT_ID}/run-b",
        delegation_depth=0,
        egress_enabled=False,  # chân "private data" tách khỏi chân "exfil"
    )
    for cid in customer_ids:
        allow_b, _ = _audit(
            ledger_path, rid, "run-b", "read_customer", ctx_b, {"customer_id": cid}
        )
        if not allow_b:
            continue
        try:
            records.append(tools.read_customer(cid))
        except tools.ToolError:
            continue

    # ── Run E: egress luôn bị policy chặn với dữ liệu restricted ────────
    if injected is not None and records:
        ctx_e = PolicyContext(
            data_classification="restricted",
            request_purpose=injected.target_url,
            agent_owner=f"{AGENT_ID}/run-e",
            delegation_depth=0,
            egress_enabled=True,
        )
        _audit(
            ledger_path,
            rid,
            "run-e",
            "http_post",
            ctx_e,
            {"url": injected.target_url, "record_count": len(records)},
        )

    return llm.summarize(docs)
