# Compliance mapping

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | chưa implement, xem stretch #4 (delete cascade: xoá 1 subject khỏi `customers.json`, giữ ledger nguyên vẹn) | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | data-flow inventory cho LLM API call | `reports/dpia-lite.md` §2, §3 |
| ASI03 — privilege abuse | per-agent identity + TTL trong ledger | `agent/policy.py` (`PolicyContext.agent_owner`, `delegation_depth`), `agent/runner.py` (`_run_id`, field `run_id` = `run-<timestamp>-<hash>`), ledger field `agent_owner` → `agent_id`/`run_id` trong `reports/ledger.jsonl` |
| ASI01 — goal hijack | trifecta split | `reports/attack-after.log` (rỗng), `agent/runner.py` (`handle`: Run A chỉ search_docs, Run B tra related_tickets, Run E bị deny), `reports/ledger.jsonl` dòng `tool=http_post, decision=deny` |
| ISO 42001 Clause 5-6 | policy-as-code có review | git log của `agent/policy.py` |
