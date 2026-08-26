# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Agent chạm vào hai kho dữ liệu:

- **`corpus/*.md`** (qua `search_docs`) — ticket khách hàng dạng văn bản
  tự do: mô tả sự cố, và có thể chứa PII người dùng gõ vào (CCCD, SĐT,
  STK, email, tên). Đây là nội dung **untrusted**: bất kỳ ai ghi được vào
  corpus đều có thể cài payload (đã chứng minh bằng 5 biến thể trong
  `injection-corpus.md`).
- **`data/customers.json`** (qua `read_customer`) — private data store:
  `name`, `cccd` (12 số), `phone`, `bank_account`, `email`,
  `related_tickets`. Toàn bộ synthetic, nhưng cấu trúc giống PII thật.

Gate PII (`agent/pii.py`) nhận diện đúng 4 loại trên với precision/recall
1.000 trên `tests/vn_pii_testset.jsonl`.

## 2. Mục đích gì

- `search_docs`: tổng hợp ticket theo yêu cầu người dùng (ví dụ "Tổng hợp
  các ticket còn mở tuần này") — cần đọc nội dung ticket.
- `read_customer`: tra hồ sơ khách để đối soát/tiếp nhận khiếu nại —
  purpose khai trong policy là `reconciliation`
  (`agent/policy.py`, `PolicyContext.request_purpose`).
- Không có mục đích hợp lệ nào yêu cầu gửi hồ sơ khách ra ngoài hệ thống.

## 3. Chảy đi đâu

- **Trong lab:** đích exfil duy nhất là sink `localhost:9999/reconcile`.
  Trước containment, prompt injection khiến toàn bộ PII của KH-000999 POST
  ra đó (xem `reports/attack-before.log`). Sau containment, egress bị policy
  deny với dữ liệu restricted (`reports/ledger.jsonl`, dòng
  `tool=http_post, decision=deny`; `reports/attack-after.log` rỗng).
- **Với model thật (`--model claude-...`):** nội dung ticket và kết quả
  tool sẽ được gửi sang API của Anthropic (provider đặt server ngoài Việt
  Nam) — đây là **chuyển dữ liệu cá nhân xuyên biên giới** theo NĐ 356/2025
  và phải nằm trong hồ sơ 60 ngày. Lab này chấm bằng `--mock` nên đường
  chảy này không kích hoạt, nhưng phải ghi nhận: nếu bật `--model`, agent
  hiện **chưa có** egress control chặn việc gửi free-text chứa PII sang
  provider; control hiện có là allowlist `localhost:9999` trong
  `agent/tools.py:http_post` và deny rule restricted+egress trong
  `agent/policy.py`.
- **Log nội bộ:** `reports/ledger.jsonl` chỉ ghi hash của args
  (`args_hash`), không ghi giá trị PII — giảm nguy cơ rò rỉ thứ cấp qua
  audit trail.
