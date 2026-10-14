# ADR 0011 — Login `outbox` và delivery audit at-least-once

Ngày: 2026-10-14. Trạng thái: chấp nhận cho phần audit của T10 (giai đoạn B); recovery delivery vẫn bị chặn. Bằng chứng ở ledger §6 của kế hoạch Foundation Hardening.

## Bối cảnh

Mọi product writer ghi `audit_outbox` trong cùng transaction với effect (ADR 0009), nhưng chưa có gì đưa event ra sink độc lập. Mọi login runtime chỉ có `INSERT` trên `audit_outbox`; cấp `SELECT/UPDATE` cho một login hiện có (identity/sync…) sẽ cho login đó đọc audit của mọi người dùng và sửa trạng thái delivery ngoài mục đích của nó.

## Quyết định

- Thêm purpose `outbox` (login `product_outbox`, provision cùng các login khác; `PRODUCT_OUTBOX_PASSWORD` bắt buộc khi `db:provision`). Ma trận quyền chính xác: `SELECT` trên `audit_outbox`; `UPDATE` chỉ các cột `delivered_at`, `delivery_attempts`, `lease_token`, `lease_until`, `dead_at`. Không `INSERT/DELETE`, không sửa nội dung event, không đọc bảng khác, không EXECUTE fence/`resolve_session`. `verifyProductPrivileges` kiểm login này như mọi login runtime; test âm tính chạy bằng login thật.
- Migration 010 thêm các cột trên (event cũ thành pending, `delivery_attempts=0`); migration 011 tạo partial index `(occurred_at,event_id) WHERE delivered_at IS NULL AND dead_at IS NULL` bằng `CREATE INDEX CONCURRENTLY` (không chặn insert audit). `USAGE` trên schema `public` cho `product_outbox` do provisioning cấp (migration login không sở hữu schema).
- `ProductAuditOutbox` (`./composition`): `claim` chọn tối đa `batchSize` event chưa giao, chưa park, không có lease còn hạn, `FOR UPDATE SKIP LOCKED`, gán `lease_token` mới, `lease_until`, tăng `delivery_attempts` — một transaction ngắn. Gửi tới `ProductAuditSink.deliver` tuần tự, **không** mở transaction nào và không lấy application fence; mỗi lần gửi có timeout, và `leaseMs ≥ batchSize × deliveryTimeoutMs` được kiểm khi tạo. `acknowledge` là transaction riêng, chỉ có hiệu lực khi `lease_token` còn khớp (ack của worker đã mất lease bị bỏ qua): thành công → `delivered_at`; thất bại → backoff `min(maxBackoffMs, backoffMs × 2^(attempts−1))` qua `lease_until`, hoặc `dead_at` khi đạt `maxAttempts` (park, không tự xóa, chờ operator). Attempt đếm lúc claim; event đã dùng hết `maxAttempts` mà lease hết hạn không có ack (worker crash) bị park ở lần claim kế tiếp, nên crash lặp lại cũng dừng ở trạng thái park. Dòng có `safe_metadata` không phải map chuỗi phẳng không được gửi, tính là một lần thất bại (rồi park), không chặn event khác trong batch.
- Delivery là **at-least-once**: crash sau khi gửi và trước ack sẽ gửi lại sau khi lease hết hạn. Sink phải idempotent theo `eventId` và chỉ resolve khi đã lưu bền. Không hứa exactly-once qua mạng. Lỗi sink không được log nội dung (có thể chứa dữ liệu event); worker chỉ giữ kết quả retry/park.
- Chưa có sink thật: không có provider, endpoint hay key management được cung cấp, và không tạo provider giả trả success. Vì vậy worker **chưa được wire** vào API hay CLI; event tiếp tục tích lũy trong outbox như trước. Khi chọn sink: quyết định nơi chạy worker (process riêng hay trong API), cấu hình credential `PRODUCT_OUTBOX_DATABASE_URL` cho đúng process đó, vòng lặp/khoảng nghỉ, metrics hữu hạn và runbook xử lý event bị park.
- Recovery delivery (mail reset) giữ 503: chưa chốt kênh gửi, mã hóa payload, sở hữu key, TTL và ACL. Reset token không được ghi vào `audit_outbox` dưới dạng plaintext hay digest (test `reset tokens never reach the audit outbox…`); outbox này không dùng làm hàng đợi recovery.

## Hệ quả

Có thêm một credential cần cấp phát/xoay vòng và một login trong probe khởi động. Nâng cấp deployment cũ: thêm `PRODUCT_OUTBOX_PASSWORD` vào `.env.ops` rồi chạy lại `db:provision` (tạo login, áp migration 009–011). Retention/xóa event đã giao chưa được quyết định (outbox login không có DELETE). Thứ tự event giao theo `occurred_at,event_id` trong một batch nhưng không bảo đảm giữa các worker hay khi retry; sink không được dựa vào thứ tự. Không gọi production-ready.
