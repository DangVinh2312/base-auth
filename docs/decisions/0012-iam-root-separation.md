# ADR 0012 — IAM thuần và Root tách khỏi IAM

Ngày: 2026-10-15. Trạng thái: chấp nhận; thiết kế ở `docs/superpowers/specs/2026-10-14-iam-root-separation-design.md`, triển khai và bằng chứng ở `docs/superpowers/plans/2026-10-15-iam-root-separation.md` (ledger) và `docs/single-product-verification.md`.

Supersede: ADR 0007 (phần "Root không bypass"; grants tường minh cho Root và system-grant reconciliation); ADR 0008 ("Permission boundaries và Root không có bypass" — phần Root; Root là role `system.root`; rank và `account_rank` của migration 006; bảo vệ peer bằng rank; Root bootstrap với exact mandatory boundaries; nhánh `user_role` của guard 004, `require_root_marker` của 007 và `protect_system_activation` của 008 — migration `012` thay bằng guard Root riêng); ADR 0009 (chỉ phần nhắc "Root không bypass"; semantics audit của 0009 giữ nguyên). Các ADR đó giữ nguyên làm lịch sử.

## Bối cảnh

Đây là auth cho một sản phẩm duy nhất của một tổ chức cố định, không phải SaaS. Root là super admin của chính tổ chức đó, tương đương AWS root user so với IAM user. Rank (`authority_level`, `account_rank`) chồng một thứ bậc ngầm lên grant/deny/boundary và làm Root phụ thuộc grants code-owned.

## Quyết định

- **Root ngoài IAM.** `app_user.kind ∈ {root, iam}`, tối đa một Root (partial unique index). Root không có role, grant, boundary, record exception hay direct rule (`guard_root_not_iam_subject`). Root bypass mọi kiểm tra phân quyền qua `planUnrestricted` trên mọi resource/action đã khai báo, kể cả action thêm sau này. `kind` chỉ lấy từ `resolve_session` trong fenced transaction; tên role không tạo bypass.
- **Root vẫn phải qua:** session hợp lệ, `auth_epoch`, không suspended, CSRF/Origin; fresh-auth 300 giây (tính trong SQL bằng `statement_timestamp()`, chính xác µs) cho ghi `write`/`admin`; action đã khai báo; projection và writable allowlist; một event audit cho mỗi `access` commit (`principalKind: 'root'`, `outcome`), ghi trực tiếp, không qua obligation registry. Denied không audit. Event đọc (list/detail/count) của Root dạng `access.<resource>.<action>`, ghi dùng `data.update`/`account.suspend` (`outcome` `ok`/`absent`); event obligation `audit@1` của IAM giữ dạng `access.<action>`.
- **IAM không rank.** Bảo vệ giữa IAM principal chỉ bằng grant, deny và permission boundary. Action tác động lên principal khác phải là `boundary: 'required'`; `account.suspend` hiện chỉ Root dùng được vì chưa có boundary nào cho `account`.
- **Bootstrap/revoke.** `bootstrap` chuyển một account pending `iam → root` đúng một lần cùng marker; `revoke-root` = suspended + tăng `auth_epoch`, marker giữ nguyên nên không có Root mới.
- **Genesis.** Reconciler product nhận release bất kỳ làm release đầu khi `release_sequence = 0` và catalog code-owned rỗng (cùng bảng/predicate với `protectedStateHash`); mọi trường hợp khác giữ predecessor nghiêm ngặt.
- **Migration 012 công bố `materialized_hash`.** Kiểm drift trước (hoặc catalog rỗng ở sequence 0), chuyển đổi, rồi (khi `release_sequence > 0`) đặt `materialized_hash = protectedStateHash` trên trạng thái sau chuyển đổi và tăng `revision` 1 trong cùng transaction; không đổi `release_sequence`/`manifest_hash`; không baseline ngầm.
- **Protocol khóa.** Promotion khóa `FOR NO KEY UPDATE` dòng target trước khi kiểm; guard gắn fact/token đọc `kind` bằng `FOR SHARE` (FK `FOR KEY SHARE` không đủ). Promotion chỉ ở READ COMMITTED (guard từ chối mức khác). Lock ordering chỉ cam kết cho cặp promotion và gắn fact/token; `issueActivation` có thể gặp deadlock với SQL ngoài runner → fail closed, runner retry `40P01` hữu hạn.
- **`down` không đảo ngược** (`irreversible; restore from backup`): rank, role `system.root` và grants Root không khôi phục được và `release_sequence` không giảm. Rollback vận hành là restore backup hoặc forward repair.
- **Repair gỡ suspend Root** chỉ offline do owner bảng: một transaction `DISABLE TRIGGER guard_root_lifecycle` → `UPDATE` đúng dòng Root → `ENABLE`. Không ghi `audit_outbox`; bằng chứng là hồ sơ approval (reference, người duyệt, thời điểm, câu SQL).
- **Provenance.** Chỉ evaluator kiểm tập `issued`; SQL compiler và gateway dựa vào việc chỉ composition dựng được gateway. ESLint `no-restricted-syntax` giới hạn nơi gọi `planUnrestricted` là ranh giới developer, không phải sandbox.

## Rủi ro đã chấp nhận

- Lộ session Root cho phép đọc mọi dữ liệu nghiệp vụ; trong cửa sổ 300 giây sau reauth thì ghi được. Reauth OIDC phụ thuộc IdP. Giảm thiểu đầy đủ (MFA) thuộc spec MFA.
- Credential identity là ranh giới tin cậy của toàn bộ đăng nhập: `product_identity` bị chiếm có thể tạo session (kể cả `reauthenticated_at`) cho Root active.
- Mọi resource/action thêm sau tự động mở cho Root.
- Không còn bảo vệ peer mặc định giữa IAM principal (đúng mô hình IAM).
- Definition `rootAccounts@1` còn lại như dòng code-owned không binding sau nâng cấp.
- Migration import `protectedStateHash` của chính package: migration và binary release 2 phải cùng version.
- Không có Root sau nâng cấp khi Root đã bị revoke trước đó; cần repair offline có duyệt.
- Repair gỡ suspend dựa vào quyền DDL của owner bảng; DB không chặn owner.
- Chưa đo timing giữa Root/absent ở suspend.
