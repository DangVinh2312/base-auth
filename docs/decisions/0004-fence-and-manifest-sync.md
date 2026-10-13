# ADR 0004 — Tenant fence, revocation và manifest sync (Task 7–8)

Ngày: 2026-10-13. Trạng thái: chấp nhận theo quyết định của chủ dự án cho Task 7–8. Permission boundary (ADR 0003) **chưa** được enforce hoặc sync.

## Fence

- Tenant migration 002 tạo `public.authz_acquire_shared_fence(uuid) RETURNS bigint`: `SECURITY DEFINER`, `SET search_path = pg_catalog, pg_temp`, bảng schema-qualified, chỉ `SELECT … FOR SHARE` đúng dòng fence của tenant khớp `tenant_anchor`; thiếu dòng → `P0002` (fail closed). Không nhận SQL/tên bảng từ caller; trả revision đọc dưới khóa.
- Owner là role NOLOGIN riêng `<db>_fence` (không superuser/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS). Quyền tối thiểu: `USAGE` schema, `SELECT(tenant_id, revision)` + `UPDATE(tenant_id)` trên `authz_fence` (PostgreSQL yêu cầu UPDATE một cột cho `FOR SHARE`; `tenant_id` không đổi được vì FK + anchor), `SELECT(tenant_id)` trên `tenant_anchor`. `CREATE` trên schema chỉ cấp tạm trong transaction đổi owner rồi thu hồi.
- `REVOKE EXECUTE … FROM PUBLIC`; `EXECUTE` chỉ cho data role. Data role không còn quyền nào trên bảng `authz_fence` (không SELECT/UPDATE/FOR UPDATE).
- `TenantTransactionRunner`: READ COMMITTED; `statement_timeout`, `transaction_timeout` (PG 17+, tham chiếu 2 giây) và `lock_timeout` đặt bằng `set_config(..., true)` trong transaction; fence là statement đầu tiên, facts authority đọc ở statement sau. Chế độ phân loại trước: `read/write` (data, shared), `admin` (authority, `FOR UPDATE` + tăng revision khi thành công), `sync` (sync credential, `FOR UPDATE`; reconciler tự tăng revision khi có thay đổi). Không nâng shared → exclusive.
- Retry toàn transaction tối đa 2 lần cho 40P01/40001/55P03 có jitter → `TransactionConflictError` (409). Timeout, mất kết nối, thiếu fence → `AuthorityUnavailableError` (503), không retry. Side effect chỉ qua outbox trong transaction nên attempt bị rollback không để lại dấu.
- `PostgresAuthority.withSnapshot` gói fence → `readAuthorityFacts` → callback (plan, gateway, obligations) trong một transaction. Boundary delta sau này load binding trong cùng hàm đọc facts, cùng fence/revision.
- `fulfillObligations` chạy handler đã đăng ký trong transaction trước khi trả payload; thiếu/lỗi handler → rollback. `AuditOutboxService` (apps/api) ghi `audit_outbox` với revision của transaction; metadata chỉ scalar phẳng, ≤ 2 KB.

## Manifest sync

- Credential `<db>_sync` riêng theo tenant (LOGIN, không thuộc tính đặc quyền, CONNECT chỉ DB của tenant). Quyền: fence `SELECT, UPDATE(revision, manifest_hash, release_sequence)`; insert/so sánh catalog code-owned (`resource_type`, `permission_policy` + `UPDATE(lifecycle)`, `permission_catalog` + `UPDATE(policy_key, policy_version, lifecycle)`, `scope_template`, `resource_relation_definition` + `UPDATE(lifecycle)`), `role_definition` (`INSERT`, `UPDATE(label, authority_level)`), `policy_rule` (`INSERT` only), `relation_edge` (seeds), `object_ref`/`tenant_anchor` `SELECT`, `audit_outbox` `INSERT`. Không có quyền trên membership, member_role, record_exception, identity_relation; không DDL; không EXECUTE hàm fence.
- `prepareRelease` kiểm chứng và đóng băng release trước khi lấy khóa (giới hạn kích thước, tham chiếu, kiểu tham số/khóa), hash SHA-256 nội dung canonical. `ManifestReconciler.reconcile` chỉ nhận object từ `prepareRelease`; capability (validator/handler) thiếu → từ chối trước transaction.
- Protocol: cùng sequence + cùng hash → kiểm readiness (policy/catalog/role/seed code-owned còn đủ) và no-op; cùng sequence khác hash → `conflicting_release`; sequence cũ hơn → `downgrade` (không ghi); predecessor sai → `predecessor_mismatch`. Release mới: resource types → policies (version bất biến, đổi nội dung cùng version bị từ chối) → templates → relation definitions (resource → resource) → catalog (permission mới, chuyển binding, permission biến mất → deprecated) → code roles (role tenant cùng key → collision) → default grants (chỉ cho permission vừa tạo, id xác định) → seeds (va chạm tuple runtime/owner khác → rollback; thiếu object → rollback) → removal tường minh cùng owner → fence (revision+1, hash, sequence) → audit. Tất cả trong một transaction.
- `BootstrapCoordinator` (packages/nest) chạy trong `onApplicationBootstrap`, được Nest await trước khi `listen()` hoàn tất; tenant sync lỗi giữ tenant và process ở trạng thái not ready. Port sync dùng token không export khỏi `BootstrapModule`.
- Chưa có tool CLI/script `manifest:check`/`manifest:sync`: ứng dụng chưa có manifest D1 thật (Task 10). Chưa có chữ ký release; "verified" hiện nghĩa là được code deploy cung cấp + `prepareRelease`.

## Hệ quả và còn mở

- Mỗi tenant có 3 login role + 1 role NOLOGIN; budget kết nối local: data 5 + authority 2 + sync 2 cho mỗi tenant active.
- Tenant tạo trước Task 7 cần chạy lại `db:provision -- tenant --id <id>` để có sync role; `db:migrate` báo lỗi rõ nếu thiếu login role.
- Định nghĩa relation tới identity không có bảng DB (theo spec), nên `identity_relation` không có composite FK tới definition; tính hợp lệ được kiểm trong manifest code.
- Permission boundary: definitions/bindings/requirement chưa sync, chưa enforce (chờ delta ADR 0003).
