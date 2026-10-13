# ADR 0002 — Lõi quyết định, ReBAC có kiểu và SQL compiler (Task 4–6)

Ngày: 2026-10-13. Trạng thái: chấp nhận cho Task 4–6; cập nhật sau Task 7 (xem ADR 0004). Mục "Còn mở" chưa được phê duyệt.

## Quyết định

### Lõi (`packages/core`)

- Hai tầng AST: `Expr` (khai báo do code hệ thống viết, có `ValueRef`) và `PlanExpr` (đã hạ kiểu, mọi giá trị đã bind). Compiler và evaluator chỉ nhận `PlanExpr`. `not` và `exception` chỉ do lõi tạo; validator từ chối mọi operator/nguồn giá trị lạ (fail closed).
- `P = requiredScope AND (allow scopes OR record allow) AND NOT (deny scopes OR record deny)`; tenant, membership, catalog/policy binding, context validators và obligation handlers kiểm tra trước. Bất kỳ rule hỏng nào (template/tham số/kiểu) làm cả quyết định deny, không bỏ qua rule.
- Null: so sánh với NULL không khớp. Để `NOT D` trong SQL không thành NULL, template dùng cho deny không được so sánh field nullable ngoài `exists` (dùng `isNull` tường minh); vi phạm → deny lúc plan.
- Số nguyên là chuỗi thập phân int64 chuẩn hoặc `bigint`; JS `number` bị từ chối. Decimal so sánh chính xác bằng chuỗi. Chuỗi so theo code point (= thứ tự byte UTF-8 = `COLLATE "C"`). Timestamp chuẩn hóa 6 chữ số thập phân, UTC.
- `validate` trả bản đóng băng + `canonical` JSON không phụ thuộc thứ tự khai báo; `plan` chỉ nhận declarations do `validate` tạo (WeakSet). Lõi không có crypto nền tảng: adapter băm `canonical` (SHA-256) cho manifest hash ở Task 8.
- Không có node tham chiếu template/policy khác, nên vòng tham chiếu không biểu diễn được; node lạ bị từ chối. Path ReBAC tối đa 8 bước (manifest có thể hạ thấp hơn).
- Validator ngữ cảnh và obligation handler là registry của adapter; lõi chỉ nhận kết quả `true`. `false`, `'unknown'`, throw hoặc thiếu handler đều deny.
- Ngoại lệ `purpose='emergency'` **không bao giờ cấp quyền** cho tới khi hợp đồng kích hoạt khẩn cấp D3 (Task 12) được triển khai; deny ngoại lệ luôn có hiệu lực.
- Property test (thêm deny không mở rộng quyền; tenant khác không bao giờ allow) dùng PRNG có seed trong test, không thêm `fast-check`.

### Adapter PostgreSQL (`packages/typeorm-postgres`)

- `BindingRegistry` kiểm tra lúc khởi tạo: mọi resource/field có binding, identifier an toàn, projection thuộc field đã khai báo, relation `domain` có binding. Binding `domain` tới resource (không phải identity) chưa hỗ trợ → lỗi readiness.
- Bảng nghiệp vụ có `object_id` (UNIQUE(tenant, object_id) + FK `object_ref`); EXISTS cho edge/exception join theo `object_id`, không cần mã hóa khóa trong SQL. So khóa chính bằng bind có kiểu (`CAST($n AS int8|uuid|text)`), không cast cột; EXPLAIN test xác nhận dùng `*_pkey`.
- ~~`identity_relation.relation_key` lưu `key@version`~~ — đã bỏ. Từ tenant migration 002, `identity_relation` có cột `relation_version` (NOT NULL, > 0, nằm trong PK và index); `relation_key` chỉ chứa key. Migration backfill dữ liệu cũ dạng `key@N` và dừng (raise) nếu gặp giá trị không chuyển đổi chắc chắn. Compiler/fixtures/entity đã cập nhật.
- Mọi cạnh kiểm tra tenant và cửa sổ hiệu lực bằng `statement_timestamp()`; hạn của plan cũng kiểm bằng đồng hồ DB trong cùng statement.
- Giá trị luôn là bind parameter: raw dùng `$n`, QueryBuilder dùng tên duy nhất theo process (`authz_<seq>_<n>`). Không thay chuỗi SQL bằng regex.
- `DataGateway`: list/detail/count với cùng predicate; list dùng `count(*) OVER ()` để tổng và trang cùng statement; filter người dùng chỉ trên field projection, bọc AND sau predicate; limit ≤ 100, offset ≤ 10 000; sắp xếp luôn có khóa làm tie-breaker. Integer/decimal/timestamp trả về dạng text chuẩn.
- QueryBuilder bridge trả bảng dẫn xuất đã lọc quyền chỉ có `key` + projection; `.where()`/`.orWhere()` của handler không gỡ được predicate; join resource khác qua `subQuery(plan)` của chính resource đó.
- Gateway nhận `TenantTransaction` (Task 7): plan phải cùng tenant **và cùng revision** với transaction đang giữ fence. `readAuthorityFacts(tx, identity)` đọc trong transaction đó, revision lấy dưới fence.

## Còn mở

1. ~~Cơ chế shared fence~~ — đã chốt ở ADR 0004.
2. Raw SQL template đã đăng ký (slot predicate) chưa triển khai; hiện chỉ có list/detail/count và QueryBuilder bridge.
3. `mutate` (write path, pre/post state) thuộc Task 10.
4. JSON Schema/Ajv cho tham số template: hiện dùng map tên → `FieldKind` có kiểm tra kiểu; Ajv chỉ thêm khi cần schema phức tạp hơn.
