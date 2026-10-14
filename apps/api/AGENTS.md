# @base-authorization/api

Ứng dụng NestJS ghép các adapter: config, health, authentication/session, administration, audit, domain demo D1 (review). Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của app.

## Ranh giới

- Logic phân quyền nằm trong packages; app chỉ khai báo (declarations/bindings) và ghép module. Không viết lại planner/compiler ở đây.
- Runtime mới có document fixture nhỏ (`product-manifest.ts`, `product-migration.ts`); không xây domain demo lớn hoặc UI.
- Handler không nhận DataSource/QueryRunner/credential thô; truy cập dữ liệu chỉ qua gateway/command của adapter.
- Không route HTTP cho provisioning, manifest upload hay superadmin bypass; các việc đó là CLI trong `tools/`.

## Hiện trạng

- `ProductRuntime` wire bốn DB logins, privilege probe, application fence và manifest sync vào AppModule thật trước listen/readiness. API env `.env.api` riêng; không migration/bootstrap/admin secret.
- Handler nhận `ProductHttpServices` chỉ gồm operations và HTTP config, không DataSource/manager/DB credentials hoặc bootstrap writer.
- Local/OIDC/session/recovery/link adapters ở package PostgreSQL; route thiếu classification làm boot fail. Guard kiểm session sớm, service vẫn recheck trong fenced transaction.
- API có document list/detail/update title và suspend user thấp cấp; OpenAPI examples/status ở `/openapi.json`, metrics labels hữu hạn ở `/health/metrics`.
- Recovery delivery default unavailable; generic administration/file/export/jobs chưa mở. `src/audit/audit-outbox.service.ts` là adapter lịch sử; product effects append audit trong transaction, sink chưa triển khai.

## Quy tắc khi sửa

- Biến môi trường mới: thêm vào `config.ts` có validation và vào `.env.example` (không giá trị thật).
- DTO có validation và Swagger examples; route khai báo success shape và mọi status thực tế. Không trả field ngoài projection, không phân biệt foreign/absent.
- Không log secret, token, cookie, authorization header hay PII.
- User admin không có capability reset/link/impersonate global identity.

## Cấu trúc và composition

- Khi thực hiện task refactor foundation, tổ chức theo capability (`auth`, `documents`, `administration`, `health`) và vùng composition/config/infrastructure theo plan. Đây là cấu trúc đích; không tự di chuyển toàn bộ file trong task sửa nhỏ.
- Controller chỉ xử lý HTTP input/output và gọi operation đã định nghĩa; không đặt SQL, parsing scalar, policy algebra hoặc orchestration DB trong controller/filter. Không tạo service chỉ chuyển tiếp nếu không có trách nhiệm riêng.
- Chọn adapter và bind DI ở composition root. Module runtime giữ pool/config nhạy cảm private; feature chỉ inject facade/token có operations cần thiết. Không cast facade về runtime để lấy capability bị ẩn.
- Di chuyển file phải giữ route paths/status, cookie, CSRF, trusted proxy, projection, route classification và bootstrap ordering. Cập nhật imports/exports/tests/OpenAPI cùng task, không bỏ validation/error handling khi tách controller.
- Error filter dùng mapping lỗi có chủ đích; lỗi không biết trả lỗi server an toàn, không biến thành 200/allow hoặc lộ DB detail. Giới hạn body/query/page size và validate trước khi gọi operation.
- Config mới phải fail boot nếu thiếu/sai và ảnh hưởng bảo mật; không default credential, permissive CORS/proxy hoặc fallback provider để app khởi động được. Không bật tính năng qua env khi semantics chưa được chốt.
- Recovery/mail/audit delivery không được coi là durable khi chỉ chạy promise nền; capability unavailable phải phản ánh đúng contract. Không thêm endpoint admin/debug để vượt provider hoặc xem secrets.

## Chạy

- `pnpm run start:dev` (build rồi chạy `apps/api/dist/main.js`, đọc `.env.api` nếu có).
- Smoke test: `pnpm run test:unit -- test/workspace.smoke-spec.ts`.
- HTTP E2E: `pnpm run test:e2e -- apps/api/test/product.e2e-spec.ts` (cần Docker). Khi đổi routes/DI/auth, kiểm cả trường hợp unauthenticated, unauthorized, invalid input và response projection liên quan; không chỉ happy path.
