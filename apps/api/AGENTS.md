# @base-authorization/api

Ứng dụng NestJS ghép các adapter: config, health, authentication/session, administration, audit, domain demo D1 (review). Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của app.

## Ranh giới

- Logic phân quyền nằm trong packages; app chỉ khai báo (declarations/bindings) và ghép module. Không viết lại planner/compiler ở đây.
- Runtime mới có document fixture nhỏ (`documents/document.declarations.ts`, `documents/migrations/product-document.ts`); không xây domain demo lớn hoặc UI.
- Handler không nhận DataSource/QueryRunner/credential thô; truy cập dữ liệu chỉ qua gateway/command của adapter.
- Import boundary (developer, không phải process isolation): `auth/`, `documents/`, `administration/`, `health/`, `openapi/` (mọi `*.ts` kể cả thư mục con, trừ `documents/migrations/`) chỉ import `@base-authorization/typeorm-postgres` root (error/type), facade token và `@nestjs/*`; ESLint `no-restricted-imports` chặn `typeorm`/`pg`, `typeorm-postgres/{composition,operations,legacy}`, `infrastructure/product-runtime|runtime.module` và đường dẫn private `packages/*/{src,dist}`. `infrastructure/` và `authorization/product-manifest.ts` (composition side) được import `./composition`; `tools/` được import `./composition` và `./operations`. `test/package-boundaries.spec.ts` chứng minh bằng ESLint thật, gồm negative check.
- Không route HTTP cho provisioning, manifest upload hay superadmin bypass; các việc đó là CLI trong `tools/`.

## Hiện trạng

- Chọn value codecs duy nhất ở `authorization/product-manifest.ts#createProductAuthorizationCore` (Day.js timestamp + standard codecs); `ProductRuntime.create` và `tools/product.ts` cùng gọi nó, release là `createProductRelease(core)` (không prepare lúc import).
- `ProductRuntime` wire bốn DB logins, privilege probe, application fence và manifest sync vào AppModule thật trước listen/readiness. API env `.env.api` riêng; không migration/bootstrap/admin secret.
- Handler nhận port token của capability (`AUTH_HTTP_PORT`, `DOCUMENTS_HTTP_PORT` đã bind `document.read/update`, `ADMINISTRATION_HTTP_PORT`, `METRICS_SNAPSHOT`, `ReadinessGate`) chỉ gồm operations và HTTP config; không DataSource/manager/DB credentials, runner hay offline command. `ProductRuntime` là provider private của `RuntimeModule`; `apps/api/test/structure.spec.ts` kiểm DI thật và inventory route/OpenAPI.
- Local/OIDC/session/recovery/link adapters ở package PostgreSQL; route thiếu classification làm boot fail. Guard kiểm session sớm, service vẫn recheck trong fenced transaction.
- API có document list/detail/update title và suspend IAM user (Root, hoặc grant + boundary; resource `account` bind `iam_account`); OpenAPI examples/status ở `/openapi.json`, metrics labels hữu hạn ở `/health/metrics`.
- Recovery delivery default unavailable; generic administration/file/export/jobs chưa mở. `src/legacy/audit-outbox.service.ts` là adapter lịch sử (chỉ test legacy dùng); product effects append audit trong transaction; adapter delivery `ProductAuditOutbox` (login `outbox`, ADR0011) có ở package nhưng chưa wire vì chưa có sink thật — không tạo sink giả, không inject vào controller.

## Quy tắc khi sửa

- Biến môi trường mới: thêm vào `config/app.config.ts` có validation và vào `.env.example` (không giá trị thật).
- DTO có validation và Swagger examples; route khai báo success shape và mọi status thực tế. Không trả field ngoài projection, không phân biệt foreign/absent.
- Không log secret, token, cookie, authorization header hay PII.
- User admin không có capability reset/link/impersonate global identity.

## Cấu trúc và composition

```text
src/main.ts, app.module.ts        # load config/listen; compose modules (không DB)
src/config/app.config.ts          # env parsing, secret-safe errors
src/infrastructure/               # runtime.module.ts (ProductRuntime private, export facades),
                                  # product-runtime.ts (pools, bootstrap, cleanup), http-security.ts,
                                  # product-error.filter.ts
src/auth/                         # auth/oidc controllers, auth.http-port.ts
src/documents/                    # controller, documents.http-port.ts, document.declarations.ts,
                                  # migrations/product-document.ts
src/administration/               # users.controller.ts, administration.http-port.ts, account.declarations.ts
src/health/                       # live/ready/metrics, product-metrics.ts
src/authorization/product-manifest.ts  # codecs + compose fragments + createProductRelease(core)
src/openapi/                      # openapi.controller.ts, product-openapi.ts
src/legacy/audit-outbox.service.ts
```

- Feature module chỉ khai báo controllers; `AppModule` import `RuntimeModule.register(runtime)` vào từng feature module. Capability mới: thêm port token + bound operations trong `runtime.module.ts`, declaration fragment vào `authorization/product-manifest.ts`; không `@Global()`, không export `ProductRuntime`.
- Controller chỉ xử lý HTTP input/output và gọi operation đã định nghĩa; không đặt SQL, parsing scalar, policy algebra hoặc orchestration DB trong controller/filter. Không tạo service chỉ chuyển tiếp nếu không có trách nhiệm riêng.
- Chọn adapter và bind DI ở composition root. Module runtime giữ pool/config nhạy cảm private; feature chỉ inject facade/token có operations cần thiết. Không cast facade về runtime để lấy capability bị ẩn.
- Di chuyển file phải giữ route paths/status, cookie, CSRF, trusted proxy, projection, route classification và bootstrap ordering. Cập nhật imports/exports/tests/OpenAPI cùng task, không bỏ validation/error handling khi tách controller.
- Error filter dùng mapping lỗi có chủ đích; lỗi không biết trả lỗi server an toàn, không biến thành 200/allow hoặc lộ DB detail. Giới hạn body/query/page size và validate trước khi gọi operation.
- Config mới phải fail boot nếu thiếu/sai và ảnh hưởng bảo mật; không default credential, permissive CORS/proxy hoặc fallback provider để app khởi động được. Không bật tính năng qua env khi semantics chưa được chốt.
- Recovery/mail/audit delivery không được coi là durable khi chỉ chạy promise nền; capability unavailable phải phản ánh đúng contract. Không thêm endpoint admin/debug để vượt provider hoặc xem secrets.

## Chạy

- `pnpm run start:dev` (build rồi chạy `apps/api/dist/main.js`, đọc `.env.api` nếu có).
- Smoke test: `pnpm run test:unit -- test/workspace.smoke-spec.ts`.
- Route/OpenAPI inventory, DI boundary, bootstrap failure (không Docker): `pnpm run test:unit -- apps/api/test/structure.spec.ts`. Đổi route/facade có chủ ý thì sửa literal trong test cùng lý do.
- HTTP E2E: `pnpm run test:e2e -- apps/api/test/product.e2e-spec.ts` (cần Docker). Khi đổi routes/DI/auth, kiểm cả trường hợp unauthenticated, unauthorized, invalid input và response projection liên quan; không chỉ happy path.
