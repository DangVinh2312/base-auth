# @base-authorization/api

Ứng dụng NestJS duy nhất: config, health, authentication/session, authorization, administration, audit, database và domain demo D1 (review). Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của app. ADR 0013 ghi việc gom bốn package vào app; không đổi hành vi quyền/dữ liệu.

## Ranh giới

- Logic phân quyền nằm trong `authorization/`; core thuần ở `authorization/core`, compiler/gateway và services ở cùng module. Không viết lại planner/compiler khi thêm feature; dùng implementation hiện có.
- Runtime mới có document fixture nhỏ (`document/document.declarations.ts`, `document/migrations/product-document.migration.ts`); không xây domain demo lớn hoặc UI.
- Handler không nhận DataSource/QueryRunner/credential thô; truy cập dữ liệu chỉ qua gateway/command của adapter.
- Import boundary (developer, không phải process isolation): HTTP feature handlers không import driver, gateway/compiler, authority/identity services, raw runtime hoặc offline commands ở runtime; được import types, facade tokens và HTTP helpers. `auth/services/` và migrations được dùng TypeORM trực tiếp. `infrastructure/` ghép services; provision/migrate/bootstrap chỉ tools dùng. `test/module-boundaries.spec.ts` kiểm bằng ESLint thật, gồm negative cases và Root bypass.
- Không route HTTP cho provisioning, manifest upload hay superadmin bypass; các việc đó là CLI trong `tools/`.

## Hiện trạng

- Chọn value codecs duy nhất ở `authorization/product.manifest.ts#createProductAuthorizationCore` (Day.js timestamp + standard codecs); `ProductRuntime.create` và `tools/product.ts` cùng gọi nó, release là `createProductRelease(core)` (không prepare lúc import).
- `ProductRuntime` wire bốn DB logins, privilege probe, application fence và manifest sync vào AppModule thật trước listen/readiness. API env `.env.api` riêng; không migration/bootstrap/admin secret.
- Handler nhận port token của capability (`AUTH_HTTP_PORT`, `DOCUMENT_HTTP_PORT` đã bind `document.read/update`, `ADMINISTRATION_HTTP_PORT`, `METRICS_SNAPSHOT`, `ReadinessGate`) chỉ gồm operations và HTTP config; không DataSource/manager/DB credentials, runner hay offline command. `ProductRuntime` là provider private của `RuntimeModule`; `apps/api/test/structure.spec.ts` kiểm DI thật và inventory route/OpenAPI.
- Local/OIDC/session/recovery/link ở `auth/services/`; route thiếu classification làm boot fail. Guard ở `authorization/enforcement/` kiểm session sớm, service vẫn recheck trong fenced transaction.
- API có document list/detail/update title và suspend IAM user (Root, hoặc grant + boundary; resource `account` bind `iam_account`); OpenAPI examples/status ở `/openapi.json`, metrics labels hữu hạn ở `/health/metrics`.
- Recovery delivery default unavailable; generic administration/file/export/jobs chưa mở. Product effects append audit trong transaction; `audit/product-outbox.service.ts` (login `outbox`, ADR0011) chưa wire vì chưa có sink thật — không tạo sink giả, không inject vào controller.

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
                                  # product-runtime.service.ts (pools, bootstrap, cleanup), http-security.helper.ts,
                                  # product-error.filter.ts
src/auth/                         # controllers/auth.controller.ts, controllers/oidc.controller.ts,
                                  # auth.module.ts, auth.http-port.ts
src/document/                     # controller, document.http-port.ts, document.declarations.ts,
                                  # migrations/product-document.migration.ts
src/administration/               # user.controller.ts, administration.http-port.ts, account.declarations.ts
src/health/                       # live/ready/metrics, product-metrics.service.ts
src/authorization/product.manifest.ts  # codecs + compose fragments + createProductRelease(core)
src/authorization/core/          # pure validation/planner/evaluator, không I/O/framework
src/authorization/values/        # strict value codecs
src/authorization/enforcement/   # Nest route classification/inventory/guard
src/authorization/services/      # authority và manifest sync
src/authorization/helpers/       # shared release validation, obligations, drift hashes
src/auth/services/               # identity/session/password và OIDC
src/database/                    # fixed-purpose transactions, DB probes/config, migrations
src/audit/                       # atomic audit writer và outbox delivery
src/openapi/                      # openapi.controller.ts, product-openapi.schema.ts
```

- Feature module chỉ khai báo controllers; `AppModule` import `RuntimeModule.register(runtime)` vào từng feature module. Capability mới: thêm port token + bound operations trong `runtime.module.ts`, declaration fragment vào `authorization/product.manifest.ts`; không `@Global()`, không export `ProductRuntime`.
- Controller chỉ xử lý HTTP input/output và gọi operation đã định nghĩa; không đặt SQL, parsing scalar, policy algebra hoặc orchestration DB trong controller/filter. Không tạo service chỉ chuyển tiếp nếu không có trách nhiệm riêng.
- Chọn adapter và bind DI ở composition root. Module runtime giữ pool/config nhạy cảm private; feature chỉ inject facade/token có operations cần thiết. Không cast facade về runtime để lấy capability bị ẩn.
- Services import implementation trực tiếp; không thêm interface/repository abstraction chỉ để theo Clean Architecture. Core vẫn thuần và không biết tên domain hoặc Root.
- SQL chỉ parameterized, identifiers từ binding đã đăng ký; transaction chỉ dùng manager được truyền vào. Giữ DB clock/microseconds/collation, fence trước facts, audit/revision cùng commit; không network/hash mật khẩu trong fence.
- Migrations không đổi tên/timestamp/SQL đã áp dụng; thêm forward migration nếu cần semantics mới. Privilege/protection probes và negative tests phải khớp login/ACL/function/trigger thật; không gộp credentials.
- `ProductAuditOutbox` gửi ngoài transaction/fence, ack theo lease token và retry hữu hạn; chưa có sink thì không tự wire worker.
- Di chuyển file phải giữ route paths/status, cookie, CSRF, trusted proxy, projection, route classification và bootstrap ordering. Cập nhật imports/exports/tests/OpenAPI cùng task, không bỏ validation/error handling khi tách controller.
- Error filter dùng mapping lỗi có chủ đích; lỗi không biết trả lỗi server an toàn, không biến thành 200/allow hoặc lộ DB detail. Giới hạn body/query/page size và validate trước khi gọi operation.
- Config mới phải fail boot nếu thiếu/sai và ảnh hưởng bảo mật; không default credential, permissive CORS/proxy hoặc fallback provider để app khởi động được. Không bật tính năng qua env khi semantics chưa được chốt.
- Recovery/mail/audit delivery không được coi là durable khi chỉ chạy promise nền; capability unavailable phải phản ánh đúng contract. Không thêm endpoint admin/debug để vượt provider hoặc xem secrets.

## Chạy

- `pnpm run start:dev` (build rồi chạy `apps/api/dist/main.js`, đọc `.env.api` nếu có).
- Smoke test: `pnpm run test:unit -- test/workspace.smoke-spec.ts`.
- Route/OpenAPI inventory, DI boundary, bootstrap failure (không Docker): `pnpm run test:unit -- apps/api/test/structure.spec.ts`. Đổi route/facade có chủ ý thì sửa literal trong test cùng lý do.
- HTTP E2E: `pnpm run test:e2e -- apps/api/test/product.e2e-spec.ts` (cần Docker). Khi đổi routes/DI/auth, kiểm cả trường hợp unauthenticated, unauthorized, invalid input và response projection liên quan; không chỉ happy path.
