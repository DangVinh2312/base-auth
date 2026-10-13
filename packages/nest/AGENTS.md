# @base-authorization/nest

Adapter NestJS: decorators, guard, route manifest, request context, readiness, boot coordinator. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của package.

## Ranh giới

- Phụ thuộc core ports qua DI; không import `typeorm`/`pg` (ESLint chặn) và không import entity hay module của `apps/api`.
- Không export raw connection, credential hay đường bypass authorization cho handler.
- Bật `emitDecoratorMetadata`; DI giữa package dựa vào metadata thật từ `tsc`. Đừng chuyển sang transform không phát metadata.

## Hiện trạng

- `src/readiness.ts`: `ReadinessGate`, mặc định chưa ready → `/health/ready` 503.
- `src/bootstrap-coordinator.ts`: `BootstrapModule`/`BootstrapCoordinator` chạy manifest sync qua `ManifestSyncPort` (token `MANIFEST_SYNC` không export ra module ngoài) trong `onApplicationBootstrap`, trước `listen()`; tenant lỗi giữ not ready. Chưa ghép vào `apps/api`.
- `src/product-authorization.ts`: `ProductAuthorizationModule.register({ declarations, requestAuth })` cài global guard và kiểm kê HTTP controller routes khi bootstrap. Mỗi handler (kể cả kế thừa) cần đúng một `@ProductPublic()`, `@ProductAuthenticated()` hoặc `@ProductAuthorize(resource, action)`; thiếu/mơ hồ hoặc permission chưa khai báo làm boot throw trước `listen()`.
- `ProductRequestAuth.authenticate(request)` chỉ kiểm session sớm. `ProductAuthorize` không thay gateway enforcement: service dữ liệu bắt buộc kiểm lại session/authority và cùng AST trong transaction giữ application fence. Guard không giữ transaction qua response.
- Chỉ hỗ trợ HTTP Nest controller routes; không dùng raw adapter/router/middleware để phục vụ nghiệp vụ. Context khác HTTP bị guard deny. Legacy `BootstrapModule` không tự được chuyển sang product module.

## Quy tắc khi sửa

- Route thiếu hoặc mơ hồ metadata phải làm boot/CI fail, không mặc định Public.
- Tenant, principal và roles lấy từ session/authority đã kiểm chứng, không từ header/body/param chưa kiểm chứng.
- Foreign, absent và not-visible record trả cùng status/body.
- Readiness chỉ chuyển ready sau khi boot sync xong; sync lỗi giữ not-ready, không fallback allow.

## Test

- `packages/nest/test/*.spec.ts` (unit, `@nestjs/core` là devDependency để tạo application context) và `test/workspace.smoke-spec.ts` (boot app thật). E2E (`apps/api/test/*.e2e-spec.ts`) thêm ở Task 9–11.
