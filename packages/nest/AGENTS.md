# @base-authorization/nest

Adapter NestJS: decorators, guard, route manifest, request context, readiness, boot coordinator. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của package.

## Ranh giới

- Phụ thuộc core ports qua DI; không import `typeorm`/`pg` (ESLint chặn) và không import entity hay module của `apps/api`.
- Không export raw connection, credential hay đường bypass authorization cho handler.
- Bật `emitDecoratorMetadata`; DI giữa package dựa vào metadata thật từ `tsc`. Đừng chuyển sang transform không phát metadata.

## Hiện trạng

- `src/readiness.ts`: `ReadinessGate`, mặc định chưa ready → `/health/ready` 503.
- `src/bootstrap-coordinator.ts`: `BootstrapModule`/`BootstrapCoordinator` chạy manifest sync qua `ManifestSyncPort` (token `MANIFEST_SYNC` không export ra module ngoài) trong `onApplicationBootstrap`, trước `listen()`; tenant lỗi giữ not ready. Chưa ghép vào `apps/api`.
- `src/product-authorization.ts`: `ProductAuthorizationModule.register({ declarations, requestAuth })` cài global guard và kiểm kê HTTP controller routes trong `onModuleInit` (xong trước mọi `onApplicationBootstrap`, kể cả hook của module sâu hơn như runtime sync/readiness). Mỗi handler (kể cả kế thừa) cần đúng một `@ProductPublic()`, `@ProductAuthenticated()` hoặc `@ProductAuthorize(resource, action)`; thiếu/mơ hồ hoặc permission chưa khai báo làm boot throw trước `listen()`.
- `ProductRequestAuth.authenticate(request)` chỉ kiểm session sớm. `ProductAuthorize` không thay gateway enforcement: service dữ liệu bắt buộc kiểm lại session/authority và cùng AST trong transaction giữ application fence. Guard không giữ transaction qua response.
- Chỉ hỗ trợ HTTP Nest controller routes; không dùng raw adapter/router/middleware để phục vụ nghiệp vụ. Context khác HTTP bị guard deny. Legacy `BootstrapModule` không tự được chuyển sang product module.

## Quy tắc khi sửa

- Route thiếu hoặc mơ hồ metadata phải làm boot/CI fail, không mặc định Public.
- Tenant, principal và roles lấy từ session/authority đã kiểm chứng, không từ header/body/param chưa kiểm chứng.
- Foreign, absent và not-visible record trả cùng status/body.
- Readiness chỉ chuyển ready sau khi boot sync xong; sync lỗi giữ not-ready, không fallback allow.
- Decorator/guard là kiểm tra entrypoint, không bằng chứng đủ cho object-level authorization. Mọi đường gọi service, kể cả gọi trực tiếp ngoài HTTP, vẫn cần enforcement ở gateway/command.
- DI token gắn với interface hẹp; chỉ export provider cần cho consumer. Không dùng global module hoặc service locator để đưa raw runtime/connection tới controller; TypeScript `Pick` không thay ranh giới provider thực tế.
- Đổi module/controller phải giữ kiểm kê routes kế thừa, thứ tự authenticate/authorize, metadata thật và startup failure. Không tự hỗ trợ transport mới bằng cách bỏ qua guard khi context không phải HTTP.
- Request context không lưu trong singleton mutable field; không để principal/session của request trước rò sang request sau. Listener/timer do adapter tạo phải có lifecycle cleanup.

## Test

- `packages/nest/test/*.spec.ts` (unit, `@nestjs/core` là devDependency để tạo application context), `test/workspace.smoke-spec.ts` (boot app thật) và `apps/api/test/product.e2e-spec.ts` (HTTP E2E).
- Thay DI/module exports/route metadata phải kiểm boot bằng output `tsc` thật, routes thiếu/mơ hồ bị từ chối và lỗi sync giữ not-ready; mock guard pass không đủ.
