# HTTP authorization enforcement

Đọc root và `apps/api/AGENTS.md`. `product-authorization.module.ts` giữ decorators, route inventory và global guard; không DB driver/entity, không raw credential hoặc authorization bypass cho handler.

- Bật metadata decorator thật qua app `tsconfig`; kiểm bằng output `tsc`, không transform bỏ metadata.
- Mọi HTTP handler kể cả inherited cần đúng một classification public/authenticated/authorize; thiếu, mơ hồ hoặc permission chưa khai báo phải làm boot fail trước runtime bootstrap/listen.
- Guard chỉ kiểm session sớm; service/gateway phải kiểm lại session, authority và predicate trong fenced transaction. Không giữ transaction qua response hoặc lấy role/principal từ payload.
- Transport khác HTTP bị deny; không thêm middleware/router để vượt inventory. Không lưu request context trong singleton mutable field; resource có lifecycle cleanup.
- Readiness ở `health/services/readiness.service.ts`, mặc định đóng và chỉ mở sau privilege/sync/domain checks.

Tests: `test/enforcement/product-authorization.spec.ts`, `test/workspace.smoke-spec.ts`, `apps/api/test/structure.spec.ts`, `apps/api/test/product.e2e-spec.ts`.
