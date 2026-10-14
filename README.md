# Base Authorization — single product

NestJS + TypeORM + PostgreSQL, Node24 và pnpm12.3.4. API mới dùng một database, local password/OIDC và opaque sessions; authorization dùng chung policy/boundary/grant/deny AST. Không có tenant giả hoặc Root bypass.

Quyết định adapter/API/audit: [ADR 0009](docs/decisions/0009-value-adapters-api-structure-and-audit-semantics.md); kế hoạch giai đoạn A: [foundation hardening](docs/superpowers/plans/2026-10-14-foundation-hardening-and-adapters.md) (phase B T8–T10 chưa thực hiện). Xem [kiến trúc đích](docs/authz-single-product-architecture.md), [reuse map](docs/single-product-reuse-map.md), [trạng thái/bằng chứng](docs/superpowers/plans/2026-10-13-single-product-transition.md), [quyết định runtime](docs/decisions/0008-single-product-runtime-transition.md) và [vận hành local](docs/single-product-operations.md).

## Local

```sh
pnpm install --frozen-lockfile
# Chuẩn bị .env.ops và .env.api theo runbook; dùng credentials local riêng.
docker compose --env-file .env.ops up -d postgres
pnpm run db:provision
pnpm run db:migrate
pnpm run manifest:sync
pnpm run start:dev
```

API không chạy DDL khi boot. Privilege/capability/manifest lỗi khiến startup thất bại trước business listener. `/health/ready` chỉ200 sau sync; `/openapi.json` mô tả DTO/examples/status, `/health/metrics` chỉ chứa labels hữu hạn. Recovery delivery chưa cấu hình trả503. Không public signup, UI, file/export/job hay generic administration endpoints.

## Kiểm chứng

```sh
pnpm run format:check
pnpm run lint
pnpm run typecheck
pnpm run build
pnpm run test:unit
pnpm run test:integration
pnpm run test:e2e
```

Integration/E2E dùng PostgreSQL18.4 disposable qua Docker và IdP fixture có chữ ký thật. Tests nhận path filter sau `--`. GitHub workflow được cập nhật nhưng chưa thực chạy từ đây; local pass không là CI pass. Số đo fixture nhỏ ở [load results](docs/single-product-load-results.md) không là SLA production.

## Layout và compatibility

- `packages/core`: pure types, keys, AST, validation, shared planner/evaluator; `createAuthorizationCore({ values })` trả instance (`core.planUser/evaluateUser`, ...) nhận codecs qua `ValueCodecs`; không có default engine toàn cục.
- `packages/value-adapters`: codec thuần (Day.js strict UTC timestamp bảo toàn microsecond, int64/decimal/uuid/string/boolean). Composition root chọn adapter; hướng dẫn thay adapter ở [reuse map](docs/single-product-reuse-map.md).
- `packages/typeorm-postgres`: `product-*` là runtime mới; migrations lịch sử không sửa. Public imports qua entrypoint: `.` (errors/types an toàn), `./composition` (constructors, cho `apps/api/src/infrastructure` và CLI), `./operations` (provision/migrate/bootstrap offline, chỉ CLI), `./legacy` (tenant lịch sử). Ranh giới developer enforced bằng ESLint và `test/package-boundaries.spec.ts`, không phải process isolation.
- `packages/nest`: route inventory/decorators/guard; authorization thực vẫn recheck ở service/gateway trong fence.
- `apps/api`: tách theo capability (`config`, `infrastructure`, `auth`, `documents`, `administration`, `health`, `authorization`, `openapi`; `legacy` không wire); composition/config/OpenAPI và resource fixture nhỏ. Bootstrap order, legacy và phần chưa triển khai ở [operations §7](docs/single-product-operations.md).
- `tools/product.ts`: provision/migrate/sync/enroll/invite/bootstrap/reissue-root/revoke-root offline.

API tenant cũ và `db:*:legacy` chỉ giữ cho đối chiếu/mapping lịch sử. Không chạy chúng lên product database. Chuyển dữ liệu tenant thật cần mapping, backup và access review riêng; migration hiện tại chủ động từ chối thiếu mapping. Chưa push/deploy.
