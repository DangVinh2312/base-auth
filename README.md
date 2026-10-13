# Base Authorization — single product

NestJS + TypeORM + PostgreSQL, Node24 và pnpm12.3.4. API mới dùng một database, local password/OIDC và opaque sessions; authorization dùng chung policy/boundary/grant/deny AST. Không có tenant giả hoặc Root bypass.

Xem [kiến trúc đích](docs/authz-single-product-architecture.md), [reuse map](docs/single-product-reuse-map.md), [trạng thái/bằng chứng](docs/superpowers/plans/2026-10-13-single-product-transition.md), [quyết định runtime](docs/decisions/0008-single-product-runtime-transition.md) và [vận hành local](docs/single-product-operations.md).

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

- `packages/core`: pure types, keys, AST, validation, shared planner/evaluator; runtime mới dùng `planUser/evaluateUser`.
- `packages/typeorm-postgres`: `product-*` là runtime mới; migrations lịch sử không sửa. Public imports qua package index.
- `packages/nest`: route inventory/decorators/guard; authorization thực vẫn recheck ở service/gateway trong fence.
- `apps/api`: composition/config/OpenAPI và resource fixture nhỏ.
- `tools/product.ts`: provision/migrate/sync/enroll/bootstrap offline.

API tenant cũ và `db:*:legacy` chỉ giữ cho đối chiếu/mapping lịch sử. Không chạy chúng lên product database. Chuyển dữ liệu tenant thật cần mapping, backup và access review riêng; migration hiện tại chủ động từ chối thiếu mapping. Chưa commit/push/deploy; thư mục workspace hiện chưa có `.git`.
