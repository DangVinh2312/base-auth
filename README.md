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

## Quy ước tên file

File source dùng `<tên>.<vai-trò>.ts` để thấy trách nhiệm ngay trong cây thư mục: `product-authority.service.ts` điều phối phân quyền, `http-security.helper.ts` chứa hàm tiện ích, `authority-store.repository.ts` truy cập dữ liệu. Gateway, compiler, codec, migration và các vai trò khác cũng có hậu tố tương ứng, như `product-data.gateway.ts`, `product-sql.compiler.ts`, `dayjs-timestamp.codec.ts`, `012-iam-root.migration.ts`.

Tên module dùng số ít: `document/`, `document.module.ts`, `DocumentModule`. Trong một module/package, từ hai file cùng vai trò trở lên được gom vào folder số nhiều như `services/`, `helpers/`, `repositories/`, `controllers/`, `codecs/`; file vẫn giữ hậu tố (`services/product-authority.service.ts`). Một file thì đặt trực tiếp trong module; giữ các nhóm đã có sẵn.

Giữ tên entrypoint `index.ts`, `main.ts`, `composition.ts`, `operations.ts`, `legacy.ts`, CLI và fixtures lịch sử. Quy chuẩn đầy đủ ở `AGENTS.md`; cấu trúc code không đổi HTTP routes, public package API hay định danh migration trong database.

## Format code

Prettier dùng cấu hình chung tại `.prettierrc.json`: thụt lề 2 spaces, nháy đơn, dấu chấm phẩy, trailing comma, độ rộng mục tiêu 100 cột và xuống dòng LF. ESLint tại `eslint.format.config.js` thêm dòng trống sau nhóm import, giữa các khai báo export (kể cả const/interface/type/class) và giữa các function, arrow function, class/object method và chữ ký method trong interface/type. Comment và decorator của class/method được giữ cùng khai báo. Chạy từ thư mục root:

```sh
# Format các file TypeScript/JavaScript, gồm cả tests và tools.
pnpm run format:code
# Chỉ kiểm tra, không sửa file.
pnpm run format:code:check
# Format một file cụ thể.
pnpm exec eslint --config eslint.format.config.js --fix apps/api/src/auth/controllers/auth.controller.ts
pnpm exec prettier --write apps/api/src/auth/controllers/auth.controller.ts
```

Bước ESLint chỉ chạy rule cách dòng, không cần build hoặc typecheck; `lint` cũng kiểm tra rule này. ESLint bỏ qua `node_modules`, `dist`, coverage và thư mục công cụ tạm được khai báo trong config. Bước Prettier bỏ qua file theo `.gitignore` và `.prettierignore`. `pnpm run format` / `pnpm run format:check` vẫn áp dụng cho toàn bộ file được Prettier hỗ trợ, gồm cả tài liệu và cấu hình; CI dùng `format:check`.

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
- `apps/api`: tách theo capability (`config`, `infrastructure`, `auth`, `document`, `administration`, `health`, `authorization`, `openapi`; `legacy` không wire); composition/config/OpenAPI và resource fixture nhỏ. Bootstrap order, legacy và phần chưa triển khai ở [operations §7](docs/single-product-operations.md).
- `tools/product.ts`: provision/migrate/sync/enroll/invite/bootstrap/reissue-root/revoke-root offline.

API tenant cũ và `db:*:legacy` chỉ giữ cho đối chiếu/mapping lịch sử. Không chạy chúng lên product database. Chuyển dữ liệu tenant thật cần mapping, backup và access review riêng; migration hiện tại chủ động từ chối thiếu mapping. Chưa push/deploy.
