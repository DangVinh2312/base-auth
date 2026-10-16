# ADR 0013 — Một NestJS app chia module chức năng

Ngày: 2026-10-16. Trạng thái: chấp nhận theo yêu cầu chuyển đổi tiếp nối phương án đã trao đổi. Kế hoạch và bằng chứng: [single app modules](../superpowers/plans/2026-10-16-single-app-modules.md).

Phần giữ tenant implementation bên dưới đã được thay thế bởi [ADR 0014](0014-remove-legacy-runtime.md); quyết định topology một app vẫn áp dụng.

## Quyết định

Gom bốn package private `core`, `value-adapters`, `nest`, `typeorm-postgres` vào `apps/api/src`. App vẫn là NestJS modular monolith; bỏ package manifests/exports, SDK entrypoints và TypeScript project references giữa các library. Module import tương đối trực tiếp tới implementation/type sở hữu, services dùng TypeORM khi cần. Không áp dụng interface/port cho mọi service/repository.

Giữ lõi phân quyền thuần, value codec contracts và capability facades cho HTTP handlers. Đổi ESLint/tests từ package boundaries sang module boundaries; Root bypass vẫn chỉ ở authority service. `database` giữ runner/migrations/probes, `auth/services` giữ identity/OIDC, `audit` giữ writer/delivery, `authorization` giữ core/enforcement/authority/manifest. Tenant implementation chuyển vào `legacy/`; shared transaction errors và release validation nằm ngoài legacy để runtime không nạp code tenant.

Supersede ADR 0009 chỉ ở topology package/entrypoints; không supersede normalization, provenance, audit hoặc capability semantics. ADR 0012 tiếp tục quyết định IAM/Root. Không thay SQL, schema, migration identifiers, manifests/hashes, routes, credential matrix, fences hoặc dữ liệu hiện có. CLI offline tiếp tục chạy riêng, API không nhận migration/bootstrap credentials.

## Hệ quả

Một build app, một nơi khai báo runtime dependencies, không cần SDK imports hoặc library project references. Mất cơ chế package exports chặn deep imports; thay bằng quy định nội bộ và ESLint negative tests. Cả hai đều là ranh giới developer, không phải process isolation.

Code legacy và behavioral/security tests được giữ; không triển khai tính năng mới hay xóa tenancy history. Không commit/push/deploy hoặc tự chạy migration trên database của người dùng.
