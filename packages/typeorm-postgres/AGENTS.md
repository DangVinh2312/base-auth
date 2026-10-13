# @base-authorization/typeorm-postgres

Adapter PostgreSQL/TypeORM: schema, migrations, tenant provisioning, connection registry, SQL compiler, data gateway, authority store. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của package.

## Ranh giới

- Phụ thuộc `@base-authorization/core` qua `workspace:*` và public exports; không import NestJS hay code của `apps/api`.
- Không export DataSource/QueryRunner/credential thô cho handler. Lease và `manager` chỉ dành cho adapter.
- Entities không được dùng để sinh schema: `synchronize: false`, migrations viết tay.

## Runtime một sản phẩm

- `product-database.ts`, `migrations/product/`: schema một DB, real credentials data/identity/authority/sync/migration/bootstrap, protected rows/marker và narrow SECURITY DEFINER functions. Chưa mapping legacy data thì migrate từ chối, không đoán/gộp.
- `product-transaction.ts`: fixed-purpose pools, singleton fence, READ COMMITTED, facts statements sau lock, timeout/retry/metrics hữu hạn. Pool capability không có thì fail closed, không fallback login.
- `product-sql.ts`, `product-gateway.ts`, `product-authority.ts`: user plan, cùng policy/boundary/grant/deny predicate, projection, native keys và write action registration. API chỉ nhận service operations, không raw manager.
- `product-manifest.ts`: immutable release, exact system grants, protected-state drift gate, persistent bootstrap. Boot không tạo user/assignment; runtime seed không takeover.
- `product-identity.ts`, `product-oidc.ts`: hash/exchange ngoài fence, recheck versions/session/authority trong fence; không email link hoặc secret log.
- New tables/rights thay đổi phải cập nhật credential matrix, migration/privilege tests và ADR0008. Product source không import Nest hoặc app domain.

Các file/bảng tenant bên dưới là compatibility/historical, không wire vào API mới. Boundary đã có trong cả legacy và user path; không báo thiếu theo prose cũ.

## Bản đồ file

| File / thư mục                   | Trách nhiệm                                                                                           |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `data-source-options.ts`         | Options identity/tenant DataSource (`synchronize: false`)                                             |
| `migrations.ts`, `migrations/*/` | `runMigrations`; `identity/` và `tenant/` đánh số tăng dần                                            |
| `entities/*.entity.ts`           | Mapping đọc; phải khớp cột đã migrate (có test kiểm)                                                  |
| `tenant-provisioner.ts`          | Tạo DB/role theo tenant, ma trận quyền `tenantPrivileges`, resume idempotent                          |
| `datasource-registry.ts`         | `TenantDataSourceRegistry`: single-flight, refcount, eviction, budget, anchor                         |
| `authority-store.ts`             | Đọc authority facts từ tenant DB                                                                      |
| `sql-compiler.ts`                | `BindingRegistry`, `compilePlan`/`compileNamed` → SQL có bind parameter                               |
| `data-gateway.ts`                | `DataGateway`: list/detail/count cùng predicate, projection allowlist                                 |
| `tenant-transaction.ts`          | `TenantTransactionRunner` (fence, timeout, retry 40P01/40001/55P03), `PostgresAuthority.withSnapshot` |
| `obligations.ts`                 | `fulfillObligations` trong transaction trước khi trả payload                                          |
| `manifest-reconciler.ts`         | `prepareRelease` + `ManifestReconciler.reconcile` (sequence/hash, không downgrade, seeds)             |

Mọi truy cập authority/data đi qua `withSnapshot`/`TenantTransactionRunner`: fence là statement đầu, facts đọc ở statement sau, cùng transaction. Mode `read/write` (data role, shared fence qua hàm `authz_acquire_shared_fence`), `admin` (authority, `FOR UPDATE` + revision), `sync` (sync role). Permission boundary được load cùng authority trong fence; giữ cùng semantics ở product path.

## Quy tắc khi sửa

- **Migrations:** không sửa migration đã áp dụng; thêm forward migration số kế tiếp. Backfill phải kiểm dữ liệu và raise khi không chắc chắn. Test chạy lần hai là no-op và nâng cấp từ dữ liệu tồn tại.
- **Bảng mới:** phải được phân loại trong ma trận quyền của provisioner cho cả data/authority/sync (bảng chưa phân loại làm migrate fail) và ghi vào ADR 0001/0004.
- **Fence:** data role không có quyền trực tiếp trên `authz_fence`; chỉ EXECUTE hàm fence. Writer facts bảo mật dùng mode `admin`/`sync`. Không nâng shared → exclusive.
- **SQL:** giá trị luôn là bind (`$n` raw, tên duy nhất cho QueryBuilder). Identifier chỉ từ binding đã đăng ký. Không thay chuỗi SQL bằng regex, không cast cột PK sang text.
- **Thời gian:** hiệu lực cạnh/exception/plan so bằng `statement_timestamp()` của DB.
- **Collation:** so thứ tự chuỗi dùng `COLLATE "C"` để khớp core.
- **Transaction:** chỉ dùng `manager` của transaction được truyền vào; không global repository, không network I/O trong transaction.
- **Tên DB/role:** suy ra từ tenant UUID canonical, không từ input khác.

## Test

- Ở root `test/`: `schema`, `tenant-isolation`, `compiler`, `gateway`, `collation`, `revocation`, `obligations`, `manifest-sync` (`*.integration-spec.ts`), `datasource-registry.spec.ts`; helper `test/setup-postgres.ts`, fixtures `test/fixtures/resources.ts`.
- Integration chạy PostgreSQL 18.4 thật qua Testcontainers (cần Docker): `pnpm run test:integration -- test/<file>`.
- Test quyền phải chạy bằng credential data/authority của tenant, không bằng admin.

Quyết định chi tiết: `docs/decisions/0001-runtime-and-isolation.md`, `0002-core-plan-and-sql-compiler.md`, `0004-fence-and-manifest-sync.md`.
