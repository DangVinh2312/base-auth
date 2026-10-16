# @base-authorization/typeorm-postgres

Adapter PostgreSQL/TypeORM một sản phẩm: schema, migrations, fixed-purpose pools, SQL compiler, data gateway, authority store. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của package.

## Ranh giới

- Phụ thuộc `@base-authorization/core` qua `workspace:*` và public exports; không import NestJS, code của `apps/api` hay `value-adapters`. Nhận `AuthorizationCore` làm argument (`prepareProductRelease(source, core)`, binding registry, reconciler `options.core`, `ProductAuthorization`, root offline commands); release/declarations của core khác bị từ chối.
- Không export DataSource/QueryRunner/credential thô cho handler. Lease và `manager` chỉ dành cho adapter.
- Public entrypoints (`package.json#exports`, mỗi `src/<name>.ts` chỉ re-export, không logic). Đây là ranh giới cho developer, không phải process isolation; `test/package-boundaries.spec.ts` chốt danh sách export, ESLint chặn handler import entrypoint đặc quyền.

| Entrypoint      | Nội dung                                                                                                                           | Ai được import                                        |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `.`             | Error classes, helper thuần (`canonicalLoginEmail`, `rateLimitClient`), type contracts (service types chỉ `export type`)           | Mọi nơi, kể cả handler                                |
| `./composition` | Constructors/low-level: `ProductTransactionRunner`, services, registries, gateway, `productObligations`, `verifyProductPrivileges` | `apps/api/src/infrastructure`, `tools/`, test adapter |
| `./operations`  | Offline: provision/migrate/data source options, root bootstrap/revoke/reissue, `appendProductAudit`                                | `tools/`, test offline                                |

Thêm export mới: chọn entrypoint theo bảng và cập nhật literal trong `test/package-boundaries.spec.ts`; không thêm raw runner/pool/audit writer vào root.

- Entities không được dùng để sinh schema: `synchronize: false`, migrations viết tay.

## Runtime một sản phẩm

- `helpers/product-database.helper.ts`, `migrations/product/`: schema một DB, real credentials data/identity/authority/sync/migration/bootstrap, protected rows/marker và narrow SECURITY DEFINER functions. Chưa mapping legacy data thì migrate từ chối, không đoán/gộp.
- `runners/product-transaction.runner.ts`: fixed-purpose pools, singleton fence, READ COMMITTED, facts statements sau lock, timeout/retry/metrics hữu hạn. Pool capability không có thì fail closed, không fallback login.
- `compilers/product-sql.compiler.ts`, `gateways/product-data.gateway.ts`, `services/product-authority.service.ts`: user plan, cùng policy/boundary/grant/deny predicate, projection, native keys và write action registration; nhánh Root duy nhất trong `access` (`kind` từ `resolve_session`, fresh-auth SQL `PRODUCT_FRESH_AUTH_SQL`, audit Root trực tiếp). API chỉ nhận service operations, không raw manager.
- `services/product-manifest.service.ts`: release product v2 (role `{ key, label }`, tiền tố `system.` dự trữ, không system grants), genesis khi sequence 0 + catalog rỗng, drift gate qua `helpers/protected-state.helper.ts`, bootstrap `iam → root` (khóa target trước), revoke = suspend. Boot không tạo user/assignment; runtime seed không takeover.
- Migration `012` (ADR 0012): `app_user.kind`, `iam_account`, năm guard Root SECURITY DEFINER owner `product_session_owner` (probe kiểm VOLATILE, thân hàm, trigger, ACL owner và định nghĩa/security_invoker của view chính xác); `down` không đảo ngược.
- `services/product-identity.service.ts`, `services/product-oidc.service.ts`: hash/exchange ngoài fence, recheck versions/session/authority trong fence; không email link hoặc secret log. Limiter lấy advisory key qua `run(…, { serialize })` trước fence (ADR0010); purge session hết hạn là lệnh offline theo batch.
- New tables/rights thay đổi phải cập nhật credential matrix, migration/privilege tests và quyết định thiết kế liên quan (nền hiện tại ADR 0008; thay quyết định đã chấp nhận thì thêm ADR superseding). Product source không import Nest hoặc app domain.

ADR 0013 bỏ implementation và entrypoint tenant. Product giữ nguyên chain migration 001–012; không thêm tenant giả hoặc compatibility flag.

## Bản đồ file

| File / thư mục                                              | Trách nhiệm                                                           |
| ----------------------------------------------------------- | --------------------------------------------------------------------- |
| `postgres-connection.types.ts`                              | Connection contract, chỉ export type ở root                           |
| `helpers/product-database.helper.ts`, `migrations/product/` | Provisioning, options `synchronize: false` và migration chain 001–012 |
| `helpers/transaction-errors.helper.ts`                      | Transaction errors và runtime capability không phụ thuộc runner       |
| `helpers/release-content.helper.ts`                         | Release contracts, validation và canonical hash; không role rank      |
| `compilers/product-sql.compiler.ts`                         | `ProductBindingRegistry(core, …)`, plan → SQL có bind parameter       |
| `gateways/product-data.gateway.ts`                          | List/detail/count cùng predicate, projection allowlist                |
| `runners/product-transaction.runner.ts`                     | Fixed-purpose pools, fence, timeout, retry 40P01/40001/55P03          |
| `helpers/product-obligations.helper.ts`                     | Obligations trong transaction trước khi trả payload                   |
| `services/product-authority.service.ts`                     | Authority snapshot, recheck và authorized operations                  |
| `services/product-manifest.service.ts`                      | `prepareProductRelease` + reconcile (sequence/hash, không downgrade)  |

Mọi truy cập authority/data đi qua `ProductAuthorization`/`ProductTransactionRunner`: lấy fence trước khi đọc facts, các facts đọc ở statement sau trong cùng transaction. Mode `read/write` dùng data role và shared fence; `admin` dùng authority role và exclusive fence; `sync` dùng sync role. Identity/revoke/bootstrap có purpose riêng. Permission boundary được load cùng authority trong fence.

## Quy tắc khi sửa

- **Migrations:** không sửa migration đã áp dụng; thêm forward migration số kế tiếp. Backfill phải kiểm dữ liệu và raise khi không chắc chắn. Test chạy lần hai là no-op và nâng cấp từ dữ liệu tồn tại.
- **Bảng mới:** phân loại trong ma trận quyền theo từng purpose, cập nhật privilege tests và tài liệu thiết kế tương ứng. Product theo ADR 0007/0008/0012/0013.
- **Fence:** data role không có quyền trực tiếp trên `authz_fence`; chỉ EXECUTE hàm fence. Writer facts bảo mật dùng mode `admin`/`sync`. Không nâng shared → exclusive.
- **SQL:** giá trị luôn là bind (`$n` raw, tên duy nhất cho QueryBuilder). Identifier chỉ từ binding đã đăng ký. Không thay chuỗi SQL bằng regex, không cast cột PK sang text.
- **Thời gian:** hiệu lực cạnh/exception/plan so bằng `statement_timestamp()` của DB.
- **Collation:** so thứ tự chuỗi dùng `COLLATE "C"` để khớp core.
- **Transaction:** chỉ dùng `manager` của transaction được truyền vào; không global repository, không network I/O trong transaction.
- **Tên DB/role:** dùng fixed-purpose configuration đã validate.
- **Security facts:** load/recheck sau khi có fence; mutation phải cùng transaction với affected-set validation, revision và audit bắt buộc. Generic data write không được sửa authority tables/security columns.
- **Privilege/drift:** thay bảng/function/trigger/role phải cập nhật startup probe và negative tests bằng credential thật. Kiểm owner/ACL, SECURITY DEFINER với search_path an toàn, schema CREATE/TEMP và enabled mode của mọi protection trigger liên quan; không hardcode tổng số trigger để thay kiểm đúng từng bảo vệ.
- **Query cost:** loader chỉ lấy facts/cột cần thiết, có giới hạn và thứ tự ổn định khi pagination. Đo N+1/full-catalog reads/lock wait trước tối ưu; không cache authority qua request khi chưa có protocol invalidation đã kiểm chứng.
- **Scalar parity:** parameter type, collation và timestamp precision phải khớp codec/core; không sửa semantics bằng cast cột để query chạy được. Clock adapter của app không thay `statement_timestamp()` trong quyết định hiệu lực quyền.
- **Audit/delivery:** ghi event theo contract trong transaction; gửi ra network sau commit qua cơ chế delivery phù hợp yêu cầu durability. Không giữ fence khi gọi sink, không báo delivered khi chỉ enqueue/start promise. `services/product-outbox.service.ts` (ADR0011): claim lease + `SKIP LOCKED`, send ngoài transaction, ack theo `lease_token`, retry/park hữu hạn, login `outbox` chỉ SELECT outbox + UPDATE cột delivery. Câu lệnh `UPDATE … RETURNING` bọc trong `WITH … SELECT` (TypeORM trả `[rows, count]` cho UPDATE trần).

## Test

- Ở root `test/`: product SQL/identity unit tests và product database/authorization/fence/manifest/Root integration tests; helper `test/setup-postgres.ts`, fixtures `test/fixtures/resources.ts`.
- Integration chạy PostgreSQL 18.4 thật qua Testcontainers (cần Docker): `pnpm run test:integration -- test/<file>`.
- Test quyền phải chạy bằng đúng credential/purpose đang kiểm; admin chỉ chuẩn bị fixture, không thực thi thao tác cần chứng minh bị giới hạn.
- Race/revoke tests dùng synchronization xác định thứ tự transaction, không chỉ sleep rồi đoán. Kiểm cả rollback, timeout/retry có giới hạn và mutation bị credential sai từ chối.

Quyết định chi tiết: ADR 0007–0008 (product), 0010–0011 (limiter/outbox), 0012 (IAM/Root), 0013 (bỏ legacy, giữ packages) trong `docs/decisions/`.
