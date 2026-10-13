# ADR 0001 — Runtime, module format và cô lập tenant cho M1

Ngày: 2026-10-13. Trạng thái: chấp nhận cho M1 (Task 1–3). Ma trận quyền và credential được mở rộng ở ADR 0004 (Task 7–8); bảng dưới là trạng thái M1.

## Bối cảnh

Kế hoạch yêu cầu khóa exact versions sau compatibility test, chốt module format/decorator metadata bằng build + boot thật, và triển khai database-per-tenant với credential riêng theo `docs/authz-architecture.md` mục 5.2 và 6. Các versions dưới đây được tra bằng `pnpm view` ngày 2026-10-13 và kiểm chứng bằng install với `strictPeerDependencies`, build, boot và test hiện có.

## Quyết định

### Runtime và tooling

| Thành phần      | Version                                                     | Lý do                                                                                                                                                                                                      |
| --------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node            | 24 (`.nvmrc`, engines `>=24.15 <25`), kiểm tra trên 24.20.0 | LTS; type stripping chạy trực tiếp test/tools `.ts`                                                                                                                                                        |
| pnpm            | 12.3.4                                                      | Có sẵn trong `packageManager`                                                                                                                                                                              |
| NestJS          | 12.1.2 (`common`, `core`, `platform-express`)               | Dòng stable mới nhất. 12.1.3 phát hành < 1 ngày nên bị chính sách `minimumReleaseAge` mặc định của pnpm chặn; không thêm exclusion để lách                                                                 |
| TypeScript      | 6.0.3                                                       | TypeScript 7.0.2 đã có nhưng `typescript-eslint@8.71.x` chỉ hỗ trợ `<6.1.0`; không hạ baseline khác                                                                                                        |
| TypeORM / pg    | 1.1.2 / 8.23.1                                              | Stable mới nhất; peer `pg ^8.5.1`                                                                                                                                                                          |
| PostgreSQL      | image `postgres:18.4`                                       | Patch PG 18 mới nhất có trên Docker Hub; dùng chung cho Compose và Testcontainers                                                                                                                          |
| ESLint          | 10.12.0, `@eslint/js` 10.0.1, `typescript-eslint` 8.71.1    | Typed linting; 8.71.2 cũng bị chặn bởi release-age policy                                                                                                                                                  |
| Test runner     | `node:test` + `node:assert` (built-in)                      | Nest 12 là ESM-only; Jest ESM còn experimental, Vitest transform (esbuild/oxc) không phát decorator metadata giống `tsc`. Test chạy trên output `tsc` nên metadata giống production; không thêm dependency |
| DB test         | `testcontainers` / `@testcontainers/postgresql` 12.2.0      | PostgreSQL thật, container disposable, credentials sinh ngẫu nhiên                                                                                                                                         |
| Build scripts   | `cpu-features`, `protobufjs`, `ssh2`: tắt (`allowBuilds`)   | Đến từ Testcontainers; `ssh2` có fallback JS, `protobufjs` chỉ kiểm tra version                                                                                                                            |
| Supertest, Ajv… | chưa thêm                                                   | Chưa có test/route dùng; task sở hữu sẽ thêm                                                                                                                                                               |

Lưu ý vận hành: một lần `pnpm add -Dw typeorm` tăng dần tạo lockfile thiếu snapshot peer `pg` cho root; tạo lại lockfile bằng `pnpm clean --lockfile` + `pnpm install` cho kết quả đúng. Không sửa tay lockfile.

### Module format và decorator metadata

- Toàn workspace là ESM: `"type": "module"`, `module`/`moduleResolution: nodenext`, `verbatimModuleSyntax` trong `tsconfig.base.json`.
- `experimentalDecorators` + `emitDecoratorMetadata` chỉ bật ở `packages/nest`, `packages/typeorm-postgres`, `apps/api`. `packages/core` không decorator và `types: []`.
- Bằng chứng: `test/workspace.smoke-spec.ts` boot `apps/api/dist/main.js` thật; `HealthController` nhận `ReadinessGate` từ `@base-authorization/nest` qua `design:paramtypes`. Thiếu metadata thì Nest không resolve được dependency và test fail.
- Test/tools viết bằng TypeScript chỉ dùng cú pháp xóa được (`erasableSyntaxOnly`), chạy bằng Node type stripping và import package đã build qua `exports` → `dist`.

### Tên package

`@base-authorization/{core,nest,typeorm-postgres,api}`, tất cả `"private": true`. Đây là tên workspace nội bộ, **không** phải quyết định namespace/versioning/publish (kế hoạch mục 7.6 vẫn mở).

### Cô lập tenant trên PostgreSQL

- Database-per-tenant: `authz_t_<uuid không gạch>`; login roles `<db>_data` và `<db>_authority`, tên suy ra từ tenant UUID chuẩn (lowercase), không nhận từ input khác.
- Roles: `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`; provisioner kiểm lại thuộc tính sau mỗi lần tạo/sửa và dừng nếu bị nâng quyền. Password gửi lên server dưới dạng SCRAM-SHA-256 verifier tính tại client, plaintext không vào câu SQL/log.
- `REVOKE ALL ON DATABASE ... FROM PUBLIC` cho tenant DB và identity DB; `REVOKE ALL ON SCHEMA public FROM PUBLIC`; chỉ roles của tenant có `CONNECT` và `USAGE` schema.
- Ma trận quyền bảng (code: `tenantPrivileges` trong `tenant-provisioner.ts`, áp lại sau mỗi `db:migrate`; bảng chưa phân loại làm provisioning/migrate thất bại):

| Bảng                                                                                                         | data                   | authority                      |
| ------------------------------------------------------------------------------------------------------------ | ---------------------- | ------------------------------ |
| `tenant_anchor`                                                                                              | SELECT                 | SELECT                         |
| `authz_fence`                                                                                                | SELECT                 | SELECT, UPDATE(revision)       |
| `membership`                                                                                                 | SELECT                 | SELECT, INSERT, UPDATE         |
| `resource_type`, `permission_policy`, `permission_catalog`, `scope_template`, `resource_relation_definition` | SELECT                 | SELECT                         |
| `role_definition`, `member_role`, `policy_rule`, `record_exception`, `relation_edge`, `identity_relation`    | SELECT                 | SELECT, INSERT, UPDATE, DELETE |
| `object_ref`                                                                                                 | SELECT, INSERT, DELETE | SELECT                         |
| `audit_outbox`                                                                                               | INSERT                 | INSERT                         |

- Catalog code-owned chỉ migration principal ghi được ở M1. Admin provisioning (CREATEDB, CREATEROLE, không superuser — đã test) đồng thời là migration principal và owner các object tenant.
- `ck_single_tenant` của spec được ánh xạ thành unique index một hàng `uq_tenant_anchor_single` + anchor chỉ provisioner ghi (runtime roles không có INSERT/UPDATE/DELETE). Migration vì vậy dùng chung cho mọi tenant.
- Provisioning nhiều bước, mỗi bước idempotent; trạng thái resume suy từ catalog (`pg_roles`, `pg_database`, migrations, anchor, fence). Dòng `tenant_directory` (route = tên DB, UTF-8) ghi cuối cùng: tenant chưa routable cho tới khi mọi bước trước xong. Không giả vờ atomic.
- `TenantDataSourceRegistry`: key `(tenant, purpose, credentialVersion)`, single-flight, refcount, idle eviction chỉ khi refcount 0, budget connection cứng (LRU idle bị evict trước, hết chỗ → `TenantUnavailableError`), kiểm `tenant_anchor` sau khi kết nối để chặn directory tampering/secret nhầm. Budget local đề xuất: data 5 + authority 2 cho 2 tenant active = 14; identity pool 5 và boot sync pool 2 thuộc composition ở task sau.

## Hệ quả, giới hạn đã biết

- `pg_database`/`pg_roles` là catalog toàn cluster: login role của tenant A vẫn thấy tên DB/role của tenant khác (chứa tenant UUID). Không đọc được dữ liệu, nhưng lộ danh sách tenant trong cùng cluster.
- Role tenant vẫn `CONNECT` được DB `postgres`/template mặc định nếu cluster operator chưa revoke; provisioner không sửa DB dùng chung của cluster.
- ~~`SELECT ... FOR SHARE` cần quyền UPDATE~~ — đã giải quyết ở ADR 0004 bằng hàm SECURITY DEFINER; data role không còn quyền nào trên `authz_fence`.
- Chưa có identity runtime role, audit forwarder role, credential boot sync; chưa đặt `CONNECTION LIMIT` theo role; chưa bật RLS.
- Health routes chưa có Swagger examples (Swagger được thêm khi có API contract đầu tiên).

## Cần chủ dự án xác nhận trước M2

1. ~~Credential cho boot sync~~ — chủ dự án chốt: role sync riêng theo tenant (ADR 0004).
2. Có chấp nhận lộ danh sách tenant qua catalog cluster, hay cần cluster riêng/khác cho tenant nhạy cảm?
3. ~~Cơ chế shared fence~~ — chốt SECURITY DEFINER (ADR 0004).
4. Secret source production cho tenant passwords và cách xoay vòng (`credentialVersion`).
