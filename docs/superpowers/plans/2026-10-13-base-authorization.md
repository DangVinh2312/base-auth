# Base Authorization — Implementation Plan

> Cập nhật implementation 2026-10-13: runtime API mới theo [kế hoạch chuyển đổi](2026-10-13-single-product-transition.md) và ADR0008. Các trạng thái/spike tenant hoặc “chưa triển khai” trong bản thiết kế gốc bên dưới là lịch sử, không chứng nhận hay phủ nhận trạng thái runtime mới. Xem ledger chuyển đổi để biết bằng chứng và gates còn lại.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Có thể chuyển sang superpowers:subagent-driven-development khi người dùng chọn cách thực thi đó. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xây dựng dự án NestJS + TypeORM + PostgreSQL chạy được, cung cấp xác thực và lõi RBAC/ReBAC/ABAC/permission policy dùng lại được, kèm ứng dụng mẫu và bộ test chứng nhận tích hợp.

**Architecture:** Modular monolith, một API deployable, ba package tái sử dụng: pure core, Nest adapter và TypeORM/PostgreSQL adapter. Identity/control plane có DB riêng; tenant database và credential riêng theo thiết kế hiện tại. Permission, policy và relation manifests đồng bộ khi boot qua transaction có version; dữ liệu nghiệp vụ không bị reset.

**Tech Stack:** Node.js 24 LTS, NestJS, TypeScript, TypeORM, PostgreSQL 18, pnpm workspaces, OpenAPI, Docker Compose, OIDC; test runner tương thích scaffold Nest, Supertest, Testcontainers và fast-check. Version chính xác của framework/tooling được khóa sau compatibility test ở Task 1, không dùng tag `latest` trong CI/deploy.

**Spec:** [authz-architecture.md](../../authz-architecture.md). Kế hoạch ngày 2026-10-13, áp dụng tại `/Users/vinhdq2312/Documents/personal/base-authorization`. Hiện dự án có tài liệu và cấu hình nền pnpm/formatter/CI, chưa có source ứng dụng hoặc deployment; kết quả spike lịch sử không được coi là test pass của dự án mới.

## Global Constraints

- Dùng pnpm 12.3.4 theo `packageManager`, một `pnpm-lock.yaml`, workspace `apps/*` và `packages/*`; dependencies nội bộ dùng `workspace:*`. Đọc `AGENTS.md` trước mỗi task.

- Lõi không import NestJS, TypeORM, PostgreSQL driver hoặc tên domain.
- Tenant là ranh giới cứng; single-tenant vẫn đi qua cùng context và kiểm tra membership.
- `Allow = HardBoundary AND PolicyRequirements AND RequiredScope AND EffectiveBoundary AND (Role/Identity/RecordAllow) AND NOT AnyDeny`; thiếu cấu hình/facts thì fail closed.
- Cùng AST cho list/detail/count/export/write; không lọc quyền sau pagination.
- Permission policy luôn có key/version, áp dụng cả record exception; mỗi permission có binding tường minh, không fallback baseline ngầm.
- ReBAC dùng path hữu hạn tối đa 8 bước; không kế thừa tenant, không graph recursion tùy ý.
- Native integer key không đi qua JS number; canonical key tối đa 256 byte. Tiền/decimal so sánh chính xác, không float.
- Tất cả writer thay đổi facts phân quyền tuân thủ tenant fence và tăng revision; SQL raw chỉ qua binding/template đăng ký.
- Không positive authorization cache ở bản đầu; quyền tenant đã revoke không được dùng cho authorization bắt đầu sau revoke commit. Không hứa thu hồi byte đã gửi hoặc atomic global logout xuyên nhiều DB.
- `synchronize: false` ở mọi môi trường. Schema migrations tách khỏi permission/policy/relation boot sync.
- Không hardcode secret; không lấy code nghiệp vụ từ repo khác. Local fixtures chỉ dùng dữ liệu giả.
- Không gọi network trong transaction authority; timeout tham chiếu 2 giây, retry toàn transaction tối đa 2 lần cho lỗi được phân loại, idempotency cho side effect.
- Không viết production code trong lượt lập kế hoạch này. Các lệnh bên dưới là tiêu chí thực thi tương lai, chưa được chạy.

## Review Focus

1. Pool tenant bị evict trong lúc còn transaction: không hủy connection đang dùng, không tái sử dụng credential nhầm — Task 3.
2. Manifest không đổi nhưng code-owned tuple bị mất do cascade: phát hiện drift và không ready, không âm thầm coi checksum là đủ — Task 8.
3. Policy `pending` dùng cho approve bị áp vào trạng thái `approved` sau ghi: authorize pre-state, validate post-transition riêng — Task 10.
4. Hai scope riêng đều hợp lệ nhưng kết hợp mở rộng quyền tự cấp/peer qua role hoặc relation: kiểm tra affected set dưới khóa — Task 11.
5. OIDC identity cùng email nhưng khác issuer/subject, hoặc cookie/session bị replay: không tự link account và không bỏ CSRF — Task 9.

## 1. Phạm vi phát hành và stack đề xuất

Đây là **starter backend + thư viện tích hợp**, chưa phải một dịch vụ authorization tập trung phục vụ mọi ứng dụng từ xa. Quyết định này giữ authorization và domain write trong cùng transaction tenant; chuyển PDP ra network sau này cần một thiết kế consistency khác. Business code được coi là code đã review; nếu cần cô lập plugin/code độc hại thì phải tách data gateway thành process riêng trước khi chạy code đó.

| Thành phần              | Đề xuất                                                                                 | Lý do / thời điểm                                                                                                        |
| ----------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Runtime                 | Node 24 LTS; Nest stable và packages cùng dòng tương thích                              | Tài liệu Nest hiện mô tả v12; khóa exact versions sau boot/build/TypeORM/test smoke, không suy mọi plugin đã tương thích |
| ORM/DB                  | TypeORM + `pg`, PostgreSQL 18                                                           | Stack người dùng chọn; dùng migrations, FK ghép, locking reads và transaction manager cụ thể                             |
| Workspace               | pnpm workspaces + TypeScript project references                                         | Đủ cho 3 packages và 1 app; chưa cần Nx/Turborepo                                                                        |
| HTTP                    | REST, adapter HTTP mặc định scaffold Nest                                               | Không thêm Fastify/GraphQL chỉ để có thêm lựa chọn                                                                       |
| Validation              | DTO validation tương thích Nest; JSON Schema validator cho manifest/template parameters | Runtime request validation và policy validation có trust boundary khác nhau; JSON Schema dùng Ajv strict mode            |
| Authn                   | OIDC Authorization Code + PKCE; opaque application session                              | Không tự xây password/MFA/recovery; role vẫn đọc từ authority                                                            |
| IdP local               | Keycloak trong Compose, chỉ realm/test users giả                                        | Có login/MFA/account lifecycle để test thật; production IdP giữ là quyết định mở                                         |
| API contract            | `@nestjs/swagger`, examples/status đầy đủ                                               | Frontend hoặc hệ thống khác tích hợp được qua OpenAPI                                                                    |
| Test                    | Unit + Supertest + Testcontainers PostgreSQL + fast-check                               | Lock, FK, JSONB, isolation và SQL null phải kiểm tra bằng PostgreSQL thật                                                |
| Logs/health             | Structured JSON logs, request ID, redaction; health/readiness                           | Cần cho audit và vận hành; dùng khả năng framework trước, tránh hai logger song song                                     |
| Local/runtime packaging | Dockerfile nhiều stage + Compose                                                        | Dựng API, PostgreSQL, IdP và fixtures theo tài liệu từ môi trường sạch                                                   |
| CI                      | GitHub Actions nếu repo đặt trên GitHub; scripts độc lập CI vendor                      | Build, test, migrations, manifest và security checks là gate                                                             |
| Audit                   | PostgreSQL transactional outbox + sink adapter                                          | Không cần Kafka; local sink kiểm thử, production sink riêng trước rollout nhạy cảm                                       |

Nguồn kỹ thuật đã đối chiếu: [Nest migration guide](https://docs.nestjs.com/migration-guide), [Nest database integration](https://docs.nestjs.com/techniques/database), [TypeORM transaction repositories](https://typeorm.io/docs/working-with-entity-manager/custom-repository/), [Node release schedule](https://nodejs.org/en/about/previous-releases), [PostgreSQL support policy](https://www.postgresql.org/support/versioning/), [Testcontainers PostgreSQL](https://node.testcontainers.org/modules/postgresql/), [Keycloak local Docker setup](https://www.keycloak.org/getting-started/getting-started-docker). Patch versions và peer dependencies phải kiểm tra lại tại Task 1; link tài liệu không thay compatibility test.

### Các thành phần chưa cần thêm ngay

- Redis: chỉ thêm khi đo được nhu cầu cache/rate-limit phân tán; không là authority và không phục vụ stale allow.
- BullMQ: chỉ thêm khi có job dài cần retry/scheduling. Audit outbox nhỏ có thể được drain bằng CLI/worker cùng codebase, không cần queue service mới.
- OpenFGA/OPA/Cedar: không đưa vào bản đầu cùng một engine tự xây. ReBAC hữu hạn đã nằm trong AST; chọn engine khác là ADR thay thế, không chồng thêm tầng cấp quyền.
- PgBouncer: cân nhắc sau khi đo connection budget và thử transaction pooling; không triển khai để che pool registry chưa có giới hạn.
- Kubernetes, Kafka, Elasticsearch, object storage, admin UI: không thuộc bản đầu. Search/file endpoints chưa có adapter được kiểm chứng thì không công bố tính năng tương ứng.
- OpenTelemetry collector: nên thêm khi chạy staging/nhiều service; bản đầu phải có structured metrics/logs đủ đo authority latency, denied/error và fence wait.

## 2. Các mốc bàn giao

| Mốc                                      | Tasks | Đầu ra nghiệm thu                                                                                             |
| ---------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------- |
| M1 — nền tảng và cô lập                  | 1–3   | Fresh clone build được; PostgreSQL migrations + tenant provisioning; credential A không đọc DB B              |
| M2 — engine dùng lại                     | 4–8   | RBAC/ReBAC/policy/exception chạy cùng AST; TypeORM enforcement, revoke fence và boot sync đúng                |
| M3 — backend có thể dùng                 | 9–11  | Login/session, HTTP enforcement, demo D1 và administration API; chặn T1/T3/T5–T10 trong các ingress có hỗ trợ |
| M4 — tái sử dụng và production candidate | 12–14 | Fixtures D2/D3 không sửa core; conformance, package example, docs/runbooks, benchmark và CI                   |

Ước lượng ban đầu: **8–12 tuần với 2 backend engineer có kinh nghiệm**, cộng reviewer bảo mật/QA theo mốc; đây là dự toán, không cam kết lịch. M1 khoảng 1–2 tuần, M2 3–4 tuần, M3 2–3 tuần, M4 2–3 tuần; có phần review/docs chồng lấp. Một người làm tuần tự có thể cần 12–18 tuần. Sau M1/M2 phải ước lượng lại dựa trên actual effort và contention/consistency findings.

Task 1–11 tạo bản alpha dùng nội bộ, không quảng cáo đã đáp ứng mọi kênh file/search/job. T4 không bị bỏ: API không có các kênh chưa hỗ trợ, còn audit worker/job envelope và cache namespace contract được test ở Task 12/13. Khi mở thêm kênh, adapter phải đạt shared conformance trước khi bật route.

## 3. Cấu trúc file và chiều phụ thuộc

```text
base-authorization/
  AGENTS.md, package.json, pnpm-lock.yaml, pnpm-workspace.yaml
  tsconfig.base.json, tsconfig.json, tsconfig.build.json
  compose.yaml, Dockerfile, .env.example, .gitignore, README.md
  packages/
    core/src/
      types.ts, key-codec.ts, expression.ts, declarations.ts
      policy-validator.ts, planner.ts, evaluator.ts, administration.ts
      index.ts
    nest/src/
      authorization.module.ts, decorators.ts, route-manifest.ts
      authorization.guard.ts, context.factory.ts, authorization.filter.ts
      bootstrap-coordinator.ts, index.ts
    typeorm-postgres/src/
      datasource-registry.ts, tenant-provisioner.ts
      authority-store.ts, tenant-transaction.ts, sql-compiler.ts
      data-gateway.ts, manifest-reconciler.ts, relation-commands.ts
      entities/*.entity.ts, migrations/identity/*.ts, migrations/tenant/*.ts
      index.ts
  apps/api/src/
    main.ts, app.module.ts, config.ts, health.controller.ts
    authentication/{authentication.module,oidc-client,session.service,authentication.controller}.ts
    administration/{administration.module,administration.controller,administration.service}.ts
    review/{review.module,review.declarations,review.binding,review.controller,review.service}.ts
    audit/{audit-outbox.service,audit-sink}.ts
  apps/api/test/{authentication,authorization,administration,review}.e2e-spec.ts
  test/{setup-postgres,fixtures,conformance,performance}/
  test/domains/{review,crm,clinic}/
  tools/{provision,migrate,manifest,audit-drain}.ts
  infra/keycloak/realm.example.json
  .github/workflows/ci.yml
  docs/{authz-architecture,getting-started,integration-guide,operations,security-contract}.md
  docs/decisions/0001-runtime-and-isolation.md
```

Các `{a,b}.ts` trong tree là các file riêng, không phải một file tên có dấu ngoặc. Root `test/fixtures` chứa fixture helper do task sử dụng sở hữu; không tạo generic test framework ngoài nhu cầu.

`core` không có dependency framework; `nest` và `typeorm-postgres` phụ thuộc `core`; API ghép hai adapter. Adapter Nest nhận storage port qua DI, không import entity của D1. Các package có `package.json`, `tsconfig.json` và explicit `index.ts`; dependency nêu trong manifest, không import file private bằng relative path xuyên package. D1 nằm trong app; D2/D3 là integration fixtures trước khi cần sản phẩm domain riêng.

## 4. Hợp đồng kỹ thuật xuyên task

Các kiểu dưới đây được định nghĩa tại `packages/core/src/types.ts`, declaration DTO tại `declarations.ts`. Bám các interface trong spec; không tạo tên khác cho cùng một nghĩa giữa tasks.

| Interface                                                                            | Producer  | Consumer / trách nhiệm                                                                                       |
| ------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------ |
| `validate(declarations: SystemDeclarations): ValidationResult`                       | Task 4/5  | Boot/CI từ chối invalid AST/resource/action/policy/relation                                                  |
| `plan(input: TrustedInput, snapshot: AuthoritySnapshot): Decision`                   | Task 4/5  | Gateway/guard; tạo predicate + obligations, không query DB                                                   |
| `evaluate(plan: AuthorizedPlan, facts: CompleteFacts): Decision`                     | Task 4    | Differential tests, record check; không thay SQL enforcement                                                 |
| `authorizeAdministration(command: AdminCommand, facts: AdminFacts): Decision`        | Task 11   | Authority commands; affected set đầy đủ, fail closed                                                         |
| `withSnapshot<T>(principal, tenant, mode, run): Promise<T>`                          | Task 7    | Tham số theo `AuthorityPort` trong spec; giữ `TenantTransaction` và revision                                 |
| `compile(plan: AuthorizedPlan, tx: TenantTransaction): BoundPredicate`               | Task 6    | TypeORM query, binding parameter/alias; không nhận raw input SQL                                             |
| `list/detail/mutate(...)`                                                            | Task 6/10 | Chữ ký theo `StorageBinding` của spec; chính gateway resolve active permission policy                        |
| `reconcile(tenant: TenantId, release: VerifiedReleaseManifest): Promise<SyncResult>` | Task 8    | `SyncResult = {changed:boolean; revision:string; manifestHash:string}`; deploy CLI/boot chung implementation |
| `verify(credential: IncomingCredential): Promise<VerifiedPrincipal>`                 | Task 9    | Session/authentication port, không tin role tenant trong request                                             |

`TenantTransaction` bao bọc đúng `QueryRunner.manager`; lifecycle và credential không lộ ra handler. Không gọi global repository trong transaction. Typed IDs giữ canonical bytes/string, SQL binds có đúng PG type. TypeORM metadata cần có smoke test build/runtime thật; test transform không được làm decorator metadata khác production.

Plan là lời hứa về implementation tương lai. Chi tiết deadline/cancellation, TypeORM PostgreSQL semantics, authn và full DDL phải được chứng minh lại; không copy spike Python thành code production.

## 5. Tasks triển khai

Mỗi task thực hiện test → kiểm tra test fail đúng nguyên nhân → implementation nhỏ nhất → test pass → review diff/commit. Không commit test đang fail. Chỉ tạo git repository và commits khi bắt đầu execution; lượt lập kế hoạch chưa thực hiện điều đó.

### Task 1: Workspace chạy được và kiểm chứng stack

Cấu hình nền pnpm, AGENTS.md, TypeScript base, formatter và CI formatting đã được tạo. Kế thừa chúng; task này vẫn chưa hoàn thành vì chưa scaffold/build/test NestJS và TypeORM.

**Files:** Kế thừa root AGENTS/package/pnpm workspace/lock/tsconfig.base đã có; bổ sung root build tsconfig, `packages/*/package.json`, `packages/*/tsconfig.json`, các `src/index.ts`, `apps/api/package.json`, `apps/api/src/{main,app.module,config,health.controller}.ts`, `test/workspace.smoke-spec.ts`, `.env.example`, `.gitignore`, `README.md`, `docs/decisions/0001-runtime-and-isolation.md`.

**Interfaces:** Produces scripts `build`, `lint`, `typecheck`, `test:unit`, `test:integration`, `test:e2e`, `test:conformance`, `test:performance`, `db:provision`, `db:migrate`, `manifest:check`, `manifest:sync`, `start:dev`. Test scripts accept a file/path filter after `--`.

- [x] Viết smoke test boot API, `/health/live` 200; config thiếu DB/issuer cần thiết khiến boot fail; import core không load Nest/TypeORM. Readiness mặc định chưa ready cho đến khi authority được tích hợp.
- [x] Chạy `pnpm run test:unit -- test/workspace.smoke-spec.ts`; xác nhận fail vì scaffold/interface chưa có, không phải Docker/network.
- [x] Scaffold bằng local CLI pinned, không cài global. Chọn exact peer-compatible Nest/TypeORM/TypeScript/test versions; xác minh module format và decorator metadata bằng app compile chạy thật. Ghi quyết định Node24/Nest version/TS version trong ADR; không tự hạ baseline nếu compatibility chưa đạt.
- [x] Chạy `pnpm run build`, `pnpm run typecheck`, `pnpm run lint`, smoke test; expected exit 0. Đảm bảo root gitignore không loại bỏ `docs/` hoặc lockfile.
- [ ] Review và commit `chore: scaffold authorization workspace`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 2: PostgreSQL schema và migrations đầy đủ

**Files:** `packages/typeorm-postgres/src/entities/*.entity.ts`, `migrations/identity/001-initial.ts`, `migrations/tenant/001-initial.ts`, `tools/migrate.ts`, `compose.yaml`, `test/setup-postgres.ts`, `test/schema.integration-spec.ts`.

**Interfaces:** Produces identity/tenant DataSource options `synchronize:false`; migrations chạy độc lập AppModule. Schema theo spec gồm permission policy, typed relations và release sequence mới nhất.

- [x] Viết `migrations_apply_on_empty_database`, `cross_tenant_fk_rejected`, `permission_without_policy_rejected`, `relation_type_mismatch_rejected`, `expired_interval_rejected`, `duplicate_seed_owner_key_rejected`.
- [x] Chạy `pnpm run test:integration -- test/schema.integration-spec.ts` trên PostgreSQL 18 Testcontainer; phải fail khi thiếu schema.
- [x] Chuyển DDL MySQL trong spec sang PG thật: UUID, bytea có length checks, timestamptz, JSONB, native boolean, explicit indexes cho FK. Tạo đủ 20 bảng hiện được liệt kê trong spec; kiểm đếm lại nếu đặc tả thay đổi, không bỏ bảng mới. Dùng native entity mapping và migration handwritten cho constraints không thể hiện chính xác qua decorator.
- [x] Chạy migration hai lần (lần hai no-op), tests và down/up chỉ trên DB disposable; kiểm tra retained data khi forward migration. Schema permission/role code-owned được ghi bằng credential provisioning/sync, không cấp cho data handler.
- [ ] Review SQL và commit `feat: add postgres authority schema`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 3: Tenant provisioning và giới hạn connection pool

**Files:** `datasource-registry.ts`, `tenant-provisioner.ts`, `tools/provision.ts`, `test/tenant-isolation.integration-spec.ts`, `test/datasource-registry.spec.ts`.

**Interfaces:** `TenantDataSourceRegistry.acquire(tenant: TenantId, purpose: 'data' | 'authority'): Promise<TenantConnectionLease>`; lease có `release():Promise<void>` và private DataSource dành cho adapter. `TenantProvisioner.provision(input: ProvisionTenantInput):Promise<TenantId>`; provisioner không có HTTP route công khai. Purpose do gateway/command adapter chọn, không nhận từ client.

- [x] Test hai tenant A/B và identity DB: credential A không CONNECT/read B hoặc identity; query A thiếu tenant WHERE vẫn không thấy B; routing dùng input chưa kiểm chứng bị từ chối.
- [x] Test pool single-flight cho 20 acquire đồng thời, release reference count, idle eviction không đóng active transaction, capacity full trả unavailable có kiểm soát.
- [x] Provision DB/user bằng admin credential riêng, REVOKE CONNECT FROM PUBLIC, không SUPERUSER/BYPASSRLS/CREATEROLE; tenant anchor cố định. Tách tenant data credential (domain DML + authority read) với authority command credential (policy mutation qua invariant checks). Registry key chứa tenant + purpose + credential version. Giới hạn local: 2 active tenants × (data pool 5 + authority pool 2) + identity pool 5 = 19 runtime connections; boot sync pool tối đa 2, reserve phần còn lại trong budget 25/app. Production budget tính theo số replica và mọi pool; không cung cấp authority credential cho handler nghiệp vụ.
- [x] Run `pnpm run test:integration -- test/tenant-isolation.integration-spec.ts` và `pnpm run test:unit -- test/datasource-registry.spec.ts`; expected pass. Provisioning nhiều bước CREATE DATABASE/ROLE có trạng thái resume, không giả vờ atomic transaction bao trọn CREATE DATABASE.
- [ ] Review privilege matrix và commit `feat: isolate tenant connections`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 4: Pure core, typed keys và deny precedence

**Files:** `packages/core/src/{types,key-codec,expression,declarations,planner,evaluator}.ts`, `packages/core/test/{decision,key-codec}.spec.ts`.

**Interfaces:** Produces `validate`, `plan`, `evaluate` theo mục 4. `Decision.allow` cho list là plan có predicate, không là allow mọi row.

- [x] Table-test tenant mismatch, inactive membership, empty grant, role/personal deny, record allow ngoài grant scope, record deny thắng; integer `9007199254740993`, integer/string `42`, UUID, string Unicode/quote.
- [x] Chạy `pnpm run test:unit -- packages/core/test`; xác nhận đúng các assertions fail trước implementation.
- [x] Implement algebra thuần, immutable inputs, typed comparisons; null grant không khớp, unknown fact/operator/config fail closed. Rules giới hạn size/depth theo manifest; vượt giới hạn không truncate deny.
- [x] Chạy unit suite; property test thêm deny không làm tăng tập allow, đổi tenant không allow. Core package dependency graph không có framework/driver/domain.
- [ ] Review và commit `feat: implement pure authorization decisions`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 5: Permission policy và ReBAC có kiểu

**Files:** `packages/core/src/policy-validator.ts`, bổ sung `expression.ts`, `planner.ts`, `evaluator.ts`, `packages/core/test/{permission-policy,relations}.spec.ts`.

**Interfaces:** Consumes AST/core Task 4; produces `PermissionPolicy`, `PolicyRef`, `RelationDeclaration` và exact validation theo spec; context requirements trả boolean/unknown tường minh, handler registry ở adapter.

- [x] Test policy requiredScope/MFA không bị record allow vượt; policy true mà không grant vẫn deny; absent/retired policy và missing obligation handler fail readiness/runtime.
- [x] Test `submission.site → site.manager`, sai type/hướng/tenant ở bước giữa, expired relation, path 8 bước hợp lệ/9 bước reject, policy reference cycle reject (AST không có node tham chiếu nên cycle không biểu diễn được; test chỉ kiểm node không hỗ trợ bị từ chối, không phải phát hiện cycle). No arbitrary JS/string SQL.
- [x] Implement type-checking/lowering ReBAC thành `exists`, mandatory scope outside allow OR, obligations hợp nhất. Define validator/handler contracts không có network I/O trong transaction; record-dependent checks bắt buộc là query AST.
- [x] Run `pnpm run test:unit -- packages/core/test/permission-policy.spec.ts` và `pnpm run test:unit -- packages/core/test/relations.spec.ts`; expected pass, hash deterministic khi thay thứ tự khai báo không đổi nghĩa.
- [ ] Review và commit `feat: add permission policies and typed relations`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Bổ sung sau Task 5: Permission boundary tổng quát (chưa triển khai)

Đọc [hợp đồng boundary](../../permission-boundaries.md). Đây là delta cho cả engine và adapter, không chỉ tính năng assignRole của Task 11; các checkbox hoàn thành trước đó không bao gồm delta này.

**Files:** bổ sung declarations/types/planner/evaluator và public exports của core; `packages/core/test/permission-boundary.spec.ts`; authority-store/compiler/gateway và fixtures liên quan; forward tenant migration kế tiếp, không sửa migration đã áp dụng.

- [ ] Viết tests grant/deny/record exception với boundary, required/optional, missing facts/version/binding và ba fixture assign/approve/export theo hợp đồng.
- [ ] Thêm boundary declaration + một binding membership/permission; validate và lower vào cùng AST, không class/engine riêng cho từng domain.
- [ ] Thêm persistence/FKs, load boundary cùng authority snapshot; list/detail/count/export/mutation đều qua boundary. Test trên PostgreSQL thật và differential evaluator/compiler.
- [ ] Cập nhật manifest/Nest action metadata/CI để khai báo requirement tường minh; migration/backfill + compatibility readiness trước activation, không wildcard fallback.
- [ ] Chạy unit/integration suite liên quan, kiểm chứng mutation bỏ boundary khiến suite fail; báo đúng kết quả thực tế.

### Task 6: SQL compiler và TypeORM data gateway

**Files:** `packages/typeorm-postgres/src/{sql-compiler,data-gateway,authority-store}.ts`, `test/{compiler,gateway}.integration-spec.ts`, `test/fixtures/resources.ts`.

**Interfaces:** Consumes core plan; produces `BoundPredicate={sql:string; parameters:readonly unknown[]}` và StorageBinding read methods. QueryBuilder bridge tạo parameter name duy nhất; raw execution dùng driver positional binds, không thay chuỗi SQL bằng regex.

- [x] Differential-test evaluator với PG cho eq/lt/lte/null/EXISTS/NOT deny/exception, numeric exactness, UTF-8 equality và list/detail/count cùng snapshot.
- [x] Test user filter có OR không thoát predicate, query builder `.where()` không ghi đè quyền, joins/nested resources không lộ fields, relation nhiều-nhiều không nhân đôi list/count, pagination ổn định.
- [x] Implement resource binding registry/alias allowlist và predicate parameterization; select projection allowlist, bounded reads. Fixture có 3 native PK types; không cast indexed native PK column sang text.
- [x] Run `pnpm run test:integration -- test/compiler.integration-spec.ts` và `pnpm run test:integration -- test/gateway.integration-spec.ts`; SQL injection fixture được coi là value, zero cross-tenant results.
- [ ] Review EXPLAIN cho fixture indexes và commit `feat: enforce authorization in postgres queries`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 7: Transaction fence, revoke và audit obligation

**Files:** `tenant-transaction.ts`, bổ sung `authority-store.ts`, `apps/api/src/audit/{audit-outbox.service,audit-sink}.ts`, `test/{revocation,obligations}.integration-spec.ts`.

**Interfaces:** Produces `AuthorityPort.withSnapshot` và `TenantTransaction`; `AuditOutbox.append(tx,event):Promise<void>`. Clock/context chỉ từ adapter tin cậy.

- [x] Test hai connection: read/write giữ shared fence, revoke exclusive phải đợi; revoke commit trước thì request mới deny. Thêm deny row chưa tồn tại và xóa relation cũng phải theo fence; không chỉ test đổi role.
- [x] Test deadline 2 giây, lock/statement timeout, connection disconnect, retry tối đa 2 lần cho 40P01/40001/55P03, không lặp side effect; audit insert fail khiến rollback/không release payload.
- [x] Implement READ COMMITTED + QueryRunner.manager duy nhất, lock order trong spec, classify command trước khóa, không shared→exclusive upgrade. DB statement_timeout/lock_timeout kết hợp cancellation và abort transaction; app timer riêng không đủ ngăn query tiếp tục.
- [x] Run `pnpm run test:integration -- test/revocation.integration-spec.ts` và obligations suite. Khẳng định theo commit/admission, không ghi “revoke mọi request trong 0ms”; test pre-authenticated global logout được mô tả riêng Task 9.
- [ ] Review cleanup mọi error path và commit `feat: fence authorization changes and audit effects`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 8: Boot sync permission, policy, boundary, ReBAC

**Files:** `manifest-reconciler.ts`, `packages/nest/src/bootstrap-coordinator.ts`, `tools/{manifest,migrate}.ts`, `test/manifest-sync.integration-spec.ts`.

**Interfaces:** Produces `reconcile(tenant,release):Promise<SyncResult>`; consumes verified release + existing tenant fence, không tự chạy DDL.

- [ ] Sync boundary definitions và code-owned binding seeds theo hợp đồng; giữ runtime bindings, không tự nâng version, không retire definition còn được dùng; tăng revision/audit và chặn old binary thiếu capability. — chờ boundary delta (không thuộc lượt Task 7–8).
- [x] Test first sync, same hash no-op, same sequence khác hash reject, old binary không downgrade, new policy version switch, auto default grants, runtime edges không bị overwrite; missing resource/owner collision rollback.
- [x] Test hai boot instances publish một revision, crash trước/sau commit, missing code seed dù hash giống → readiness fail, mất validator/handler → fail. Remove seed chỉ khi explicit removal cùng owner.
- [x] Implement immutable manifest canonical hashing, release sequence/expected predecessor, sync policies trước permission bindings; audit + revision cùng transaction. Verified release được supply từ artifact deployment tin cậy; API tenant không upload manifest.
- [x] Run `pnpm run test:integration -- test/manifest-sync.integration-spec.ts`; boot hook không listen hoặc khởi động workers trước readiness. Bootstrap credential scope hạn chế và không inject vào controllers.
- [ ] Review và commit `feat: reconcile authorization manifests at boot`. — bỏ qua theo yêu cầu (không có git repository, không commit).

### Task 9: OIDC và application sessions

**Files:** `apps/api/src/authentication/*`, `infra/keycloak/realm.example.json`, `compose.yaml`, `apps/api/test/authentication.e2e-spec.ts`, `test/session-revocation.integration-spec.ts`.

**Interfaces:** `AuthenticationPort.verify` tạo `VerifiedPrincipal`; session lookup primary, không tenant roles trong session làm nguồn quyết định. OIDC library stable được pin, không tự implement JWT signature/code exchange.

- [ ] Test code+PKCE login, state/nonce/issuer/audience mismatch, token hết hạn, same email khác issuer/sub không auto-link, code replay, invalid session/disabled identity/logout.
- [ ] Test cookie Secure/HttpOnly/SameSite phù hợp deployment, CSRF cho mutation, token hash trong DB, logs không chứa token/authorization header. Local dev profile khác production rõ ràng và không bật ngoài local/test.
- [ ] Implement OIDC callback→opaque session, logout revoke local session; không hứa local logout đã kết thúc IdP SSO session. Membership administration không có password/reset/MFA/IdP-link quyền hạn. Test assurance mapping cho MFA từ issuer tin cậy, không từ header client.
- [ ] Run `pnpm run test:e2e -- apps/api/test/authentication.e2e-spec.ts` với Keycloak local/integration fixture; run session revocation test bắt đầu sau commit bị chặn. Request trước revoke giới hạn theo contract, không claim atomic xuyên DB.
- [ ] Review và commit `feat: add oidc login and revocable sessions`.

### Task 10: Nest enforcement và một luồng D1 hoàn chỉnh

**Files:** `packages/nest/src/{authorization.module,decorators,route-manifest,authorization.guard,context.factory,authorization.filter}.ts`, `apps/api/src/review/*`, `apps/api/test/{authorization,review}.e2e-spec.ts`.

**Interfaces:** Produces `@Authorize/@Authenticated/@Public`, global APP_GUARD, tenant context và API gọi StorageBinding; public module export không lộ raw repositories.

- [ ] Test route thiếu/ambiguous metadata fail build/boot, thiếu scope fail; user đổi id/tenant/header vẫn không thấy resource khác. Foreign/unknown/not-visible record cùng status/body, không lookup global trước.
- [ ] D1 fixtures A/B, reviewer/manager: list/detail/count/process theo assigned/managedSite; direct grant/deny và record exceptions cùng precedence. Test approve-like transition: required `pending` trên pre-state, hợp lệ chuyển `approved`, unauthorized post-field change rollback.
- [ ] Implement routes `GET /tenants/:tenantId/submissions`, `GET .../:id`, `POST .../:id/process`; mutation qua command + exclusive fence nếu đổi facts bảo mật. Projection/Swagger examples/status đầy đủ; error adapter tránh leak FK/unique/global identity existence.
- [ ] Run `pnpm run manifest:check` và `pnpm run test:e2e -- apps/api/test/authorization.e2e-spec.ts`, review E2E. HTTP method mới/raw router mount không có inventory phải fail CI.
- [ ] Review và commit `feat: integrate nest enforcement with review example`.

### Task 11: Administration API chống leo thang

**Files:** `packages/core/src/administration.ts`, `packages/typeorm-postgres/src/relation-commands.ts`, `apps/api/src/administration/*`, `apps/api/test/administration.e2e-spec.ts`, `packages/core/test/administration.spec.ts`.

**Interfaces:** Consumes generic boundary delta sau Task 5; `ApplicationRoleBoundary` chỉ là fixture ứng dụng. Produces `authorizeAdministration`; command service lấy affected principals/roles trước/sau trong exclusive fence. Delegation chỉ template/version cùng nhau hoặc subset proof đã đăng ký.

- [ ] Test assignRole có grant nhưng role ngoài boundary; boundary không grant; quản lý binding cần permission riêng; không gỡ/mở boundary của mình, bulk ngoài boundary rollback; role capabilities hiện tại vẫn phải nằm trong delegation envelope.
- [ ] Test self/peer/superior, edit role actor đang có, xóa deny mở quyền, union grants, role ảnh hưởng peer, team/care relation tự thêm mình, bulk/import cùng rule; immutable catalog/policy/seed/protection fields.
- [ ] Test two-admin race, state thay giữa preview/submit, `identity.reset/link/impersonate` không tồn tại trong membership admin capabilities, membership ở tenant khác không bị tác động.
- [ ] Implement endpoints tối thiểu: members, custom roles, role assignments, direct rules, record exceptions, relation commands, audit read có permission riêng. Dữ liệu global identity chỉ projection tối thiểu; không email enumeration. Không tạo UI quản trị ở task này.
- [ ] Run core administration tests và `pnpm run test:e2e -- apps/api/test/administration.e2e-spec.ts`; revoke/role change kiểm tra affected set hiện tại chứ không tin preview từ client.
- [ ] Review T5–T8 và commit `feat: add safe authorization administration`.

### Task 12: Chứng minh tái sử dụng D2/D3 và background boundary

**Files:** `test/domains/{crm,clinic}/*`, `test/conformance/domain-contract.spec.ts`, `tools/audit-drain.ts`, `test/job-envelope.integration-spec.ts`, `docs/integration-guide.md`.

**Interfaces:** D2/D3 chỉ cung cấp SystemDeclarations/StorageBinding; core API/logic không sửa theo tên domain. Audit sink port có idempotent event ID; tenant-safe job envelope có principal/action/references.

- [ ] CRM: owner/team scope, department+currency+threshold, đúng ngưỡng/null deny, personal deny thắng record grant. Clinic: treating relation, emergency invoke pre-granted + MFA + reason, TTL tối đa 900 giây, expiry/invoke revoke/explicit deny/cross-clinic deny.
- [ ] Test emergency audit cả activation và use; log reason projection hạn chế; không nhân tiện có update/export. Job execution reauthorize principal tại run time, không dùng grant serialize lúc enqueue; forged tenant/replayed event không trộn dữ liệu.
- [ ] Build reusable conformance runner nhận declaration/binding factory; audit drain bounded batches, idempotent sink, retry an toàn; không network trong authority transaction. Không cần BullMQ để test worker boundary.
- [ ] Run `pnpm run test:conformance -- test/conformance/domain-contract.spec.ts` trên cả 3 fixture systems, `pnpm run test:integration -- test/job-envelope.integration-spec.ts`; đổi core để nhận diện domain làm task thất bại về kiến trúc.
- [ ] Review và commit `test: certify reusable domain declarations`.

### Task 13: Fault injection, CI và capacity measurements

**Files:** `test/conformance/{threats,faults}.spec.ts`, `test/performance/authorization.ts`, `.github/workflows/ci.yml`, bổ sung `apps/api/src/health.controller.ts`, `docs/security-contract.md`.

**Interfaces:** `pnpm run test:conformance` là release gate; performance runner báo query count, p95/p99, fence wait, pool wait, throughput, config/dataset cụ thể.

- [ ] Test DB unavailable, stale revision, clock uncertainty, dangling binding, unknown AST, malicious filter/raw template, inactive membership; mọi failure không biến thành allow. Chứng minh mock auth không được bật bằng production env.
- [ ] Mutation-test ít nhất các biến thể: bỏ tenant predicate, bypass policy, đảo deny, skip fence, allow self/peer. Suite phải fail từng biến thể; PG privilege test phải dùng non-owner tenant role.
- [ ] Pipeline chạy install locked→lint/types/build→migrations fresh→unit→integration→E2E→manifest/conformance; dependency/secret scanning và published artifact excludes env/fixtures secrets. Chỉ mock network không liên quan, không SQLite thay lock tests.
- [ ] Benchmark dataset tham chiếu: 2 tenant, mỗi tenant 100.000 rows, 10 roles, 50 applicable rules, 10.000 relation edges, 1.000 exceptions; tải 1/10/50 concurrent request và revoke đang có traffic. Báo kết quả thực, chưa áp một SLO ms tự nghĩ. Connection budget và fence contention là gate cần quyết định trước production sizing.
- [ ] Review evidence matrix T1–T10, ghi rõ unsupported file/search adapters và commit `ci: gate authorization security and migrations`.

### Task 14: Đóng gói, tài liệu vận hành và staging handoff

**Files:** `Dockerfile`, `README.md`, `docs/{getting-started,integration-guide,operations,security-contract}.md`, package export maps, `test/package-consumer.smoke-spec.ts`.

**Interfaces:** Fresh checkout có quy trình local: install→Compose→provision→migrate→manifest sync/boot→login→demo. Library consumer import public packages qua tarball, không workspace source shortcuts.

- [ ] Test `pnpm pack` của 3 packages rồi boot một consumer fixture bên ngoài workspace; không thiếu type declarations/assets/migration exports hoặc kéo theo D1 entities.
- [ ] Viết runbook provisioning/suspend tenant, release sync/rollback forward version, revoke semantics, session/IdP recovery, audit delivery, backup/restore và connection budget. Bootstrap/recovery chỉ CLI/service identity riêng có audit, không HTTP superadmin bypass.
- [ ] Docker image non-root, graceful shutdown release query runners, secret từ environment/secret manager, network/TLS theo deployment; health/live khác readiness. Restore diễn tập bằng fixture và credentials mới trước staging launch.
- [ ] Chạy `pnpm install --frozen-lockfile`, `pnpm run build`, `pnpm run test:conformance`, consumer smoke từ môi trường sạch; xác nhận 3 domain fixtures đạt suite và tài liệu không nhận test chưa chạy là pass. Lập manifest artifact/checksum và release checklist.
- [ ] Review toàn branch; commit `docs: document integration and operations`. Chỉ deploy staging sau khi có môi trường/IdP/secret/tenant isolation decisions đã chốt; không tự publish npm hoặc deploy từ task lập kế hoạch.

## 6. Coverage và tiêu chí hoàn thành

| Yêu cầu spec                                      | Task phụ trách                                                                       |
| ------------------------------------------------- | ------------------------------------------------------------------------------------ |
| N1 tenant boundary + single tenant                | 2, 3, 6, 10, 13                                                                      |
| N2 identity đa tenant                             | 2, 9, 11                                                                             |
| N3 roles/direct allow/deny                        | 4, 11                                                                                |
| N4 scopes/list-detail consistent                  | 5, 6, 10, 12                                                                         |
| N5 record exceptions                              | 4, 6, 11, 12                                                                         |
| N6 endpoint declaration, auto sync/default grants | 8, 10, 13                                                                            |
| N7 core roles/permission immutable                | 2, 8, 11                                                                             |
| N8 revoke/cost/failure                            | 7, 9, 13                                                                             |
| N9 typed IDs + ORM/builder/raw SQL                | 4, 6                                                                                 |
| Permission policy                                 | 2, 5, 6, 8, 10, 11                                                                   |
| ReBAC resource graph + boot                       | 2, 5, 6, 8, 12                                                                       |
| T1–T3                                             | 2, 3, 6, 10, 13                                                                      |
| T4                                                | 3, 12, 13; file/search không có route đến khi adapter được chứng nhận                |
| T5–T8                                             | 9, 11, 12, 13                                                                        |
| T9–T10                                            | 3, 5, 7, 8, 10, 13                                                                   |
| D1–D3 tổng quát                                   | 10, 12                                                                               |
| Tích hợp hệ thống cũ                              | 14: shadow cùng snapshot, so sets/count/deny; canary old AND new; không OR/fail-open |

Release candidate cần: local setup tái lập được, migrations và conformance pass trên PostgreSQL thật, no production auth bypass, API docs đủ contract, non-owner credentials, default deny, missing metadata/policy làm fail readiness, protected admin operations được audit, package consumer dùng được, runbook restore/revoke đã diễn tập. Coverage % không thay bảng chứng cứ này.

MySQL và ORM thứ hai chưa là deliverable production của kế hoạch này vì stack triển khai đã chọn PostgreSQL/TypeORM. Core vẫn giữ adapter boundary; muốn quảng cáo MySQL adapter phải triển khai và chạy differential suite tương ứng trong một kế hoạch riêng. Không dùng kết quả spike cũ để tuyên bố adapter TypeScript mới portable đã được chứng minh.

## 7. Quyết định cần chốt trước production

1. **Isolation và quy mô:** tiếp tục database-per-tenant như spec; cần số tenant đồng thời/replica/connection budget trước sizing. Chuyển shared schema + RLS là ADR thay đổi kiến trúc, không tự làm vì PostgreSQL hỗ trợ RLS.
2. **IdP production:** Keycloak tự vận hành hay provider OIDC khác; ai chịu trách nhiệm backup/MFA/recovery? Keycloak local không mặc định trở thành lựa chọn production.
3. **Điểm triển khai:** VPS/container service/Kubernetes và secret manager nào. Không cần quyết định để chạy local, nhưng bắt buộc trước staging.
4. **Global revoke và durability:** admission-only hay drain mọi in-flight commit xuyên DB? Failover authority có thể mất commit đã ACK hay không? Không promote replica không đạt watermark rồi tiếp tục cấp quyền.
5. **Release authority/audit:** ai duyệt manifest mở quyền, ai giữ bootstrap credential, sink audit độc lập và thời gian lưu. Không để runtime tenant admin vừa sửa policy vừa xóa audit.
6. **Public API và publication:** starter nội bộ hay npm packages public/private; chọn namespace/versioning trước publish, không suy từ tên folder.

Các lựa chọn local/reversible nêu trong plan là đề xuất để execution không bị chặn bởi chi tiết nhỏ. Những quyết định ảnh hưởng dữ liệu/identity/operational trust ở trên vẫn cần chủ dự án xác nhận trước phần việc phụ thuộc.

## 8. Bắt đầu triển khai

Bắt đầu từ M1, review xong mới đi tới engine và authentication. Đề xuất thực thi trực tiếp tuần tự các tasks vì interface/storage/boot phụ thuộc chặt; mỗi mốc có review độc lập nếu người dùng chọn quy trình đó. Có thể dùng subagents khi được chọn, nhưng không cần chúng để hoàn thành việc lập kế hoạch.

Đã tạo cấu hình nền pnpm, AGENTS.md, formatter và CI formatting; đã cài dependency formatter và kiểm tra frozen lockfile/formatting. Chưa scaffold ứng dụng NestJS, cài runtime dependencies, tạo DB, chạy test nghiệp vụ/benchmark, commit hoặc deploy.
