# Single-product reuse map

| Existing implementation            | Reused/adapted result                                                                                                                          | Evidence                                                                                     |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| core AST/validator/key codecs      | Same definitions/key precision/collation; user contracts added without fake tenant                                                             | Core user/algebra/codec/provenance regressions                                               |
| planner/evaluator                  | Shared algebra/traversal; `planUser/evaluateUser` omit tenant; `planUnrestricted` (Root, ADR 0012); tenant wrappers removed (ADR 0013)         | User boundary/policy/deny/Root/ReBAC tests; boundary and Root mutations caught               |
| generic boundary delta             | User/permission binding, exact version/lifecycle, outside all allows                                                                           | Product SQL/evaluator parity, boundary tightening/revoke                                     |
| compiler/gateway/filter/projection | Product SQL adapted from same repo implementation; native binds, source type/version, validity and revision checks                             | Product auth suite + type/validity regressions; compiler/collation suites use product schema |
| fenced runner/retry/obligations    | Application singleton, fresh session+facts under same transaction, bounded retries and metrics                                                 | Real shared/exclusive locks,55P03, write/read-action and audit tests                         |
| release validator/reconciler       | Existing validator/canonical preparation and sync operations reused; release v2 (role key+label), genesis + full materialized drift gate added | Late Root/old catalog, races, collision, omission drift, removal, persistent bootstrap       |
| Nest readiness/boot                | Same readiness instance; real AppModule privilege/sync before listener; route inventory/guard added                                            | Real Nest startup tests + HTTP E2E drift startup rejection                                   |
| API health/config/audit            | Health retained; product config/log sanitization, audit effects and minimal document/suspend routes                                            | Unit/smoke/HTTP E2E                                                                          |
| Existing test harness              | pnpm + tsc + node:test + Testcontainers kept, E2E suite added only with actual tests                                                           | Full suites run locally; CI remote unrun                                                     |
| Authentication                     | New Argon2id/openid-client where no implementation existed                                                                                     | Local reset/link races, real signed token/JWKS fixture, opaque sessions                      |

No source or business logic copied from another repository. `base-auth/docs/prompt.md` was read as the task brief only. Layout/packages and locked versions retained; only required auth libraries/direct runtime dependencies added. Tenant implementation/contracts/CLI and frozen release 1 fixtures removed before deployment (ADR 0013); package topology retained.

# Mở rộng và tái sử dụng sau giai đoạn A (2026-10-14)

Mục này mô tả cách ghép và mở rộng sau Foundation Hardening, API Structure & Pluggable Adapters (ADR 0009, giai đoạn A: T0–T7). Không là chứng nhận production-ready; bằng chứng chạy thực ở [verification](single-product-verification.md).

## Package dependency graph

```text
apps/api (composition root: infrastructure/, auth/, document/, administration/, health/, openapi/, authorization/)
tools/product.ts (CLI offline)
  ├── core: createAuthorizationCore + types/ports (ValueCodecs, ScalarCodec)
  ├── value-adapters: Day.js timestamp + int64/decimal/uuid/string/boolean codecs
  ├── typeorm-postgres: `.` (errors/types), ./composition, ./operations (chỉ CLI)
  └── nest: ProductAuthorize, route inventory, guard (không import thư viện giá trị)

value-adapters ──type imports──> core
core ──X──> Day.js / Moment / NestJS / TypeORM / pg / value-adapters
feature handlers (auth/document/administration/health/openapi) ──> chỉ facade token + Nest decorators
```

Core không có production dependency và không có default engine. Mã chọn adapter nằm ở một nơi: `createProductAuthorizationCore()` trong `apps/api/src/authorization/product.manifest.ts`; `infrastructure/product-runtime.service.ts` và `tools/product.ts` cùng gọi nó.

## Composition copy/paste (Day.js adapter)

```ts
import { createAuthorizationCore } from '@base-authorization/core';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';

const core = createAuthorizationCore({
  values: createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
});
// Truyền `core` tường minh: prepareProductRelease(source, core), new ProductBindingRegistry(core, declarations, bindings),
// new ProductManifestReconciler(runner, { core, ... }). Không có setDefaultAdapter().
```

Yêu cầu của package dùng đoạn trên: dependency trực tiếp `@base-authorization/core`, `@base-authorization/value-adapters` (`workspace:*`) và project reference trong `tsconfig`. Codec thiếu hoặc sai shape thì `createAuthorizationCore` throw trước khi mở pool, nên API không mở listener; codec đúng shape nhưng sai ngữ nghĩa chỉ bị chặn bởi conformance suite và test parity PostgreSQL, không bởi constructor. Release phải được prepare bằng đúng instance này: declarations/release/plan từ instance khác bị từ chối (`unvalidated_declarations`, `invalid_release`, `foreign_plan`).

## Viết adapter thay thế và chạy conformance

1. Implement `ScalarCodec<string>` (`packages/core/src/ports/value-codecs.port.ts`): `normalize(input: unknown): string | undefined` và `compare(left, right): -1 | 0 | 1`. Contract timestamp: chỉ UTC `YYYY-MM-DDTHH:mm:ss[.f{1..6}]Z`, năm `0001..9999`, output luôn sáu chữ số lẻ, giữ microsecond, từ chối ngày không tồn tại/giờ 24/giây 60/offset/thiếu Z/hơn 6 chữ số lẻ; không truncate/round, không `now()`, không clock hay timezone máy. Adapter chỉ đổi cách parse; nó không được tạo thêm kind hay SQL type.
2. Conformance hiện **chưa là export dùng lại**: các case nằm trong `packages/value-adapters/test/value-codecs.spec.ts` (`timestampCases`, `timestampConformance(label, make)`). Với adapter thứ hai phải copy hoặc promote các case đó (ví dụ sang file test-helper không phải spec) rồi gọi `timestampConformance('moment', createMomentTimestampCodec)`. Test hiện kèm negative control: codec `Date.parse` lỏng phải fail các case 30/2, giờ 24, offset, thiếu Z, 7 chữ số lẻ, microsecond và năm 0001.
3. Chạy: `pnpm run test:unit -- packages/value-adapters/test/value-codecs.spec.ts`, sau đó `pnpm run test:integration -- test/product-values.integration-spec.ts` (PostgreSQL thật: so SQL với `evaluateUser`, `.123456` không mất ba chữ số cuối, input sai bị từ chối trước SQL) và `pnpm run typecheck`.
4. Đổi composition root ở `createProductAuthorizationCore()`; không sửa planner/compiler. Manifest hash không đổi khi đổi adapter (adapter không vào canonical JSON); `test/system-release.spec.ts` ghim hash.
5. Chỉ Day.js được triển khai ở đợt này; không cài Moment để minh họa. Thêm adapter khi có consumer thật. Nếu hai adapter cùng tồn tại, mỗi instance của core vẫn độc lập.

## Walkthrough: thêm một resource

Ví dụ theo `document` (xem `apps/api/src/document/`). Thay `invoice` cho tên mới; không thêm field làm đổi authority (owner/team/rank/boundary/grant) vào writable field.

1. **Declaration fragment** `apps/api/src/<feature>/<resource>.declarations.ts`: `resources` (key, `keyKind`, `fields`, `actions` mỗi action có `policy` + `boundary`), `policies` (có `contextRequirements`, `requiredScope`, `obligations` như `audit@1`), `templates`, default grants (`ProductReleaseSource['defaultGrants']`) và `ProductStorageBindings['resources'][number]` (binding bên dưới). Chỉ dữ liệu; không tự prepare release.
2. **Migration/privileges**: class migration trong `apps/api/src/<feature>/migrations/` (tên và timestamp không đổi sau khi áp dụng, số tiếp theo thực tế). Bảng cần `object_id uuid NOT NULL UNIQUE REFERENCES object_ref(object_id)`, owner/FK/CHECK, index theo khóa lọc, `GRANT` đúng cột cho `product_data` (SELECT và UPDATE theo cột nếu có action ghi) và `SELECT` cho `product_authority` nếu rule/relation dùng. Đăng ký class vào `migrate` trong `tools/product.ts` (cùng chỗ `ProductDocument1792108800002`). Runtime so khớp ACL chính xác: thêm các grant mong đợi vào `verifyProductPrivileges` trong `ProductRuntime.onApplicationBootstrap` (`table:<t>:SELECT`, `column:<t>.<c>:UPDATE`), nếu không boot sẽ fail vì grant dư. Thêm kiểm bảng tồn tại (`SELECT ... LIMIT 0`) trước `markReady`.
3. **Binding**: `ProductStorageBindings.resources` (table, `objectIdColumn`, `keyColumn`, `columns`, `projection`) và, nếu cần, mutable field trong danh sách `ProductAuthorization` writable (`{resource, action, fields}`) ở runtime. Identifier chỉ lấy từ binding đã đăng ký; giá trị luôn bind.
4. **Route + classification**: facade port nhỏ `<feature>.http-port.ts` (operation đã bind resource/action, không để body chọn permission), controller với `@ProductAuthorize('<resource>', '<action>')` hoặc classification khác, DTO validate, success shape và status thực tế; facade được dựng trong `infrastructure/runtime.module.ts` bằng method bound của service. Controller chỉ import facade token/types (ESLint chặn typeorm/composition/runtime). Thiếu classification thì boot fail trước runtime bootstrap.
5. **Release/manifest**: thêm fragment vào `fragments` và `productReleaseSource` ở `authorization/product.manifest.ts`; bump sequence/predecessor/hash đúng quy tắc release (không sửa manifest đã áp dụng); `pnpm run manifest:sync`.
6. **Tests**: core (planner/evaluator + boundary/deny), PostgreSQL parity gateway (`test/*.integration-spec.ts`: list/detail/count/update dùng cùng AST, hidden và absent cùng 404), inventory route/OpenAPI trong `apps/api/test/structure.spec.ts`, ACL/probe trong `test/product-database.integration-spec.ts`, E2E nếu thay HTTP surface. Kiểm đủ boundary và deny ngoài mọi allow.

## Public API migration map

| Trước (free function / import)                                              | Sau                                                                                                 |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `validate`, `isValidated`                                                   | `core.validate(declarations)`, `core.isValidated(declarations)` (provenance theo instance)          |
| `planUser`, `evaluateUser`                                                  | `core.planUser(...)`, `core.evaluateUser(...)`                                                      |
| `normalizeValue`, `compareValues`, `canonicalTimestamp`, `canonicalInt64`   | cùng tên, là method của `AuthorizationCore`, delegate tới codec                                     |
| `parseKey`, `isCanonicalUuid`                                               | method của `AuthorizationCore` (UUID canonical vẫn chỉ lowercase)                                   |
| `prepareProductRelease(source)`, constant release                           | `prepareProductRelease(source, core)`, `createProductRelease(core)`                                 |
| `new ProductBindingRegistry(decl, bindings)`                                | thêm `core` làm tham số đầu                                                                         |
| `ProductManifestReconciler` options                                         | thêm `options.core`; `reissueRootActivation(..., core)`, `revokeProductRoot(..., core)`             |
| `ProductAuthorization(runner, bindings, validators, writable)`              | tham số thứ ba là `{ validators, obligations }` (typed registry, `productObligations` có `audit@1`) |
| `ProductIdentityService.audit(tx, userId, 'string')`                        | kind typed `ProductIdentityAuditKind`; writer chung `appendProductAudit` (`./operations`)           |
| `@base-authorization/typeorm-postgres` root (runner, gateway, provision...) | root: errors/types/helpers an toàn; `./composition` (constructors); `./operations` (CLI)            |
| `apps/api/src/{product.controller, http-services, product-runtime,...}.ts`  | `auth/`, `document/`, `administration/`, `health/`, `openapi/`, `infrastructure/`, `authorization/` |
| `import ... from '@base-authorization/typeorm-postgres/dist/...'`           | không còn resolve (`ERR_PACKAGE_PATH_NOT_EXPORTED`); dùng entrypoint chính thức                     |

Hành vi đổi có chủ ý: timestamp strict (30/2, `24:00:00`, offset, hơn 6 chữ số lẻ nay bị từ chối); audit `policy_revision` = revision đã đánh giá, `resultingRevision` trong metadata; lệnh offline ghi actor là `PRODUCT_OFFLINE_ACTOR`. Chi tiết ở ADR 0009.

## Chưa có

Delegation, generic administration và resource-to-resource domain binding chưa mở. T8 đã triển khai; T9 và T10 có phần độc lập đã triển khai và phần phụ thuộc policy/provider còn bị chặn (ADR 0010–0011, ledger của foundation hardening). Worker audit chưa wire vì thiếu sink thật; recovery delivery bền vững chưa có. Trạng thái theo kế hoạch/verification, không suy từ cấu trúc source.
