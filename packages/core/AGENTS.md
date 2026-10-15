# @base-authorization/core

Lõi quyết định thuần: types, typed keys, AST, validate/plan/evaluate qua instance `createAuthorizationCore`. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của package.

## Ranh giới

- Không thêm runtime dependency vào `package.json`. Trong `src/` không import thư viện ngoài, `@nestjs/*`, `typeorm`, `pg`, `express`, `node:*` hay package workspace khác. `eslint.config.js` và `test/workspace.smoke-spec.ts` có kiểm tra ranh giới; không suy ra chúng đã chặn mọi dependency có thể thêm.
- Không decorator, `types: []`; không I/O, không clock/crypto nền tảng. Adapter truyền thời gian và băm `canonical` (SHA-256).
- Không tên domain (submission, deal, patient…) trong `src/`. Domain chỉ là declarations/fixtures.
- Public API duy nhất qua `src/index.ts`; consumer không import file con.

## Bản đồ file

| File                    | Trách nhiệm                                                                                               |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| `types.ts`              | `TenantId`, `Key`, facts, `Expr`/`PlanExpr`, `Decision`, `TrustedInput`                                   |
| `runtime.ts`            | `createAuthorizationCore({ values })`: instance validate/plan/evaluate + scalar/key methods               |
| `key-codec.ts`          | Helper thuần của khóa: `keyEquals`, `keyToString`, `MAX_KEY_BYTES`, byte length/code point                |
| `expression.ts`         | Type-check/lower/simplify AST, `MAX_PATH_DEPTH` (8); normalize nhận từ instance                           |
| `ports/value-codecs.ts` | Interface `ScalarCodec`/`ValueCodecs` (chỉ type); implementation ở `packages/value-adapters`              |
| `declarations.ts`       | Kiểu `SystemDeclarations` (resource, action, policy, scope template, relation)                            |
| `policy-validator.ts`   | `validateDeclarations` → đóng băng + `canonical`; `canonicalJson` thuần                                   |
| `planner.ts`            | `planUser`/`planUnrestricted` (chung `resolveTarget`) → `UserAuthorizedPlan`; `plan` là wrapper tenant cũ |
| `evaluator.ts`          | `evaluateUser` và `evaluate` dùng chung traversal AST; không thay SQL                                     |

## Bất biến cần giữ khi sửa

- `P = requiredScope AND (allow OR record allow) AND NOT (deny OR record deny)`; tenant/membership/policy/validator/obligation kiểm tra trước. Một rule hỏng → cả quyết định deny.
- Permission boundary (ADR 0003, `docs/permission-boundaries.md`) đã lower vào cùng AST, AND ngoài mọi allow; không tự grant.
- Contract một sản phẩm dùng `UserTrustedInput`, `UserAuthoritySnapshot.user`, `UserAuthorizedPlan.userId` và facts không tenant. Không thêm tenant giả hoặc flag bỏ isolation. `plan`/`evaluate` cũ chỉ giữ compatibility trong giai đoạn chuyển đổi và kiểm tenant riêng.
- Lõi không biết Root. `planUnrestricted` giữ mọi kiểm tra target/principal/user/validity của `planUser` cộng revision canonical, predicate `true`, không obligations; chỉ `ProductAuthorization.access` được gọi (ESLint `no-restricted-syntax`, test ở `test/package-boundaries.spec.ts`). Tên role, kể cả `system.root`, không tạo bypass.
- JS `number` bị từ chối cho integer; decimal so bằng chuỗi; chuỗi so theo code point (khớp `COLLATE "C"`).
- `not`/`exception` chỉ lõi tạo. Emergency exception không cấp quyền cho tới Task 12; emergency deny vẫn có hiệu lực.
- `core.plan`/`core.planUser` chỉ nhận output của `core.validate` của **cùng instance** (WeakSet theo instance); `core.evaluate*` chỉ nhận plan do chính instance đó phát hành (`foreign_plan`). Không có engine/codec mặc định; free function scalar/plan/evaluate đã bỏ (ADR 0009).

## Khi refactor sang codec ports

- Factory `createAuthorizationCore` và ports đã có (`runtime.ts`, `ports/value-codecs.ts`). Codec thiếu/sai hình dạng → throw khi tạo; codec throw hoặc trả ngoài contract → mọi đường quyết định thành deny, `validate` trả `{ ok: false }` (không echo input). `isCanonicalUuid`/`parseTenantId`: codec quyết định hợp lệ, core tự giữ yêu cầu chữ thường. Không tự đổi public API ngoài task được yêu cầu.
- Core định nghĩa interface bằng primitive/readonly data; thư viện Day.js/Moment/decimal/UUID nằm ngoài core. Test adapter qua public API từ package adapter hoặc integration harness, không tạo dependency ngược từ core source.
- Không dùng clock, locale/timezone toàn cục hoặc mutable default codec. Một runtime phải dùng bộ codec nhất quán cho validate/plan/evaluate; dữ liệu validated không được chuyển sang runtime có semantics khác mà bỏ validation.
- Parse strict: từ chối invalid input thay vì tự sửa ngày, trim, làm tròn hoặc đoán timezone. Giữ integer/decimal chính xác và timestamp precision theo contract; lỗi codec không sinh allow.
- Unknown AST node/operator/kind phải fail closed, không lọt vào nhánh default được coi là thành công. Giới hạn depth/size trước traversal tốn tài nguyên; không mở arbitrary callback từ declarations.

## Test

- `packages/core/test/*.spec.ts`, fixtures chung ở `packages/core/test/fixtures.ts` (export `core` dựng từ `@base-authorization/value-adapters`, devDependency của root; core không khai báo dependency ngược). `runtime.spec.ts` kiểm instance/provenance/codec lỗi. Chạy: `pnpm run test:unit -- packages/core/test` (hoặc một file).
- Property test dùng PRNG có seed viết trong test, không có `fast-check`.
- Thay đổi algebra cần mutation check: bỏ conjunct tương ứng phải làm test fail.
- Codec change cần ca invalid calendar, leap year, timezone, precision, overflow và các luật normalize/compare; chạy cùng vectors cho mọi implementation. Predicate scalar phải có differential tests với PostgreSQL ở harness ngoài core.

Quyết định chi tiết: `docs/decisions/0002-core-plan-and-sql-compiler.md`.
