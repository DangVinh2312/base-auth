# Authorization core

Lõi quyết định thuần: types, typed keys, AST, validate/plan/evaluate qua instance `createAuthorizationCore`. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của module.

## Ranh giới

- Trong module này không import thư viện ngoài, `@nestjs/*`, `typeorm`, `pg`, `express`, `node:*` hoặc services/adapters của app. `eslint.config.js` và `test/workspace.smoke-spec.ts` có kiểm tra ranh giới; không suy ra chúng đã chặn mọi dependency có thể thêm.
- Không decorator, I/O hoặc clock/crypto nền tảng. Adapter truyền thời gian và băm `canonical` (SHA-256).
- Không tên domain (submission, deal, patient…) trong `src/`. Domain chỉ là declarations/fixtures.
- Consumer và tests import trực tiếp file sở hữu; không giữ barrel/entrypoint của package cũ.

## Bản đồ file

| File                            | Trách nhiệm                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `authorization.types.ts`        | `UserId`, `Key`, facts, `Expr`/`PlanExpr`, `UserDecision`, `UserTrustedInput`                          |
| `authorization.factory.ts`      | `createAuthorizationCore({ values })`: instance validate/plan/evaluate + scalar/key methods            |
| `key.codec.ts`                  | Helper thuần của khóa: `keyEquals`, `keyToString`, `MAX_KEY_BYTES`, byte length/code point             |
| `expression.helper.ts`          | Type-check/lower/simplify AST, `MAX_PATH_DEPTH` (8); normalize nhận từ instance                        |
| `ports/value-codecs.port.ts`    | Interface `ScalarCodec`/`ValueCodecs` (chỉ type); implementation ở `apps/api/src/authorization/values` |
| `authorization.declarations.ts` | Kiểu `SystemDeclarations` (resource, action, policy, scope template, relation)                         |
| `policy.validator.ts`           | `validateDeclarations` → đóng băng + `canonical`; `canonicalJson` thuần                                |
| `authorization.planner.ts`      | `planUser`/`planUnrestricted` (chung `resolveTarget`) → `UserAuthorizedPlan`                           |
| `authorization.evaluator.ts`    | `evaluateUser` traversal AST; không thay SQL                                                           |

## Bất biến cần giữ khi sửa

- `P = requiredScope AND (allow OR record allow) AND NOT (deny OR record deny)`; user/policy/validator/obligation kiểm tra trước. Một rule hỏng → cả quyết định deny.
- Permission boundary (ADR 0003, `docs/permission-boundaries.md`) đã lower vào cùng AST, AND ngoài mọi allow; không tự grant.
- Contract một sản phẩm dùng `UserTrustedInput`, `UserAuthoritySnapshot.user`, `UserAuthorizedPlan.userId` và facts không tenant. Không thêm tenant giả hoặc flag bỏ isolation. Không giữ contracts/wrappers tenant (ADR 0014).
- Lõi không biết Root. `planUnrestricted` giữ mọi kiểm tra target/principal/user/validity của `planUser` cộng revision canonical, predicate `true`, không obligations; chỉ nhánh Root của `ProductAuthorization.access` được gọi. ESLint `no-restricted-syntax` chặn truy cập thuộc tính/destructuring tên `planUnrestricted` ngoài file `apps/api/src/authorization/services/product-authority.service.ts`, core factory nội bộ `apps/api/src/authorization/core/authorization.factory.ts` và `test/core/**` (test ở `test/module-boundaries.spec.ts`); Import/re-export trực tiếp tên `planUnrestricted` cũng bị chặn ngoài các vị trí đó; computed access như `core['planUnrestricted']` không bị bắt, nên đây là ranh giới developer, không phải sandbox. Tên role, kể cả `system.root`, không tạo bypass.
- JS `number` bị từ chối cho integer; decimal so bằng chuỗi; chuỗi so theo code point (khớp `COLLATE "C"`).
- `not`/`exception` chỉ lõi tạo. Emergency exception không cấp quyền cho tới Task 12; emergency deny vẫn có hiệu lực.
- `core.planUser`/`core.planUnrestricted` chỉ nhận output của `core.validate` của **cùng instance** (WeakSet theo instance); `core.evaluateUser` chỉ nhận plan do chính instance đó phát hành (`foreign_plan`). Không có engine/codec mặc định; free function scalar/plan/evaluate đã bỏ (ADR 0009).

## Khi refactor sang codec ports

- Factory `createAuthorizationCore` và ports đã có (`authorization.factory.ts`, `ports/value-codecs.port.ts`). Codec thiếu/sai hình dạng → throw khi tạo; codec throw hoặc trả ngoài contract → mọi đường quyết định thành deny, `validate` trả `{ ok: false }` (không echo input). `isCanonicalUuid`: codec quyết định hợp lệ, core tự giữ yêu cầu chữ thường. Không tự đổi public API ngoài task được yêu cầu.
- Core định nghĩa interface bằng primitive/readonly data; thư viện Day.js/Moment/decimal/UUID nằm ngoài core. Test adapter qua module codec hoặc integration harness, không tạo dependency ngược từ core source.
- Không dùng clock, locale/timezone toàn cục hoặc mutable default codec. Một runtime phải dùng bộ codec nhất quán cho validate/plan/evaluate; dữ liệu validated không được chuyển sang runtime có semantics khác mà bỏ validation.
- Parse strict: từ chối invalid input thay vì tự sửa ngày, trim, làm tròn hoặc đoán timezone. Giữ integer/decimal chính xác và timestamp precision theo contract; lỗi codec không sinh allow.
- Unknown AST node/operator/kind phải fail closed, không lọt vào nhánh default được coi là thành công. Giới hạn depth/size trước traversal tốn tài nguyên; không mở arbitrary callback từ declarations.

## Test

- `test/core/*.spec.ts`, fixtures chung ở `test/core/fixtures.ts` (export `core` dựng từ codecs của app; core source không import ngược codecs). `runtime.spec.ts` kiểm instance/provenance/codec lỗi. Chạy: `pnpm run test:unit -- test/core` (hoặc một file).
- Property test dùng PRNG có seed viết trong test, không có `fast-check`.
- Thay đổi algebra cần mutation check: bỏ conjunct tương ứng phải làm test fail.
- Codec change cần ca invalid calendar, leap year, timezone, precision, overflow và các luật normalize/compare; chạy cùng vectors cho mọi implementation. Predicate scalar phải có differential tests với PostgreSQL ở harness ngoài core.

Quyết định chi tiết: `docs/decisions/0002-core-plan-and-sql-compiler.md`.
