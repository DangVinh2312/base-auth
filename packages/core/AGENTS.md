# @base-authorization/core

Lõi quyết định thuần: types, typed keys, AST, validate/plan/evaluate. Đọc root `AGENTS.md` trước; file này chỉ bổ sung phần riêng của package.

## Ranh giới

- Không dependency nào trong `package.json`. Không import `@nestjs/*`, `typeorm`, `pg`, `express`, `node:*` hay package workspace khác — ESLint (`eslint.config.js`) và `test/workspace.smoke-spec.ts` chặn điều này.
- Không decorator, `types: []`; không I/O, không clock/crypto nền tảng. Adapter truyền thời gian và băm `canonical` (SHA-256).
- Không tên domain (submission, deal, patient…) trong `src/`. Domain chỉ là declarations/fixtures.
- Public API duy nhất qua `src/index.ts`; consumer không import file con.

## Bản đồ file

| File                  | Trách nhiệm                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `types.ts`            | `TenantId`, `Key`, facts, `Expr`/`PlanExpr`, `Decision`, `TrustedInput`                    |
| `key-codec.ts`        | Khóa canonical (int64 dạng chuỗi/bigint, uuid, text ≤ 256 byte), so sánh                   |
| `expression.ts`       | Chuẩn hóa/so sánh giá trị, `MAX_PATH_DEPTH` (8)                                            |
| `declarations.ts`     | Kiểu `SystemDeclarations` (resource, action, policy, scope template, relation)             |
| `policy-validator.ts` | `validate` → declarations đóng băng + `canonical`; từ chối node/operator lạ                |
| `planner.ts`          | `planUser` → `UserAuthorizedPlan`; `plan` là wrapper compatibility tenant cũ; cùng algebra |
| `evaluator.ts`        | `evaluateUser` và `evaluate` dùng chung traversal AST; không thay SQL                      |

## Bất biến cần giữ khi sửa

- `P = requiredScope AND (allow OR record allow) AND NOT (deny OR record deny)`; tenant/membership/policy/validator/obligation kiểm tra trước. Một rule hỏng → cả quyết định deny.
- Permission boundary (ADR 0003, `docs/permission-boundaries.md`) đã lower vào cùng AST, AND ngoài mọi allow; không tự grant.
- Contract một sản phẩm dùng `UserTrustedInput`, `UserAuthoritySnapshot.user`, `UserAuthorizedPlan.userId` và facts không tenant. Không thêm tenant giả hoặc flag bỏ isolation. `plan`/`evaluate` cũ chỉ giữ compatibility trong giai đoạn chuyển đổi và kiểm tenant riêng.
- `system.root` là role thông thường trong lõi: không bypass policy/boundary/deny hoặc tự sinh grant.
- JS `number` bị từ chối cho integer; decimal so bằng chuỗi; chuỗi so theo code point (khớp `COLLATE "C"`).
- `not`/`exception` chỉ lõi tạo. Emergency exception không cấp quyền cho tới Task 12; emergency deny vẫn có hiệu lực.
- `plan`/`planUser` chỉ nhận output của `validate` (WeakSet), không nhận object tự dựng.

## Test

- `packages/core/test/*.spec.ts`, fixtures chung ở `packages/core/test/fixtures.ts`. Chạy: `pnpm run test:unit -- packages/core/test` (hoặc một file).
- Property test dùng PRNG có seed viết trong test, không có `fast-check`.
- Thay đổi algebra cần mutation check: bỏ conjunct tương ứng phải làm test fail.

Quyết định chi tiết: `docs/decisions/0002-core-plan-and-sql-compiler.md`.
