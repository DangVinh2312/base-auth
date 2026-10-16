# Remove legacy implementation plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` for independent core and SQL fixture tasks; root integrates and verifies. Do not commit/push.

**Goal:** Xóa implementation/compatibility tenant cũ theo yêu cầu người dùng; giữ runtime và các kiểm tra bảo mật một sản phẩm.

**Architecture:** Một NestJS app, PostgreSQL product database với fixed-purpose credentials. Không tenant contract/wrapper/adapter/CLI; core và compiler hiện hành giữ semantics. Product migration chain vẫn dựng schema hiện tại.

**Spec:** [ADR 0014](../../decisions/0014-remove-legacy-runtime.md), bổ sung ADR 0013 và yêu cầu hiện tại.

## Constraints / review focus

- Giữ thay đổi trước đó và tài liệu HR của người dùng; không reset/stash/commit/push/deploy.
- Không đổi product SQL/migration identifiers, manifest hash, HTTP/auth/Root/fence/audit/precision semantics.
- Không xóa coverage algebra, SQL differential hoặc collation chỉ vì fixtures cũ dùng tenant.
- Xóa source và consumers cùng nhau; cold build không để artifacts legacy tồn tại giả.
- Tests chạy bằng pnpm/Node 24, PostgreSQL disposable; integration và E2E chạy tuần tự.

## Task 1: Core một sản phẩm

- [x] Xóa tenant types, wrappers, `parseTenantId` và factory API; `User*` thành contracts độc lập.
- [x] Chuyển shared core fixtures/tests sang user; chỉ bỏ assertions tenant-specific, giữ deny/boundary/policy/ReBAC/provenance/codec behavior.
- [x] Core build/unit và review.

## Task 2: SQL fixtures còn hữu ích

- [x] Chuyển `test/fixtures/resources.ts`, compiler/collation suites sang product compiler/schema/pools.
- [x] Giữ differential vectors/key precision/native-index/SQL binding tests, bỏ tenant-cross-routing assertions.
- [x] PostgreSQL verification và review.

## Task 3: Xóa legacy graph và đồng bộ callers

- [x] Xóa `apps/api/src/legacy`, `test/legacy`, tenant CLI/env và tests chỉ dành cho tenant adapters.
- [x] Xóa frozen release 1 compatibility fixture/suite; dọn release helper types và unit tests legacy, giữ product release validation/hash/provenance checks.
- [x] Cập nhật config/scripts/module boundaries, current AGENTS/README/operations/architecture/reuse docs; giữ lịch sử ADR/plans.

## Task 4: Kiểm chứng cuối

- [x] Rà import graph/references và diff, cold build, typecheck/lint/format có phạm vi, full unit.
- [x] Full integration serial rồi full E2E, không đổi assertions/timeouts để che lỗi.
- [x] Review độc lập, ghi kết quả thật/giới hạn và bàn giao chưa commit.

## Ledger

- Repo/branch đã xác nhận: `/Users/vinhdq2312/Documents/personal/base-auth`, `refactor/single-app-modules`; working tree có conversion/cleanup/startup harness chưa commit và tài liệu HR của người dùng. Không coi đó là baseline sạch.
- Ruling: giữ product migrations 001–012 vì đó là đường dựng schema hiện tại; xóa implementation và fixtures compatibility riêng, không gộp thay SQL/security design trong task bỏ legacy.

- Removed graph: 34 files (18 tenant/bootstrap/audit source files, tenant-only tests/CLI, frozen release 1 fixture và upgrade suite). Danh sách kiểm trong `/tmp/base-auth-removed-legacy-files.json`; tất cả vẫn không tồn tại sau build. Không còn `db:*:legacy` scripts hoặc `apps/api/dist/legacy`.
- Core: `User*` contracts độc lập; bỏ tenant types, `plan`/`evaluate` wrappers và `parseTenantId`. Shared `buildPlan`, unrestricted planner và evaluator traversal giữ semantics; giữ user-state/principal, deny/boundary/policy, scalar precision, ReBAC/expiry, instance provenance tests. Chỉ xóa assertions/cases riêng cho tenant/parser cũ.
- SQL: compiler/collation fixtures dùng một product dataset, product migrations và `product_data` login. Giữ 17 differential scenarios, record exceptions, relation version/type/expiry, bigint/UUID/text keys, native-index EXPLAIN, injection và ICU/code-point ordering. Chỉ bỏ ca query cross-tenant.
- Root/runtime: bỏ tenant readiness Set/methods; giữ readiness trước listen, facades, Root/session guards, privilege probes, fenced transactions và atomic audit. Product SQL/migrations 001–012 và manifest hashes không đổi. Negative fixture từ chối schema ngoài thiết kế vẫn cần cho product provisioning; không phải đường hỗ trợ/import legacy.
- Review độc lập: phát hiện duplicate-role/blank-label assertions hữu ích bị xóa cùng test legacy; đã chuyển sang `prepareProductRelease(productReleaseSource)` và reviewer xác nhận đóng finding. Không còn findings; reviewer chỉ đọc, không thay kết quả runtime checks.
- Cold build: kiểm app dist chỉ gồm generated files rồi xóa 169 artifacts; `pnpm run build` exit 0 (log `/tmp/base-auth-no-legacy-cold-build.log`). Typecheck/lint cuối exit 0: `pnpm run typecheck` (gồm build), `pnpm run lint` (logs `/tmp/base-auth-no-legacy-typecheck-final.log`, `/tmp/base-auth-no-legacy-lint-final.log`). Scoped Prettier và `git diff --check` pass.
- Full unit trước khôi phục role-validation case: 239/239 pass; full unit cuối `pnpm run test:unit`: exit 0, 240/240 pass, 12 suites, không skip/cancel/todo; 12712.137906 ms (log `/tmp/base-auth-no-legacy-unit-final.log`). Không chỉ rerun subset.
- Targeted SQL port verification: `pnpm exec node --test --test-timeout=300000 --test-concurrency=1 test/compiler.integration-spec.ts test/collation.integration-spec.ts`: exit 0, 26/26 pass, không skip/cancel (log `/tmp/base-auth-no-legacy-sql.log`).
- Full integration sau đó: `pnpm exec node --test --test-timeout=300000 --test-concurrency=1 'test/**/*.integration-spec.ts'`: exit 0, 142/142 pass, 2 suites, đủ 18 files, không skip/cancel/todo; 212658.064866 ms (log `/tmp/base-auth-no-legacy-integration.log`). Đây là full run mới; số tests giảm vì các suites tenant/release 1 đã bị xóa theo yêu cầu. Concurrency bên trong lock/transaction/worker tests giữ nguyên; chưa xác nhận chế độ runner mặc định ba file đồng thời.
- Full E2E cuối: `pnpm run test:e2e`: exit 0, 1/1 pass, không skip/cancel/todo; 10956.719785 ms (log `/tmp/base-auth-no-legacy-e2e.log`). Giữ đầy đủ activation/login, scoped read/write, Root fresh-auth/bypass, revoke/reset, boot drift/privilege refusal và pool cleanup assertions.
- SHA-256 của 129 source/test/config files khớp trước/sau full integration và E2E; không có thay đổi đầu vào trong lúc chạy. Không thêm dependency, không cần đổi lockfile cho xóa scripts/source; không đọc secrets hoặc tài liệu HR. Không production/provider thật, commit/push/deploy.
