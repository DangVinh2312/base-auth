# Single product transition implementation plan

> Execution: implement directly, with isolated parallel work where file ownership permits. No commit/push/deploy. User prompt explicitly authorizes implementation without another design approval.

**Goal:** one PostgreSQL database, local/OIDC authentication, opaque sessions and strict user authorization.
**Spec:** `docs/authz-single-product-architecture.md`, ADR 0005–0007; implementation brief `../base-auth/docs/prompt.md`.
**Architecture:** reuse the pure AST, validation, planner/evaluator and parameterized SQL compiler. Remove tenant from the new runtime contracts; use one application fence and distinct database logins. Preserve historical migrations without editing them.
**Tech stack:** locked NestJS/TypeORM/pnpm/Node 24/PostgreSQL.

## Constraints and review focus

- No fake tenant, bypass Root, implicit optional boundary, runtime seed takeover, default password or email auto-link.
- Real data consolidation requires explicit mapping; fail migration rather than guess. Local disposable fixtures are authorized.
- Check absent facts, drift of code-owned rows, reset/login races, provider proof replay and privilege escalation.
- Every phase updates its callers, exports, fixtures, configuration and operations instructions. Checkbox completion requires current evidence.

## Steps and evidence ledger

- [x] P0: inspect existing contracts/tests; write reuse map and update root/module guidance. Frozen install/build/unit hiện tại đã pass; baseline unit trước mọi edit chưa capture riêng do DNS/dependency restoration.
- [x] P1: add single-product schema/forward migrations, distinct roles and application fence; test empty DB and fixture upgrade/refusal of unmapped legacy data.
- [x] P2: move core/gateway/authority/boundary/sync to user facts; run semantic regression and SQL differential tests.
- [x] P3: exact system-grant reconciliation, code-row DB protection, persistent Root bootstrap and actual API boot sync; race/drift/privilege tests.
- [x] P4: local/OIDC, sessions, invitations/recovery/linking; protocol fixtures, revoke/reset/login concurrency.
- [x] P5: minimal admin and one resource route fixture using shared service enforcement, projection, policies and boundaries.
- [x] P6: full local checks, E2E/mutation/concurrency/load evidence, CI configuration and operations runbooks. Frozen install, format/lint/types/build và full local suites đã pass; remote/production gates vẫn chưa đánh dấu.

## Initial findings (2026-10-13)

Boundary is already implemented in core, authority loading, tenant migration 003 and reconciler; older prose is stale. AppModule only has health routes and has no DB/authn wiring. No `.git` exists at destination; preserve source snapshot in `/private/tmp/base-auth-transition-backup/source-before.tar`, do not initialize/commit. Docker socket requires sandbox escalation; Docker 29.8.2 reachable with authorized escalation. Node 24.20.0 and pnpm 12.3.4 match constraints.

## Data gate

No credentials or mapping for real existing tenant/identity databases have been supplied. Do not inspect or modify them. New runtime and disposable fixtures can proceed; real consolidation and staging remain unverified.

## Bằng chứng theo bước

- P0: [reuse map](../../single-product-reuse-map.md), root/nested AGENTS đã cập nhật; frozen install pass, source snapshot giữ ngoài repo. Kiểm byte-for-byte4 historical migrations không đổi.
- P1: product schema + protection + relation-version forward migrations; actual real-login DB suite17cases và CLI fixture. Không merge legacy data; fixture nâng product schema và refusal cases giữ nguyên dữ liệu.
- P2: core79cases, product gateway/service7cases, SQL regressions và actual ReBAC wrong-type case. Legacy wrappers/regression giữ để đối chiếu, không wire vào AppModule mới.
- P3: system4cases + drift/ID/effect regressions3cases, bootstrap race/idempotency/no-reseed; API E2E thực sự không listen khi drift hoặc thiếu quyền write. Root recovery runbook ngoài API chưa là automated command.
- P4: Argon2 unit2cases, signed-OIDC/PostgreSQL9cases, local CLI invitation và HTTP activation/reset/revoke. Production delivery/IdP configuration vẫn là gate, không tự bật fallback hoặc trả secret HTTP.
- P5: API tối thiểu document list/detail/title write, user suspend với fresh reauth/rank/boundary; DTO allowlists/OpenAPI; handler-facing operations không có DB credentials/pools. Generic administration/file/export/jobs không mở.
- P6: [verification report](../../single-product-verification.md) có157integration +115unit +1actualHTTP E2E; bốn mutations đều caught/restored,55P03 thật và40P01/40001 injected có rollback/effect proof. [Load results](../../single-product-load-results.md), [operations](../../single-product-operations.md), CI chứa actual commands, remote chưa chạy.

## Rulings và phạm vi chưa triển khai

- Dùng implementation user-based song song legacy compatibility để giữ regression và không tự gộp dữ liệu. Chi phí: còn code tenant lịch sử cho tới khi mapping/parity/retirement được duyệt; runtime API mới không dùng nó.
- Drift chặn cả new release để không nhận omitted unauthorized facts làm baseline. Recovery yêu cầu repair offline có approval/audit rồi forward release; chi phí: không có automatic in-place repair hoặc recovery CLI.
- Recovery delivery là port, default503 vì chưa có provider; local invitation/bootstrap proof ghi artifact0600. Chi phí: cần kênh delivery thật được chọn trước production.
- Administration chọn phạm vi tối thiểu suspend; generic assignments/grants/bindings/relations và files/export/jobs fail closed qua capability không mở. Không claim toàn bộ admin roadmap cũ hoàn tất.
- No Git repository: giữ snapshot, không init/commit/push/deploy. Independent reviewer đã kiểm các phần DB/compiler/manifest; API/CLI cuối là self-review + actual-process tests, không whole-branch independent review cuối.

## Gate ngoài local (chưa hoàn tất)

- [ ] Mapping/backup/access review để chuyển dữ liệu thật; không cần gate này để tiếp tục fixtures/runtime độc lập.
- [ ] Production IdP/TLS, approval authority recovery, mail/audit delivery, secret rotation, Argon2/blocklist calibration và durability/failover/restore.
- [ ] Production workload/replicas/pool sizing; benchmark fixture không là SLO.
- [ ] GitHub workflow thực chạy và staging handoff được authorize; local pass không CI pass.
