# IAM thuần / Root ngoài IAM (ADR 0012)

Ngày: 2026-10-15. Môi trường: Node 24.20.0, pnpm 12.3.4, Docker 29.8.2, PostgreSQL 18.4 disposable (Testcontainers), macOS. Branch `feat/iam-root-separation`, HEAD `72367b6` (Task 1–9 đã commit) cộng thay đổi docs của Task 10 chưa commit lúc chạy; không staging/production, không push/deploy. Kết quả là lượt chạy local, không thay CI hoặc kiểm chứng production và không nâng trạng thái production-ready. Plan và ledger: `docs/superpowers/plans/2026-10-15-iam-root-separation.md`.

## Semantics mới

- Root là account `app_user.kind = 'root'` ngoài IAM (tối đa một; không role/grant/boundary/rule/record exception, DB guard chặn). `ProductAuthorization.access` là điểm rẽ nhánh duy nhất: `kind` từ `resolve_session` trong fenced transaction; Root dùng `planUnrestricted` (predicate `true`, không obligations, vẫn kiểm resource/action đã khai báo, principal, validity, revision canonical), IAM dùng `planUser` như cũ.
- Root vẫn cần session hợp lệ, `auth_epoch`, không suspended, CSRF/Origin; ghi `write`/`admin` cần fresh-auth 300 giây tính trong SQL (`PRODUCT_FRESH_AUTH_SQL`, µs, đồng hồ DB). Thiếu fresh → `ProductAccessDenied`, không audit.
- Mỗi `access` commit của Root ghi một event (`principalKind: 'root'`, `outcome` `ok`/`absent`) trực tiếp trong transaction: đọc `access.<resource>.<action>`, ghi `data.update`/`account.suspend`. Audit lỗi → rollback, không payload. Event IAM giữ nguyên.
- IAM không còn rank; `account.suspend` cần grant + boundary (hiện chưa có boundary cho `account`, nên chỉ Root suspend được). Root, chính actor Root và id vắng mặt đều 404.
- Lịch sử bên dưới (vd. mutation "Bypass Root" bị bắt như lỗi) giữ nguyên; semantics đó đã bị ADR 0012 thay thế.

## Gate

| Lệnh (từ repo root)              | Exit | Kết quả                                                                                                                                                                                                              |
| -------------------------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install --frozen-lockfile` | 0    | Lockfile up to date; `pnpm-lock.yaml` không đổi                                                                                                                                                                      |
| `pnpm run format:check`          | 1    | Chỉ 15 file trong `.superpowers/sdd/` (workspace SDD tạm, untracked và git-ignored bằng `.gitignore` lồng mà Prettier không đọc) bị báo. Cùng lệnh Prettier thêm `--ignore-path .superpowers/sdd/.gitignore`: exit 0 |
| `pnpm run lint`                  | 0    | pass                                                                                                                                                                                                                 |
| `pnpm run typecheck`             | 0    | pass                                                                                                                                                                                                                 |
| `pnpm run build`                 | 0    | pass                                                                                                                                                                                                                 |
| `pnpm run test:unit`             | 0    | 234/234 pass, 13 suites, 0 skip                                                                                                                                                                                      |
| `pnpm run test:integration`      | 0    | 236/236 pass, 12 suites, 0 skip/cancelled; không có lỗi môi trường/Testcontainers timeout (161,6 s)                                                                                                                  |
| `pnpm run test:e2e`              | 0    | 1/1 pass                                                                                                                                                                                                             |

Một lượt full-suite thật, không targeted rerun. Không sửa `.prettierignore` cho workspace tạm.

## Mutation checks (spec mục 10) trên bản sao cô lập

Git worktree của `72367b6` trong thư mục scratchpad, `pnpm install --frozen-lockfile`; mỗi mutation: sửa đúng chuỗi (script kiểm chuỗi xuất hiện đúng một lần) → chạy lệnh (script tự `tsc -b`) → ghi exit code và test fail → `git checkout -- .`. Worktree đã xóa. Cả 10 mutation đều bị bắt; mutation nào cũng làm fail test được plan nêu tên.

| #   | Mutation                                                                                                 | Lệnh (`pnpm run test:integration -- …`)             | Exit | Test fail (fail/tổng)                                                                                                                                                                                                                                                              |
| --- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Coi mọi principal là Root (`session.kind === 'root'` → `true` trong ternary `decision`)                  | `test/product-root.integration-spec.ts`             | 1    | 3/10: `IAM reads stay scoped and unaudited; a role named like Root grants nothing`, `IAM suspend needs a grant and a boundary; self is 403; Root is invisible to IAM`, `a failed Root audit rolls the access back and returns nothing`                                             |
| 2   | Lấy `kind` từ role name (`snapshot.roles.includes('system.root')`)                                       | như #1                                              | 1    | 5/10: `IAM reads stay scoped…`, `Root reads every document without a grant, through the same projection, with an audit per access`, `Root writes need a fresh reauthentication…`, `an OIDC reauthentication is fresh as well…`, `Root suspends an IAM account…`                    |
| 3   | Bỏ fresh-auth ghi Root (xóa `if (session.kind === 'root' && mode !== 'read' && !session.fresh) throw …`) | như #1                                              | 1    | 3/10: `Root writes need a fresh reauthentication; then policy scope is bypassed but fields are not`, `an OIDC reauthentication is fresh as well…`, `Root suspends an IAM account…`                                                                                                 |
| 4   | Bỏ `kind='iam'` trong view `iam_account` (`012-iam-root.ts`)                                             | `test/product-root-guards.integration-spec.ts` + #1 | 1    | 3/17: `iam_account hides Root, DELETE app_user is refused, resolve_session reports kind`, `Root suspends an IAM account; itself, absent and malformed ids reveal nothing`, `IAM suspend needs a grant and a boundary…`                                                             |
| 5   | Bỏ audit Root (xóa `if (session.kind === 'root') await appendProductAudit(…)`)                           | như #1                                              | 1    | 4/10: `Root reads every document…`, `Root writes need a fresh reauthentication…`, `a failed Root audit rolls the access back…`, `Root suspends an IAM account…`                                                                                                                    |
| 6   | Bỏ drift check trong migration (xóa khối bước 2 của `012`)                                               | `test/product-iam-migration.integration-spec.ts`    | 1    | 1/7: `unmarked release 1: drift and a stray holder roll back; then 012 upgrades and release 2 syncs`                                                                                                                                                                               |
| 7   | Genesis không kiểm catalog rỗng (`current!.sequence === '0'`)                                            | `test/product-genesis.integration-spec.ts`          | 1    | 1/2: `genesis needs an empty code-owned catalog; otherwise the predecessor stays strict`                                                                                                                                                                                           |
| 8   | Bỏ ` FOR SHARE` trong `guardRootNotIamSubjectBody`                                                       | `test/product-root-concurrency.integration-spec.ts` | 1    | 2/4: `facts and tokens written while a promotion holds the target wait, then are refused`, `a promotion waiting behind an uncommitted fact or token is refused once the writer commits`                                                                                            |
| 9   | Bỏ khối `IF current_setting('transaction_isolation')…END IF;` trong `guard_root_kind`                    | như #8                                              | 1    | 1/4: `a promotion outside READ COMMITTED is refused with real credentials outside the runner`                                                                                                                                                                                      |
| 10  | `guardRootLifecycleBody`: `ELSIF session_user NOT IN ('product_identity','product_authority')`           | `test/product-root-guards.integration-spec.ts`      | 1    | 3/7: `lifecycle: bootstrap never touches IAM, authority never touches Root, identity keeps its flows`, `no runtime login lifts a Root suspension; the approved offline repair does (spec 4.6)`, `iam_account hides Root, DELETE app_user is refused, resolve_session reports kind` |

Chuỗi đích của cả 10 mutation khớp nguyên văn code tại `72367b6` (mutation #7 đúng `current!.sequence === '0' && (await codeOwnedCatalogIsEmpty(m))`). Lượt đầu của #8 bị dừng giữa chừng do lỗi script của người chạy (không phải kết quả test); #8–#10 chạy lại trọn vẹn và kết quả trên là của lượt chạy lại.

## Kiểm tra thủ công một lần: binary cũ trên schema mới

- Git worktree `50d6053` (trước Task 1) trong scratchpad: `pnpm install --frozen-lockfile`, `pnpm run build` (exit 0); repo hiện tại build bằng `tsc -b tsconfig.build.json` (exit 0).
- Container disposable `postgres:18.4` trên cổng 55432 (`--rm`).
- Script provision (dist mới) gọi `provisionProductDatabase` với password ngẫu nhiên và in JSON settings ra stdout; JSON chỉ đi qua pipe sang script probe cũ, không in ra terminal hay ghi file. Script probe cũ mở DataSource `data`, `identity`, `authority`, `sync` bằng `productDataSourceOptions` của dist `50d6053` và gọi `verifyProductPrivileges` của dist `50d6053`.
- Lệnh: `node iam-compat-provision.ts | node iam-compat-old-probe.ts`.
- Kết quả: DB ở migration `ProductIamRoot1792108800012`; probe cũ ném `Product privilege drift for data: unexpected [], missing [column:app_user.authority_level:SELECT]`. Binary cũ không khởi động trên schema mới (đúng kỳ vọng `Product privilege drift …`). Exit code của hai tiến trình trong pipe không được ghi lại; bằng chứng là thông điệp lỗi ở trên. Không chạy lại vì provision lần nữa sinh password mới không khớp role đã tạo.
- Đã dọn: `docker stop iam-compat`, `git worktree remove … --force`, xóa hai script.

## Gates chưa được chứng nhận (ADR 0012)

- CI GitHub chưa chạy cho branch này; kết quả trên là local.
- Spec 4.3 yêu cầu holder giữ nguyên `state` pending/active/suspended khi nâng cấp; test hiện chỉ kiểm `active`.
- Chưa đo timing Root/absent ở suspend; chưa có test khẳng định IAM actor nhận event giống hệt cho target Root và target vắng mặt (lập luận từ code).
- Reauth OIDC trong suite `product-root` dựng bằng `reauthenticated_at` do DB đặt, không qua IdP thật (spec deviation 8).
- Repair gỡ suspend Root và nâng cấp production chưa diễn tập; runbook ở `docs/single-product-operations.md` mục 8–9.

---

# Bằng chứng giai đoạn A — Foundation Hardening, API Structure & Pluggable Adapters

Ngày: 2026-10-14. Môi trường: Node 24.20.0, pnpm 12.3.4, Docker local, PostgreSQL 18.4 disposable (Testcontainers), macOS. Working tree chưa commit trên branch `feat/foundation-hardening-adapters`; không staging/production, không push/deploy. Kết quả dưới đây là lượt chạy local của T11 trên working tree này; không thay thế CI hoặc kiểm chứng production, và không nâng trạng thái production-ready. Phase B (T8–T10) chưa thực hiện.

| Lệnh (từ repo root)              | Exit | Kết quả                                                                                                                                                   |
| -------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install --frozen-lockfile` | 0    | Lockfile up to date; `pnpm-lock.yaml` không đổi (md5 trước/sau giống nhau)                                                                                |
| `pnpm run format:check`          | 1    | Chỉ 23 file trong `.superpowers/` (workspace SDD tạm, xóa khi kết thúc) bị báo; mọi file nguồn/tài liệu branch thay đổi hoặc mới: `prettier --check` sạch |
| `pnpm run lint`                  | 0    | pass                                                                                                                                                      |
| `pnpm run typecheck`             | 0    | pass                                                                                                                                                      |
| `pnpm run build`                 | 0    | pass                                                                                                                                                      |
| `pnpm run test:unit`             | 0    | 227/227 pass, 0 skip                                                                                                                                      |
| `pnpm run test:integration`      | 0    | 184/184 pass, 0 skip/cancelled; không có Testcontainers startup timeout (đủ 12 suites, `--test-concurrency=3`)                                            |
| `pnpm run test:e2e`              | 0    | 1/1 pass (HTTP process thật + PostgreSQL)                                                                                                                 |

Đây là một lượt chạy full-suite thật, không phải targeted rerun. `format:check` toàn repo chỉ xanh sau khi xóa `.superpowers/`; không sửa `.prettierignore` cho workspace tạm.

## Mutation checks trên bản sao cô lập

Bản sao repo (kèm `node_modules`) trong thư mục tạm; working tree không bị mutate; mỗi mutation: áp dụng → build → chạy test hành vi → ghi test fail → khôi phục (so `cmp` với nguồn) rồi xóa bản sao.

| Mutation                                                                                                       | Test hành vi fail                                                                                                                                                                                                                                               | Kết luận |
| -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| Bỏ boundary conjunct khỏi predicate (`packages/core/src/planner.ts`; SQL compile cùng predicate)               | Unit core 8 fail (permission-boundary, seeded property "boundary never enlarges", user-decision). Integration `product-authorization` + `permission-boundary` 11 fail (list/detail/count parity, narrowing/removing binding, "three applications, one core" ×6) | Bị bắt   |
| Bypass Root: predicate `true` khi role `system.root`                                                           | Unit `user facts must identify the active principal; Root has no grant bypass`, `user authorization exports a tenant-free plan...`; integration 3 fail (list/detail/count parity, integer writes, boundary tightening)                                          | Bị bắt   |
| Bỏ application fence: shared runner không gọi `authz_acquire_shared_fence`                                     | `boundary tightening waits for shared access; decisions after commit read fresh authority` (`true !== false`) và 2 audit test phụ thuộc revision                                                                                                                | Bị bắt   |
| Timestamp adapter cắt microsecond (đổi codec trong `createProductAuthorizationCore` thành bản giữ 3 chữ số lẻ) | `test/product-values.integration-spec.ts`: `timestamp literal, parameter deny, boundary and expiry: SQL equals evaluateUser on DB facts`, `writes keep all six fractional digits...`                                                                            | Bị bắt   |
| (Bổ sung) cùng lỗi cắt microsecond ngay trong adapter Day.js                                                   | `packages/value-adapters` conformance 7 fail (`keeps full microsecond precision`, `.000001 sorts before .000002`, năm round-trip)                                                                                                                               | Bị bắt   |

Ghi chú: mutation fence thay lệnh khóa bằng truy vấn trả revision hằng (không khóa), nên hai test audit fail thêm vì revision hằng; test khóa mới là bằng chứng hành vi. Test conformance của adapter chỉ chạy adapter được đưa vào; lỗi trong composition root (hàng thứ tư) do test PostgreSQL parity bắt, không phải conformance.

## Phạm vi giai đoạn A đã kiểm (tóm tắt, chi tiết ở ledger kế hoạch)

T1: codec ports + Day.js adapter (61 test conformance/scalar). T2–T3: instance core, provenance A/B, fail-closed khi codec lỗi, PostgreSQL parity timestamp µs, hash manifest giữ nguyên. T4: probe CREATE/TEMP/grant option/trigger/function ACL mới. T5: audit typed target/`resultingRevision`, obligation registry. T6: inventory 24 route, OpenAPI hash, DI behavioural, bootstrap fail trước listen, route inventory chạy ở `onModuleInit`. T7: exports map + ESLint boundary + `test/package-boundaries.spec.ts` (21 test).

## Gates chưa được chứng nhận (giai đoạn A)

Giữ nguyên danh sách ở cuối tài liệu này, thêm: T8 (I/O trong fence theo số đo), T9 (limiter/session/cleanup), T10 (audit sink và recovery delivery bền vững) chưa thực hiện; delegation, generic administration, resource-to-resource domain binding chưa có; adapter thời gian thứ hai chưa có (conformance chưa là export dùng lại); `product-authority` còn `Date.parse` cho freshness 300s (số học trên clock DB, không phải validation timestamp). CI GitHub chưa chạy.

---

# Lịch sử — bằng chứng một sản phẩm trước giai đoạn A (không chứng nhận working tree hiện tại)

Ngày: 2026-10-14 (chạy lại sau sửa review findings 1–10 và năm vòng review độc lập). Môi trường Node24.20.0, pnpm12.3.4, Docker29.8.2, PostgreSQL18.4 disposable. Không staging/production, commit/push/deploy. Các lệnh sau đã chạy trên implementation hiện tại; không lấy spike hoặc kết quả tenant cũ làm chứng nhận bản mới.

| Lệnh                             | Kết quả                                                       |
| -------------------------------- | ------------------------------------------------------------- |
| `pnpm install --frozen-lockfile` | Pass; lockfile không cần sửa                                  |
| `pnpm run format:check`          | Pass                                                          |
| `pnpm run lint`                  | Pass                                                          |
| `pnpm run typecheck`             | Pass                                                          |
| `pnpm run build`                 | Pass                                                          |
| `pnpm run test:unit`             | 120/120 pass, không skip                                      |
| `pnpm run test:integration`      | 168/168 pass ×3 liên tiếp, không skip, `--test-concurrency=3` |
| `pnpm run test:e2e`              | 1/1 pass, actual HTTP process + PostgreSQL, nhiều assertions  |

Format check đã pass sau khi formatter hoàn tất toàn bộ tài liệu bàn giao. Logs cục bộ của phiên ở `/private/tmp/base-auth-transition-backup`; tài liệu này lưu kết quả và phạm vi để không phụ thuộc retention của thư mục tạm.

## Phạm vi đã kiểm

- 79 core tests và8 Nest tests gồm cả compatibility; user contracts không tenant, generic boundary không grant, policy/boundary/deny ngoài mọi record allow, user status/missing facts, Root không bypass, typed ReBAC và expiry.

- Product PostgreSQL kiểm login thực data/identity/authority/sync/bootstrap, function owners/search_path/PUBLIC EXECUTE, DDL/SET ROLE, code rows/ownership takeover, permanent marker, monotonic state, missing bootstrap capability, replication drift và missing authority session capability.
- Fresh product schema, fixture initial→protection, repeated provisioning/migrations, legacy schema refusal không xóa dữ liệu và version migration refusal không đoán tuple cũ. Bốn migration identity/tenant lịch sử khớp byte-for-byte snapshot trước thay đổi.
- System roles/grants: first/repeated/concurrent boot, catalog có trước Root, new permission không auto-grant, exact changed grant previousHash/removal expectedHash, drift cùng release và release mới, persisted omitted grant, noncanonical stable ID/effect, collision, race bootstrap, mandatory boundary và không reseed assignment bị offline revoke.
- Gateway/service: SQL/evaluator parity, bigint, values injection, projection, filter/count/detail/list, source type/version, domain validity, grant không vượt boundary, revoke boundary/session và write dùng action được đăng ký riêng; caller đưa `read` vào write bị từ chối, malformed Unicode không được lưu thành replacement characters.
- Local/OIDC: Argon2 profile, opaque hash-only sessions, reset single-use/race, stale password verification, linking/unlink/relink/last-method guard, provider/binding revoke race, OIDC activation bằng invitation token cho Root/user thường, idle/absolute expiry. Token fixture ký RSA thật, token/JWKS HTTP server, PKCE/nonce/state/issuer/audience/azp/signature/expiry thực sự qua openid-client. Hybrid user có cùng authorized rows và deny với local/OIDC session. Network routing tới fixture là test-only; production discovery/TLS chưa chạy.
- HTTP E2E: AppModule thật sync/readiness; CSRF; activation/login; owner-scoped list/detail và hidden/absent404; protected write; reset/logout revoke; Root không mặc nhiên đọc documents; fresh reauth, self/peer/boundary trên suspend; drift hoặc thiếu write privilege không mở listener. `/openapi.json`, no-store và secret-safe errors được kiểm.
- Offline CLI actual process: provision→migrate/no-op→sync/no-op→pending enrollment/local và OIDC invitation, reissue invitation (vô hiệu token cũ)→Root bootstrap/idempotency→`reissue-root` (Root pending; non-Root bị từ chối với `(ReleaseRejectedError collision)`)→`revoke-root` cần approval/reason; proof chỉ nằm file mới0600, không stdout.

## Mutation và concurrency

Năm mutations đã thực chạy, quan sát tests fail rồi restore nguồn/build:

| Mutation                              | Test bắt lỗi                               | Failure quan sát                                                   |
| ------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------ |
| Bỏ boundary conjunct                  | `packages/core/test/user-decision.spec.ts` | allow thay vì deny                                                 |
| Predicate true khi role `system.root` | Cùng user core tests                       | Root ngoài boundary hoặc thiếu grant vẫn allow                     |
| Shared runner không lấy fence         | Product DB shared/revoke test              | Revoke chạy trong lúc read còn giữ transaction: true thay vì false |
| Sync được takeover runtime ownership  | Product DB ownership test                  | Missing expected rejection                                         |
| Probe bỏ so body function bảo vệ      | Product DB protection drift test           | Missing expected rejection cho `protect_product_rows` no-op        |

Sau restore, full suites xanh. Đây là manual source mutations trong phiên, không phải một mutation job đã chạy trên GitHub. Scripts dùng tạm tại `/private/tmp/base-auth-transition-backup`; không có bypass flag trong runtime.

55P03 được sinh từ PostgreSQL lock contention thật, có bounded retries/timeout metrics. 40P01/40001 được fault-inject bằng TypeORM QueryFailedError vào product runner; transaction/effects vẫn dùng PostgreSQL thật, rollback hai lần rồi chỉ commit một effect. Không gọi hai trường hợp này là deadlock/serialization do DB tự phát sinh. Legacy conflict tests vẫn giữ nhưng không thay evidence cho runner mới.

## Tải và giới hạn

[Load results](single-product-load-results.md) lưu standalone dataset100,8workers,80operations, p95/p99 và metrics. Lượt full-suite cuối cùng trên cùng host chạy nhiều containers đồng thời: elapsed1341.72ms, p95 424.02ms, p99 737.07ms, timeout0%, failures0. Đây là fixture nhỏ có nhiễu, không HTTP benchmark hoặc production SLO; không dùng làm lý do chia fence.

## Gates chưa được chứng nhận

- Mapping/consolidation dữ liệu tenant/identity thật và restore/failover/durability.
- Production IdP discovery/TLS/assurance governance, IdP event revocation và secret rotation.
- Mail/recovery delivery provider/outbox durability; default endpoint trả503. Invitation local dùng artifact offline, không phải mail service.
- Root recovery/elevation approval authority độc lập và audit sink/retention thật; runbook có, chưa có automated recovery command hoặc diễn tập production.
- Generic administration role/grant/boundary/relation APIs, files/export/jobs chưa mở; không claim đã có các capabilities này.
- Production Argon2 calibration/blocklist corpus, pool sizing/load saturation và nhiều replicas.
- GitHub workflow đã cập nhật nhưng chưa thực chạy. Không có `.git` ở workspace nên không có Git diff/commit/branch handoff; không khởi tạo repo tự động.

Independent review đã kiểm DB/compiler/manifest và phát hiện các lỗi được regression/fix trong phiên. Ngày 2026-10-14 chạy thêm năm vòng review độc lập (subagent chỉ đọc) trên toàn bộ thay đổi chưa commit, vòng sau kiểm lại vòng trước. Vòng 5 (chỉ đọc code, không chạy reproducer) tìm thấy: probe chưa so body function/binding trigger, chưa chặn `session_replication_role`, authority kích hoạt được account pending; cả ba đã sửa kèm regression test (body no-op, trigger trỏ function khác/đổi sự kiện/cột/WHEN, trigger lạ, GRANT SET parameter, authority `→active/→pending`) và mutation bỏ phép so body làm test fail. Phát hiện audit thiếu operator được xử lý bằng tài liệu (operator nằm trong bản ghi approval tham chiếu). Không tuyên bố production-ready.
