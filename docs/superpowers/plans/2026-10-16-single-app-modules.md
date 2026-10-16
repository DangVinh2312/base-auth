# Single App Modules Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task in this session. Do not commit or push; the user requested a branch and working tree conversion only.

**Goal:** Một NestJS app tại `apps/api`, không còn bốn package nội bộ hoặc imports SDK giả lập.

**Architecture:** Di chuyển implementation vào module chức năng, dùng imports trực tiếp. Giữ behavior và capability facades hiện có; tách phần dùng chung khỏi tenant implementation để runtime không nạp legacy.

**Tech Stack:** NestJS, TypeORM, PostgreSQL 18.4 disposable, Node 24.20.0, pnpm 12.3.4, TypeScript ESM/NodeNext.

**Spec:** [Thiết kế](../specs/2026-10-16-single-app-modules-design.md).

## Global Constraints

- Không đổi schema/SQL/migration identifiers, policy, manifest hashes hoặc HTTP contracts.
- Không gộp credentials; không đưa offline credential/capability vào HTTP handlers.
- Không bỏ behavioral/security tests; legacy giữ để đối chiếu và tests.
- Không commit/push/deploy hoặc chạm database thật.

## Review Focus

- Runtime graph không kéo theo tenant implementation qua shared errors/validators.
- Root bypass chỉ ở authority service; HTTP handlers không import raw runner/driver.
- Migration identity và manifest hashes giữ nguyên qua imports mới.
- Test discovery vẫn chạy cả core, codecs, Nest, app và legacy tests.
- Dependencies khai báo trực tiếp ở app/root tests; frozen lockfile install hoạt động.

### Task 1: Chuyển source và consumers

- [x] Thêm `test/single-app.spec.ts`: app/root không còn dependency `workspace:*` vào package đã bỏ; runtime imports không nạp legacy; chạy thấy fail trước chuyển đổi.
- [x] Chuyển package source/tests vào app module và `test/{core,values,enforcement,legacy}`; cập nhật mọi caller, fixture, CLI và relative imports tới built output.
- [x] Tách shared transaction errors/DB connection types/release validation khỏi tenant implementation, giữ nội dung và thứ tự validation.
- [x] Bỏ package entrypoints/manifests/config, cập nhật app dependencies, root dependencies/scripts, TypeScript references, test discovery và pnpm lockfile bằng pnpm.

### Task 2: Ranh giới và tài liệu

- [x] Chuyển ESLint/package-boundary tests sang imports nội bộ; kiểm negative cases cho controller, runtime và Root bypass.
- [x] Cập nhật smoke/structure tests và quy định `AGENTS.md`, README, tài liệu vận hành/kiến trúc/reuse hiện hành; giữ ADR/plan lịch sử.
- [x] Kiểm diff source/migrations để phát hiện thay đổi hành vi ngoài imports hoặc phần shared code được di chuyển.

### Task 3: Kiểm chứng

- [x] Format có phạm vi; `pnpm run lint`, `pnpm run typecheck`, `pnpm run build`, `pnpm run test:unit`.
- [x] `pnpm install --frozen-lockfile`, PostgreSQL integration và HTTP E2E trên Docker disposable.
- [x] Review diff cuối, cập nhật ledger và bàn giao nhánh/chưa commit cùng giới hạn thực tế.

## Ledger

- Branch: `refactor/single-app-modules`; baseline working tree sạch.
- Baseline: `pnpm run test:unit` trong sandbox: 250/252 pass, 2 `listen EPERM`; chạy ngoài sandbox: 252/252 pass (log `/tmp/base-auth-baseline-unit.log`). Docker 29.8.2 truy cập được ngoài sandbox.
- Quyết định: giữ `apps/api` để giảm di chuyển phần HTTP hiện có; gom bốn package vào app. Yêu cầu thực hiện chuyển đổi tiếp nối phương án đã trao đổi là authorization để triển khai; không thêm vòng hỏi lại.

- Source: đã di chuyển 68 files (gồm shared validator), bỏ bốn package manifests/SDK entrypoints/project references; imports trực tiếp và test discovery mới. AST comparison của 66 file gốc: không thay non-import declarations sau khi tính phần shared được di chuyển và export modifiers. Migration bodies/identifiers giữ nguyên.
- RED: `node --test test/single-app.spec.ts` fail trước chuyển đổi ở internal package dependencies và runtime graph. Sau chuyển đổi cả hai pass. Module boundaries: thêm regression phát hiện specialized ESLint rules ghi đè common restrictions; sửa composition và core outward imports, 21/21 module tests pass. Review độc lập không còn actionable findings.
- Checks hiện tại: format có phạm vi pass; `git diff --check`, `pnpm run lint`, `pnpm run typecheck`, `pnpm run build` exit 0; unit cuối 252/252 pass, không skip. `pnpm install --frozen-lockfile` exit 0. Offline install đã thử nhưng thiếu cached tarball; frozen online install hoàn tất, không tắt supply-chain checks hoặc đổi dependency version.
- Lần integration đầu: 236/237 pass, CLI `purge-sessions` trả generic Error; E2E chạy đồng thời timeout chờ startup (0/1). Không đổi code/timeout/assertions để che lỗi. CLI chạy riêng sau đó 2/2 pass; đang chạy lại toàn bộ integration và E2E tuần tự. Các lần chạy fail không được gọi là pass.

- Lần integration thứ hai (không chạy đồng thời E2E/checks): 236/237 pass; CLI pass, `product-fence-io` lỗi Testcontainers `Timed out after 10000ms while waiting for container ports to be bound to the host` trong `startPostgres`, trước test body. Tiếp theo chạy E2E riêng và toàn bộ integration với một file mỗi lần; không thay timeout/assertions hoặc cấu hình mặc định trong repo.

- E2E chạy riêng cuối: `pnpm run test:e2e` exit 0, 1/1 pass, không skip (log `/tmp/base-auth-e2e-final.log`). Full integration serial dùng `pnpm exec node --test --test-timeout=300000 --test-concurrency=1 'test/**/*.integration-spec.ts'` trên app đã build; không sửa runner mặc định `--test-concurrency=3`.

- Full integration serial cuối: 237/237 pass, 12 suites, không skip/cancel (317629.65 ms; log `/tmp/base-auth-integration-serial.log`). Đây là lần chạy toàn bộ suite mới, không gộp nhóm rerun thành pass của lần mặc định bị lỗi. Concurrency bên trong các tests locks/transactions/worker giữ nguyên.
- Final boundary review: thêm regression RED→GREEN chặn import/re-export trực tiếp `planUnrestricted` (kể cả alias) ngoài core factory, authority service và core unit tests; thay thế hạn chế deep import trước đây của package exports. Không thay runtime source.

- Chốt quy ước AGENTS: gom transaction errors vào `database/helpers/`; metrics/readiness vào `health/services/`; bootstrap/audit legacy vào `legacy/services/`. Chỉ sửa imports/callers/docs. AST comparison mở rộng tới 93 file gốc (gồm app source), không có khác biệt non-import declarations sau khi tính shared extraction/export modifiers. Typecheck/lint/build và unit 252/252 pass sau bước này; E2E và năm integration files có callers bị ảnh hưởng được chạy lại riêng. Full serial 237/237 ở trên chạy trước bước gom năm đường dẫn cuối, không thay thế bằng nhóm rerun.

- Kiểm chứng sau năm path moves cuối: `pnpm run test:unit` 252/252 pass (log `/tmp/base-auth-unit-final-paths.log`); `pnpm run test:e2e` 1/1 pass (log `/tmp/base-auth-e2e-final-paths.log`); `pnpm exec node --test --test-timeout=300000 --test-concurrency=1 test/obligations.integration-spec.ts test/permission-boundary.integration-spec.ts test/product-identity.integration-spec.ts test/product-load.integration-spec.ts test/revocation.integration-spec.ts` 60/60 pass, không skip/cancel (log `/tmp/base-auth-affected-final-paths.log`). Các tests còn lại đã pass trong full serial run trước đó; không tuyên bố full suite mặc định concurrency 3 pass.
- Bàn giao: một app tại `apps/api`, branch `refactor/single-app-modules`, working tree chưa commit/push. Không đổi version dependency, SQL/migration identifiers, HTTP contracts hoặc quyền/dữ liệu; không chạm database thật hoặc xác nhận provider/production. Đã review độc lập các thay đổi cấu trúc và static boundaries; không còn actionable findings.

## Cleanup sau chuyển đổi (2026-10-16)

Phạm vi người dùng đã chọn: xóa code chết/phần dư, giữ legacy và migrations đang dùng. Không thay runtime behavior hoặc bỏ các tests legacy/security.

- [x] Rà source/callers/tests: barrel `authorization/core/index.ts` chỉ còn hai test consumers; `BoundaryRef` chỉ được barrel re-export, không có caller. Chuyển tests sang factory sở hữu, giữ kiểm tra pure imports/no default engine và instance/provenance behavior. Regression no-barrel đã chạy RED trước khi xóa.
- [x] Bỏ direct devDependency `testcontainers` ở root bằng `pnpm remove -w testcontainers`; `@testcontainers/postgresql@12.2.0` khai báo dependency đó và vẫn giữ phiên bản khóa. Không xóa provider PostgreSQL hoặc tests.
- [x] Kiểm tra bốn thư mục package cũ chỉ còn generated `dist`/`node_modules` và thư mục rỗng; dọn các artifacts đó. Xóa app `dist` chỉ chứa build output để cold build không dùng barrel/artifact cũ. Không xóa source legacy, migrations hoặc dữ liệu.
- [x] Cold build, typecheck/lint, unit và một PostgreSQL integration fixture sau dependency cleanup; format/diff cuối.

Cleanup verification: `pnpm run build` từ app `dist` đã xóa, `pnpm run typecheck`, `pnpm run lint` exit 0; `pnpm run test:unit` 252/252 pass (log `/tmp/base-auth-cleanup-unit.log`); `pnpm run test:integration -- test/product-genesis.integration-spec.ts` 2/2 pass trên PostgreSQL disposable (log `/tmp/base-auth-cleanup-postgres.log`), không skip/cancel. Scoped Prettier và `git diff --check` pass; review độc lập không có findings. Không chạy lại full integration/E2E cho cleanup này vì không đổi HTTP wiring, SQL hoặc runtime logic; fixture kiểm dependency PostgreSQL sau khi bỏ direct dependency dư. Không commit/push.

## Full integration/E2E và review độc lập sau cleanup (2026-10-16)

Theo yêu cầu chạy lại của người dùng, kiểm chứng trên branch `refactor/single-app-modules`, HEAD `e001313` cùng toàn bộ thay đổi chưa commit. Docker disposable; không chạy integration và E2E đồng thời, không sửa timeout/assertions hoặc runner mặc định.

- `pnpm run build`: exit 0 trước khi chạy integration.
- Full integration: `pnpm exec node --test --test-timeout=300000 --test-concurrency=1 'test/**/*.integration-spec.ts'`: exit 0, 237/237 pass, 12 suites, không skip/cancel/todo; 731236.695278 ms. Log `/tmp/base-auth-full-integration-review.log`. Chạy đủ 26 files với một file mỗi lần; concurrency bên trong tests giữ nguyên. Không xác nhận chế độ mặc định ba file đồng thời pass.
- Full E2E: `pnpm run test:e2e`: exit 1, 0/1 pass, 1 fail, không skip/cancel; 34217.531828 ms. Log `/tmp/base-auth-full-e2e-review.log`. Fail tại `apps/api/test/product.e2e-spec.ts:164`: `live?.status` là `undefined`, expected `200`, sau vòng chờ `/health/live`; chưa đến assertions nghiệp vụ.
- Chạy lại nguyên full E2E bằng cùng lệnh, không sửa code/config: exit 1, 0/1 pass, 1 fail, không skip/cancel; 190704.614791 ms. Log `/tmp/base-auth-full-e2e-review-rerun.log`. Cùng vị trí và assertion. Hai lượt fail vẫn được ghi nhận; không dùng E2E pass lịch sử thay kết quả hiện tại.
- Reviewer độc lập mới, chỉ đọc, kiểm toàn bộ conversion/cleanup so với HEAD, gồm source/tests chưa tracked: không có finding cụ thể do chuyển đổi. AST comparison độc lập giữ nguyên migration bodies/identifiers và các declarations được tách dùng chung; imports/callers/CLI/fixtures/discovery/dependencies/config được kiểm tra. Tám ESLint probes kiểm các ranh giới driver/runner, core, offline capability và unrestricted planner. Giới hạn computed-property của ESLint vẫn như đã ghi trong thiết kế.
- Review bổ sung failure E2E: vòng chờ `150 × 50ms`, launch/env, `main.ts` và xử lý startup không đổi so với HEAD. Test chỉ kèm child output khi child thoát sớm, không kèm khi vòng chờ health hết; log hiện tại chưa xác định startup kẹt ở phase nào. Chưa chứng minh nguyên nhân môi trường hoặc regression hiệu năng; E2E startup failure còn mở, không tuyên bố toàn bộ checks xanh.
- SHA-256 của 161 source/test/config files và HEAD khớp trước/sau cả hai nhóm tests; không có thay đổi đầu vào trong lúc chạy. Lượt này chỉ bổ sung ledger, không sửa source/tests, không đọc/sửa tài liệu HR, không commit/push. Unit/lint/typecheck không chạy lại trong lượt này; kết quả trước ở ledger phía trên. Không kiểm chứng provider thật hoặc production.

## Sửa chờ startup E2E (2026-10-16)

Người dùng yêu cầu sửa failure ở trên. Phạm vi: test harness, không sửa runtime, SQL, migration, auth hoặc timeout của suite.

- Chẩn đoán bằng preload probe tạm trong `/tmp`, chỉ in phase/timing: E2E không sửa chạy pass 1/1; lần đo startup đầu kết thúc bootstrap ở uptime khoảng 5 giây, trong đó import runtime khoảng 2,6 giây. Đây không xác định phase gây hai failure lịch sử. Tuy nhiên vòng chờ 150 probes có giới hạn riêng khoảng 7,5 giây dù suite cho phép 300 giây, nên có thể kết thúc trước khi một startup hợp lệ hoàn tất.
- RED có kiểm soát: thêm delay 8 giây vào preload của child, giữ nguyên E2E/runtime; tái hiện đúng assertion `undefined !== 200`, exit 1, 0/1 pass (log `/tmp/base-auth-e2e-slow-start-red.log`). Delay/probes không nằm trong source được bàn giao.
- `test/http-startup.helper.ts` chờ theo signal/deadline của test, hủy fetch hoặc retry delay ngay khi child exit/error hoặc test bị hủy; dọn listeners trong `finally`. Không thêm startup timeout hoặc tăng timeout 300 giây của runner. Trả ngay response HTTP kể cả 503 để assertion 200 của caller vẫn bắt lỗi. `stop()` trong E2E nhận biết child đã thoát bằng signal để không chờ lại một exit event đã xảy ra.
- Regression với child HTTP thật: helper dùng vòng chờ cũ fail sau 150 probes (log `/tmp/base-auth-http-startup-red.log`); sau sửa 5/5 pass (log `/tmp/base-auth-http-startup-green.log`). Các ca: hơn 150 probes thất bại rồi thành công, child bị SIGTERM khi fetch đang chờ, deadline hủy fetch đang chờ, HTTP 503 và child đã exit.
- Full unit đầu: 256/257 pass, 1 fail do child exit trong retry delay trả `AbortError` chung thay nguyên nhân SIGTERM (log `/tmp/base-auth-startup-unit.log`). Sửa helper giữ nguyên cancellation reason; không đổi assertion. Full unit mới `pnpm run test:unit`: exit 0, 257/257 pass, không skip/cancel (log `/tmp/base-auth-startup-unit-final.log`).
- Full E2E với cùng delay 8 giây đã gây RED: exit 0, 1/1 pass, không skip/cancel; 42732.296671 ms (log `/tmp/base-auth-e2e-slow-start-green.log`). Các assertions nghiệp vụ và boot fail closed sau drift/revoke privilege giữ nguyên và đều chạy.
- Full E2E thông thường, không preload/delay: `pnpm run test:e2e`: exit 0, 1/1 pass, không skip/cancel; 11138.040673 ms (log `/tmp/base-auth-e2e-startup-fixed.log`). Hai failure trước sửa vẫn được giữ trong ledger.
- `pnpm run typecheck` (gồm build) và `pnpm run lint` cuối: exit 0 (logs `/tmp/base-auth-startup-typecheck-final.log`, `/tmp/base-auth-startup-lint-final.log`). Lint lần đầu bắt IPC payload từ `once()` chưa được nhận/validate bằng `unknown`; đã sửa validation, không tắt rule.
- Review độc lập helper, regressions và E2E, gồm follow-up cancellation race: không còn findings. SHA-256 xác nhận chỉ ba test files thay đổi so với full integration 237/237 trước đó; 163 source/test/config files không đổi trong hai lượt E2E cuối. Không rerun full integration vì không sửa runtime/DB/config hoặc integration tests; không dùng các checks này chứng nhận provider thật/production. Không commit/push hoặc chạm tài liệu HR.
