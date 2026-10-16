# Multi-package legacy cleanup plan

> Use `superpowers:subagent-driven-development` for independent core and PostgreSQL adapter tasks. Root integrates callers, Nest, fixtures, documentation and verification. Do not commit/push without current authorization; user has deferred push.

**Goal:** Dọn legacy/code thừa tương tự `version/single-app`, giữ topology multi-package.

**Spec:** [ADR 0013](../../decisions/0013-remove-legacy-keep-packages.md).

## Constraints

- Branch `version/multi-package`, baseline `e001313`; working tree sạch trước sửa. `version/single-app` ở `c7105c0` không đổi.
- Public package exports và `workspace:*` dependencies còn nguyên; core thuần; HTTP không raw credential/runner/offline capabilities.
- Không đổi product migration SQL/identifiers, hashes, auth/Root/fence/audit/precision semantics; không chạm secrets/HR docs/database thật.
- pnpm/Node 24, disposable PostgreSQL; serialize integration/E2E để tránh tranh tài nguyên.

## Tasks

- [x] Core: port User contracts và tests từ single-app vào package, bỏ tenant API/BoundaryRef, giữ root entrypoint và provenance/behavior tests.
- [x] PostgreSQL adapter: tách shared helpers, bỏ tenant source/migrations/legacy export; root safe exports không nạp legacy.
- [x] Nest/app/CLI: bỏ tenant bootstrap/readiness/audit, CLI/env dư; giữ facades và package boundaries.
- [x] Port SQL/collation/current product callers và E2E cancellation; giữ useful tests, bỏ suites riêng cho legacy.
- [x] Dọn dependency dư bằng pnpm, cập nhật current AGENTS/README/operations/architecture/reuse docs.
- [x] Cold build, frozen install, typecheck/lint/scoped format, full unit, full serial integration rồi full E2E.
- [x] Review độc lập, ghi ledger và bàn giao giới hạn thực tế.

## Ledger

- User hoãn push khi phát hiện repo không có remote. Không tự tạo remote hoặc push.
- Ruling: dùng source/behavior đã review ở single-app làm tham chiếu, điều chỉnh imports qua public package entrypoints; không cherry-pick commit chuyển topology.
- Cleanup giữ bốn package, public root/`composition`/`operations` entrypoints và dependencies `workspace:*`. Bỏ subpath `legacy`, tenant implementation/CLI/migrations và frozen release-one fixtures. Shared transaction errors, connection types và release validation còn dùng được tách trước khi xóa.
- Product migrations 001–012 và domain document migration không đổi so với baseline. Kiểm tra source/callers không còn tenant API, ngoài assertions xác nhận API đã bị gỡ và fixture từ chối schema tenant không tương thích.
- Chỉ bỏ direct devDependency `testcontainers` bằng `pnpm remove -w testcontainers`; dependency transitive của `@testcontainers/postgresql` vẫn giữ. Lockfile chỉ mất ba dòng ở root importer, không nâng version.
- Review độc lập đọc implementation/callers/tests, phát hiện reuse-map còn tên adapter cũ và thiếu coverage validation boundary seeds sau khi bỏ tenant suite. Đã sửa tài liệu và thêm test qua public `prepareProductRelease`: seed hợp lệ; reject version/permission/status/identity/owner sai và duplicate user+permission. Target suite pass 6/6; reviewer đọc lại xác nhận không còn finding.

### Verification — 2026-10-16

Node `v24.20.0`, pnpm `12.3.4`, PostgreSQL disposable `18.4` qua Docker. Các lệnh bên dưới exit 0; integration và E2E chạy tuần tự, không sửa timeout hoặc assertion để pass.

| Command/check                                                                                      | Kết quả                                                                    | Log local                                  |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------ |
| `pnpm install --frozen-lockfile`                                                                   | Lockfile up to date; 371 entries qua supply-chain verification             | `/tmp/base-auth-multi-install-final.log`   |
| `pnpm run build` sau khi dọn generated output                                                      | Cold build pass                                                            | `/tmp/base-auth-multi-cold-build.log`      |
| `pnpm run typecheck`                                                                               | Pass                                                                       | `/tmp/base-auth-multi-typecheck-final.log` |
| `pnpm run lint`                                                                                    | Pass                                                                       | `/tmp/base-auth-multi-lint-final.log`      |
| Scoped Prettier check và `git diff --check`                                                        | Pass trên files thay đổi/còn tồn tại, không format toàn repo               | Terminal output                            |
| `pnpm run test:unit`                                                                               | 241/241 pass, 13 suites; 0 fail/cancel/skip/todo                           | `/tmp/base-auth-multi-unit-final.log`      |
| `pnpm exec node --test --test-timeout=300000 --test-concurrency=1 'test/**/*.integration-spec.ts'` | Đủ 18 files; 142/142 pass, 2 suites; 0 fail/cancel/skip/todo; 260935.56 ms | `/tmp/base-auth-multi-integration.log`     |
| `pnpm run test:e2e`                                                                                | 1/1 pass; 0 fail/cancel/skip/todo; 20097.10 ms                             | `/tmp/base-auth-multi-e2e.log`             |

- Unit run đầu pass 240/240; sau khi bổ sung boundary seed coverage đã chạy lại toàn bộ và pass 241/241 như bảng. Một lần `pnpm exec prettier` ban đầu kích hoạt dependency restore khi workspace links chưa sẵn sàng, gặp lỗi DNS và bị dừng (exit 130); frozen install và format/check cuối sau đó pass. Không coi lần lỗi môi trường đó là pass.
- Scoped format check sau khi bổ sung ledger báo một file Markdown chưa đúng format (exit 1); đã format lại file đó và kiểm tra cuối pass. Không có thay đổi runtime.
- SHA-256 của 142 source/test/config files khớp snapshot trước full integration; không đổi code giữa các checks cuối. Chỉ ledger tài liệu được cập nhật sau E2E.
- Branch refs vẫn là `version/multi-package` tại `e001313` và `version/single-app` tại `c7105c0`; cleanup nằm trong working tree, chưa commit/push.
- Giới hạn: chưa kiểm chứng full integration với concurrency mặc định 3 files; run đầy đủ ở trên dùng 1 file/lần để tránh tranh tài nguyên Docker. Test local/disposable và OIDC fixtures không chứng nhận provider thật hoặc production.
