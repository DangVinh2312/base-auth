# Bằng chứng kiểm chứng một sản phẩm

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
