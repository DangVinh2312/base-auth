> **Prompt lịch sử.** Phần Root/rank của prompt này đã bị ADR 0012 (`docs/decisions/0012-iam-root-separation.md`) thay thế; không thực thi lại.

# Triển khai kiến trúc một sản phẩm: local + IdP, authorization nghiêm ngặt

Bạn là Principal Engineer chịu trách nhiệm triển khai, không chỉ tư vấn hoặc viết kế hoạch.

## Dự án và phạm vi được giao

Dự án đích: `/Users/vinhdq2312/Documents/personal/base-auth-b2b`.
Prompt này được lưu tại `/Users/vinhdq2312/Documents/personal/base-auth/docs/prompt.md`; thư mục chứa prompt không phải đích scaffold một repo khác.

Tôi cho phép triển khai/refactor code, viết forward migrations, bổ sung tests và cập nhật config/tài liệu trong dự án đích để chuyển sang kiến trúc một sản phẩm. Chạy kiểm chứng bằng DB/IdP fixtures local dùng một lần; không chạm staging/production, không tự commit/push/deploy. Không xóa dữ liệu thật hoặc gộp dữ liệu nhiều tenant khi chưa có mapping/authorization cụ thể.

Hãy lập/cập nhật kế hoạch ngắn theo từng bước rồi bắt đầu thực hiện. Không dừng chỉ ở thiết kế hoặc hỏi lại những quyết định đã chốt dưới đây. Quyết định migration dữ liệu thật chưa đủ thông tin phải ghi rõ và chỉ chặn bước phụ thuộc; tiếp tục phần độc lập.

## Nguồn sự thật và tái sử dụng

Đọc root và nested AGENTS.md của module sẽ sửa, sau đó đọc:

1. `docs/authz-single-product-architecture.md`: kiến trúc đích, đặc biệt mục 4.5, 8.1, 9.1, 10.1–10.2 và 11.1.
2. `docs/decisions/0005-single-product-local-authentication.md` và `0006-single-product-local-and-idp.md`.
3. `docs/decisions/0007-system-roles-db-privileges-and-fence.md`: contract mới về Root/seed, DB roles và fence.
4. `docs/permission-boundaries.md`: giữ semantics nhưng chuyển membership/permission sang user/permission trong bản mới.
5. `docs/authz-architecture.md`, ADR 0001–0004 và kế hoạch cũ: nguồn thiết kế/code cần tái sử dụng, không phải ràng buộc duy trì multi-tenant ở kiến trúc đích.
6. README, package.json, code và tests hiện hữu trong packages/, apps/, test/, tools/.

Quyết định của tôi trong prompt này thay thế các quy định cũ bắt buộc tenant/IdP cho bản chuyển đổi. Cập nhật AGENTS và kế hoạch để phân biệt runtime hiện tại với mục tiêu mới; không xóa lịch sử ADR hoặc ghi tính năng dự kiến thành đã hoàn thành.

Dự án đã có code, không scaffold/copy cả repo. Tận dụng implementation có giá trị, kiểm tra thực tế trước khi viết lại. Đường dẫn base-authorization trước đây không còn tồn tại; không tạo lại repo đó. Không copy node_modules, dist, secrets hoặc cấu hình production.

## Quyết định đã chốt

- Một sản phẩm, một PostgreSQL database; không tenant giả, tenantId tùy chọn hoặc disableTenantChecks.
- NestJS + TypeORM + pnpm; giữ versions đã khóa nếu không có lý do tương thích cần đổi. Không npm/yarn/npx, không nâng dependency hàng loạt.
- Có thể giữ layout packages/apps để giảm diff; không cần gộp vào src/ chỉ vì sơ đồ kiến trúc gợi ý.
- Core thuần, không Nest/TypeORM/SQL. Tái sử dụng AST/planner/evaluator/compiler/key codec và test hữu ích.
- Hỗ trợ local password, OIDC hoặc cả hai; cùng user/session/authorization. Local-only không cần IdP; OIDC enabled thiếu config phải fail closed.
- Password Argon2id, opaque server-side session, cookie/CSRF, rate-limit và recovery theo spec. Không JWT quyền dùng độc lập khỏi authority hiện tại.
- RBAC/ReBAC/ABAC, policy, generic boundary, direct allow/deny và record exceptions đều được giữ.

```text
Allow = valid user/session
        AND hard invariants
        AND permission policy
        AND user permission boundary
        AND applicable grant
        AND NOT applicable deny
```

Boundary không tự grant, không chỉ là ApplicationRoleBoundary. Record allow không vượt policy/boundary/deny. List/detail/count/export/write cùng semantics; missing config/facts fail closed. Không tự nâng quyền, quản trị peer/superior hoặc chiếm account bằng quyền quản lý user.

## Phần bắt buộc bổ sung: system roles và Root

1. Seed permission catalog, system role `system.root` và grants qua manifest version/hash, transaction/fence/audit, trước readiness.
2. Root là application role code-owned, không phải PostgreSQL superuser; không `if root then allow`, không wildcard mọi quyền và không tự đọc mọi dữ liệu nhạy cảm.
3. Role definition, tập system grants và user-role assignment là ba loại dữ liệu/lifecycle khác nhau. Boot không tự tạo user hoặc gán lại Root.
4. Kiểm tra và tận dụng reconciler hiện có: `defaultGrants` chỉ chạy khi permission mới xuất hiện. Bổ sung `systemGrants` với stable owner/key để Root thêm muộn vẫn được cấp các permission cũ được manifest khai báo rõ.
5. System grants có exact permission/scope/version/params; explicit change/removal, không takeover runtime facts. Cùng release/hash phải kiểm drift đầy đủ và fail readiness khi lệch, không âm thầm phục hồi quyền.
6. Bảo vệ system role/grants bằng command validation và cơ chế DB bảo vệ code-owned rows. Metadata managed_by đơn lẻ không đủ. Chọn write functions/trigger hoặc cơ chế phù hợp nhỏ nhất, privilege-test bằng runtime credential.
7. Bootstrap Root một lần bằng command ngoài API với persistent marker, exclusive fence, target account định danh rõ, mandatory boundaries và audit. Hai bootstrap đồng thời không tạo hai Root. Marker không reset khi user bị suspend/xóa hoặc invite hết hạn.
8. Local activation không dùng password mặc định; OIDC activation cần đúng issuer/subject/proof, không auto-link email. Không seed secret trong manifest/log. Bootstrap credential không ở API process.
9. Root vẫn chịu policy/boundary/deny và self/peer invariants. Root recovery/elevation ngoài API có runbook, approval độc lập và audit.

## Phần bắt buộc: DB roles và application fence

- Một DB nhưng credential thực khác nhau cho data, identity, authority, sync và migration. Không nhiều tên DataSource trỏ cùng login toàn quyền.
- Tuân thủ ma trận mục 8.1; runtime không owner/superuser, không SET ROLE lên đặc quyền, không có migration/bootstrap secret.
- SECURITY DEFINER phải hẹp, owner NOLOGIN quyền tối thiểu, trusted search_path, schema-qualified objects, REVOKE EXECUTE PUBLIC; cấp cho đúng caller, kể cả identity login nếu cần shared fence. Không dynamic SQL/identifier từ request.
- Kiểm bằng DB thật: data không đọc credential hoặc ghi quyền; authority không phát session/sửa system rows; identity không grant role; sync không DDL/overwrite runtime data; không sửa ownership hoặc disable protection qua runtime.
- Giữ một application fence trước. READ COMMITTED, fence trước rồi load fresh authority/session ở statement sau; giữ cùng transaction tới effect/audit commit. Không nâng shared → exclusive giữa chừng.
- Giữ revoke semantics theo spec, deadline/retry/idempotency có giới hạn. Không network/hash/stream file khi giữ fence.
- Thêm metrics lock wait/hold theo mode, transaction duration, revoke commit latency, timeout/deadlock/retries, pool wait; labels hữu hạn, không PII/high-cardinality IDs.
- Load test mixed read/write/authority changes/slow transaction. Ghi dataset/concurrency/p95/p99 và timeout rate. Không tự phân vùng theo module/resource_type; chỉ đề xuất ADR nếu số đo chứng minh cần và đã xác định dependencies/lock ordering/revision.
- Không coi DB roles thay thế row-scope gateway hoặc chống được toàn bộ process bị compromise.

## Local và IdP cùng một luồng quyền

- OIDC Code Flow + PKCE S256, state/nonce một lần, validate signature/issuer/audience/azp/expiry, callback và provider allowlist.
- External identity UNIQUE(issuer, subject); không auto-link qua email hoặc auto-grant từ group claims.
- Link/unlink cần reauthentication và provider proof; không gỡ phương thức cuối, không biến OIDC-only thành local bằng forgot-password.
- IdP outage không tự mở local fallback. Assurance acr/amr được mapping theo issuer; OIDC không tự đồng nghĩa MFA.
- IdP exchange/password hashing ngoài fence, sau đó kiểm lại user/provider/binding/version trước tạo session để chặn race revoke/login.
- Local logout/revoke khác IdP logout/revoke; không hứa thu hồi IdP tức thời khi chưa tích hợp event. Thực hiện đúng absolute expiry/freshness đã chọn.
- Test local-only, OIDC-only, hybrid bằng IdP test fixture có signature/claims thật. Không coi mock boolean “OIDC OK” là kiểm chứng protocol. Không cần kết nối IdP production.

## Thứ tự thực hiện

P0. Kiểm kê code/test và lập reuse map; ghi trạng thái thật, giữ thay đổi của người dùng. Cập nhật kế hoạch chuyển đổi và AGENTS theo kiến trúc đích rồi triển khai tiếp.

P1. Schema/forward migrations một sản phẩm, user/authority mappings, credential matrix và application fence. Kiểm DB rỗng và nâng schema có fixtures; không sửa migrations đã áp dụng. Không tự gộp dữ liệu thật nhiều tenant.

P2. Chuyển core contracts/data gateway/boundary/sync sang user-based facts, giữ regression suite. Boundary có thể đã được bổ sung ở code nguồn: kiểm tra trước, không viết lại hoặc báo thiếu theo README cũ.

P3. System role/grant reconciliation, Root bootstrap marker và DB protection. Wire manifest/authority/fence/readiness vào AppModule thật. Lỗi sync/privilege/capability không mở business listener/worker; readiness flag riêng không đủ.

P4. Local/OIDC authenticators, application sessions, invitation/recovery/linking, shared authorization enforcement trên route và internal service. Root activation dùng đúng luồng xác minh; bootstrap CLI không biết password của người dùng.

P5. Administration APIs tối thiểu và một resource fixture chứng minh read/write/list/detail/deny/boundary; hoàn thiện audit và protected file/export/job path nếu thực sự triển khai chúng. Không tạo một domain demo lớn hoặc UI không được yêu cầu. Capability chưa có phải fail closed và được ghi rõ.

P6. E2E/revoke/concurrency/privilege/migration/load tests, CI config và tài liệu vận hành. Hoàn tất các bước có thể kiểm chứng local; báo rõ những gate staging chưa chạy. Không dừng ngay sau P0 với một bản kế hoạch.

Mỗi bước cập nhật callers, public exports, fixtures, config/env, scripts và docs liên quan; chỉ chuyển bước khi checks phù hợp đạt. Không đánh dấu bước hoàn thành dựa vào kết quả của kiến trúc cũ.

## Kiểm chứng bắt buộc

- pnpm frozen install; format, lint, typecheck, build; unit/integration/E2E theo scripts thực có.
- PostgreSQL thật với runtime credentials; node:test/output tsc hiện có được phép giữ.
- System roles: first boot, repeated/concurrent boot, Root thêm sau catalog, permission mới, collision/drift/removal, bootstrap race và không reseed assignment đã thu hồi.
- Core/gateway: grant không vượt boundary, boundary không grant, deny wins, missing facts deny, cùng SQL/evaluator, injection chỉ là value, collation khác C, không mất precision integer.
- API: login/activation → access → revoke/reset → deny; missing endpoint declaration fail CI/startup; manifest lỗi không phục vụ protected route.
- Concurrency: revoke role/deny/relation/session, bootstrap, reset token, OIDC linking; retry lỗi 55P03/40P01/40001 với scenario thực hoặc fault injection được ghi rõ, không claim test DB thật nếu chỉ mock.
- Mutation tests tối thiểu: bỏ boundary, bỏ fence, bypass Root, bật takeover runtime seed phải làm tests fail.
- Metrics/load results có số đo và điều kiện chạy, không tuyên bố hiệu năng/production-ready khi chưa có bằng chứng.
- GitHub workflow chưa thực chạy thì ghi chưa chạy; không đánh đồng local pass với CI pass.

## Tài liệu và báo cáo bàn giao

Cập nhật:

- `docs/single-product-reuse-map.md`.
- `docs/superpowers/plans/2026-10-13-single-product-transition.md` với trạng thái và bằng chứng từng bước.
- Architecture/ADR nếu cần làm rõ quyết định, README/AGENTS đúng runtime mới.
- Hướng dẫn local setup, migration, manifest sync, Root bootstrap/activation/recovery, DB roles và test commands thực chạy.

Chỉ thêm dependency cần thiết tại package sở hữu bằng pnpm, pin exact/lockfile; không thêm engine/library khi code hiện có đáp ứng. Không scripts giả, --if-present để che thiếu checks, hoặc tắt tests để đạt kết quả xanh.

Báo cáo cuối: phần đã triển khai và tái sử dụng, file chính, lệnh/kết quả thực chạy, khoảng trống cùng rủi ro và bước tiếp theo. Không claim hoàn tất nếu local/OIDC, system role protection, boundary, API wiring hoặc privilege checks trong phạm vi còn thiếu. Không commit/push/deploy.
