# Vận hành local và các gate triển khai

Runtime mới: [architecture](authz-single-product-architecture.md), [ADR0008](decisions/0008-single-product-runtime-transition.md). Chỉ dùng disposable/local database cho các lệnh thử. Không dùng credentials staging/production để kiểm chứng.

## 1. Setup local

Node theo `.nvmrc`, pnpm theo `package.json#packageManager`. Cài đúng lockfile:

```sh
pnpm install --frozen-lockfile
cp .env.ops.example .env.ops
cp .env.example .env.api
```

Tạo password ngẫu nhiên riêng cho sáu mục đích; không đưa vào CLI arguments, source hoặc chat. Điền `.env.ops` và URLs tương ứng trong `.env.api`. API chỉ nhận data/identity/authority/sync; không source `.env.ops` vào shell chạy API. Config chủ động từ chối migration/bootstrap/admin URLs trong process API. File mẫu không chứa credentials thật.

Thêm `POSTGRES_ADMIN_USER`, `POSTGRES_ADMIN_PASSWORD`, `POSTGRES_PORT` vào `.env.ops` để Compose local đọc; `DATABASE_ADMIN_URL` phải trỏ cùng PostgreSQL. Chạy:

```sh
docker compose --env-file .env.ops up -d postgres
pnpm run db:provision
pnpm run db:migrate
pnpm run manifest:sync
```

`db:provision` tạo một database theo `PRODUCT_DATABASE_NAME`, các login `product_data/identity/authority/sync/migration/bootstrap` và NOLOGIN function owners. Runtime không owner/superuser/CREATE ROLE/SET ROLE lên owner. `db:migrate` dùng migration login riêng và áp cả migration application document fixture. Boot không chạy migrations. Provision/migrate/sync lặp trên fixture đã được kiểm; passwords của role đã tồn tại không bị tự xoay bằng provision.

Database đã có `tenant_anchor` hoặc `identity_record` bị từ chối thay vì gộp dữ liệu. Dừng phần chuyển dữ liệu thật cho tới khi có mapping user/identity/authority, collision review, backup/restore và authorization cụ thể. Không xóa bảng tenant để vượt gate. Product migration nâng version identity edges cũng từ chối tuple cũ chưa có version thay vì đoán.

## 2. Root bootstrap và activation

Boot chỉ tạo definition/grants; không tự tạo hoặc gán Root. Cần một pending target rõ ràng. Local:

```sh
pnpm run identity:enroll -- --user <canonical-uuid> --method local --email <verified-delivery-address>
pnpm run root:bootstrap -- --user <same-uuid> --operation <operation-uuid> --method local --activation-file /private/tmp/root-activation-proof
```

Local token chỉ ghi vào file mới mode0600 sau commit, không stdout/audit; file tồn tại khiến command từ chối trước mutation. Operator phải chuyển proof bằng kênh đã xác minh, không gửi vào log/chat. Proof15phút, dùng một lần tại `POST /auth/activate` với password tự chọn, không mật khẩu mặc định. Sau khi dùng, xóa artifact proof theo quy trình secret handling. Nếu crash sau DB commit trước khi artifact được ghi, marker vẫn initialized; dùng quy trình recovery, không reset marker hoặc chạy với operation khác để reseed.

Lấy CSRF cookie/token bằng `GET /auth/csrf`. Mọi POST/PATCH có `Origin` đúng `APP_ORIGIN` và header `x-csrf-token` bằng cookie. Local HTTP dùng cookie `authz_*`; HTTPS dùng `__Host-authz_*`, Secure, Path=/, session/browser HttpOnly, SameSite=Lax. API giả định same-site, không bật CORS/trust-proxy tùy tiện.

OIDC:

```sh
pnpm run identity:enroll -- --user <uuid> --method oidc --issuer <exact-issuer> --subject <exact-subject>
pnpm run root:bootstrap -- --user <same-uuid> --operation <uuid> --method oidc --issuer <exact-issuer> --subject <exact-subject>
```

Provider phải nằm trong cấu hình deploy tin cậy và enabled ở DB. Dùng `POST /auth/oidc/activate`, theo authorization URL và callback. Chỉ exact issuer/subject đã prebind với marker pending còn15phút được activate; email/groups không link/grant. Không seed client secret hoặc password trong manifest. Marker giữ nguyên sau token hết hạn, suspend hoặc revoke assignment. Repeated bootstrap cùng operation trả trạng thái cũ, không cấp lại assignment.

Root chỉ có exact grant `account.suspend` trong manifest hiện tại, kèm `rootAccounts@1` boundary. Login chưa đủ cho thao tác nhạy cảm: gọi `POST /auth/reauthenticate` hoặc flow OIDC reauth. Self/peer/superior vẫn bị chặn. Root không mặc nhiên đọc documents.

## 3. Local/OIDC, session và recovery

- `AUTH_METHODS=local` không cần IdP. `oidc`/`local,oidc` yêu cầu `OIDC_PROVIDERS_JSON` hợp lệ, issuer và callback HTTPS cố định; fail discovery/config không mở listener và không fallback sang local.
- OIDC Code+PKCE S256, state/nonce một lần và signature/issuer/audience/azp/expiry được kiểm bằng openid-client. Assurance mapping theo issuer; baseline OIDC không tự là MFA. Linking/unlinking cần reauth/provider proof, không gỡ phương thức cuối.
- Session DB chỉ lưu digest, absolute12giờ/idle30phút. Data-only requests không touch activity; `/auth/session` và identity operations touch idle. Đây là giới hạn sớm bảo thủ, không kéo dài absolute expiry.
- Local logout/revoke khác IdP logout/revoke. Chưa có IdP event integration; revoke tại IdP có thể còn session ứng dụng tới absolute expiry. Provider/binding/user revoke ở DB dùng exclusive fence và version/epoch nên quyết định sau commit bị chặn.
- Password Argon2id19MiB/t2/p1,15–128 code points, preserved spaces, input bounds/Unicode validation, blocklist và tối đa4 hashes/verify đồng thời. Profile này cần calibration hardware và blocklist feed thật trước production; danh sách cục bộ nhỏ không thay compromised-password corpus.
- Recovery service dùng token một lần, credential version, epoch và revoke sessions; OIDC-only không được reset thành local. API default chưa có mail/delivery provider và trả503 cho recovery request. Có `RecoveryDelivery` port cho deployment/test; lựa chọn delivery, durability/outbox và secrets là gate riêng. Không trả token reset qua HTTP.
- CLI enroll tạo pending account, không phát password/session. Local invitation offline dùng `pnpm run identity:invite -- --user <uuid> --method local --email <delivery-address> --activation-file /private/tmp/invitation-proof`; proof mới mode0600 sau commit, người nhận tự activate. HTTP invitation và mail delivery chưa cấu hình; không dùng fixture credential để vận hành sản phẩm thật.

## 4. Root recovery/elevation ngoài API

Chưa có automatic recovery/elevation CLI. Không dùng `root:bootstrap` lần hai hoặc reset marker. Runbook bắt buộc:

1. Mở sự cố có operation ID, reason, target UUID/method và exact boundary/grant refs. Kiểm identity target qua kênh độc lập; không dựa vào email match hoặc password do admin tự đặt.
2. Một người có thẩm quyền khác operator phê duyệt bằng hệ thống approval độc lập; lưu approval ID/hash và thời hạn. Operator không được tự phê duyệt. Production phải chốt hệ thống approval/key pinning trước khi tạo command tự động.
3. Dừng mọi thao tác identity nhạy cảm liên quan target; dùng capability offline ngắn hạn, không inject vào API. Người phụ trách identity xử lý activation/recovery bằng proof thật; không tạo session impersonation.
4. Offline authorization operation lấy exclusive application fence; đọc manifest/system grants còn đúng hash, kiểm target và boundary exact. Chỉ thay assignment/bindings đã được duyệt; ghi actor/operator, approver reference/hash, reason, target, revision và audit event cùng transaction; tăng revision rồi commit. Không đổi marker hoặc definitions để vượt checks. Nếu cần sửa drift/ownership, đó là migration/repair riêng được duyệt, không disable trigger bằng runtime.
5. Kiểm quyền target thực tế và các deny/boundary sau commit, thu hồi capability offline và xác nhận audit ra sink độc lập. Revoke Root cũ cũng cần approval rõ ràng; không coi count(root)=0 là lý do tự cấp mới.

Các bước này là gate vận hành, không là bằng chứng đã diễn tập production. Chưa cung cấp approval authority/audit sink thật; không chạy sửa dữ liệu thật trong phiên này.

## 5. Manifest, privileges, rollback và metrics

`manifest:sync`/boot dùng cùng release đã validate/freeze, monotonic sequence/hash và expected predecessor. `defaultGrants` chỉ cho permission mới; `systemGrants` dùng stable owner/key cho cả permission đã có. Thay content cần `previousHash`, removal cần `expectedHash`; omission không revoke. Sync không ghi runtime grants/tuples/bindings/assignments.

Same release kiểm toàn bộ materialized code facts. Drift chặn cả release mới; khôi phục về trạng thái được duyệt bằng repair offline có audit/approval, rồi publish release sửa chữa tường minh. Không phục hồi user assignment khi boot. Không rollback bằng binary cũ/manifest thấp sequence hoặc snapshot quyền cũ; giữ credential/revoke state, dùng forward release/migration. Backup restore/durability/failover chưa diễn tập; không promote primary thiếu acknowledged revoke watermark.

`/health/metrics` chứa histograms hữu hạn theo metric/mode: pool wait, lock wait/hold, transaction, revoke commit, retry/timeout/deadlock. Không user/record IDs hoặc SQL binds. [Load results](single-product-load-results.md) là fixture nhỏ, không production SLO; không phân vùng fence từ số đo này. Data role không có row scope tự động ở DB: mọi truy vấn nghiệp vụ vẫn qua authorization service/gateway. DB roles không chống toàn bộ process compromise.

## 6. Tests và capabilities chưa mở

```sh
pnpm run format:check
pnpm run lint
pnpm run typecheck
pnpm run build
pnpm run test:unit
pnpm run test:integration
pnpm run test:e2e
```

Docker local chạy PostgreSQL18.4 disposable. OIDC fixture có RSA signatures, token/JWKS HTTP server và actual protocol library checks; routing network tới fixture là test-only, không kiểm production TLS/discovery. SQL/evaluator parity, bigint/collation, boundaries, deny, privilege, migrations, bootstrap/reset/link/revoke concurrency được kiểm trong suites. 55P03 có contention thật; 40P01/40001 được fault-inject trực tiếp vào product runner với rollback/effects PostgreSQL thật; không gọi chúng là deadlock/serialization do DB tự phát sinh.

Chưa mở generic role/grant/boundary/relation administration, file/export/job, public signup, UI, IdP backchannel logout hoặc cache allow. Route không khai báo bị startup/CI tests từ chối; capability chưa có không được quảng cáo đã hoạt động. Workflow có các lệnh thực, chưa chạy trên GitHub trong phiên này. Không commit/push/deploy.
