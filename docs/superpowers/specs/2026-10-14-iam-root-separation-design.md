# IAM thuần và Root tách khỏi IAM — Design spec

Ngày: 2026-10-14. Trạng thái: bản thiết kế sửa lần 9, sau bảy vòng review tĩnh độc lập; chưa có implementation.

## 1. Mục tiêu và phạm vi

**Mục tiêu:** đơn giản hóa mô hình phân quyền theo kiểu IAM của AWS.

- Bỏ mọi khái niệm rank ở product: `authorityLevel`, `authority_level`, view `account_rank`.
- Bảo vệ giữa các IAM principal chỉ còn bằng grant, deny policy và permission boundary.
- Root là **một loại account riêng nằm ngoài IAM**, tương đương super admin, giống AWS root user so với IAM user. Root không có role, grant, boundary, record exception hay direct rule, và **bypass mọi kiểm tra phân quyền** trên mọi resource/action đã khai báo.

Bối cảnh của quyết định: đây là auth cho **một sản phẩm duy nhất**, triển khai cho một doanh nghiệp, công ty, nhóm hoặc đội cố định (bán hàng, quảng cáo, nhà hàng), không phải SaaS hay multi-tenant. Root là super admin của chính tổ chức đó và có toàn quyền quyết định. Phân quyền chi tiết kiểu AWS (giới hạn cả root) chỉ cần thiết cho SaaS, nằm ngoài phạm vi.

**Trong phạm vi:**

- Data model và DB protection.
- Migration chuyển đổi, gồm cả hash materialized.
- Release/manifest product và quy tắc genesis.
- Điểm rẽ nhánh trong `access`, fresh-auth ghi của Root, audit Root.
- `account.suspend` và CLI Root.
- Tài liệu, bất biến và test fixtures liên quan.

**Ngoài phạm vi:**

- API quản trị IAM lúc runtime (gán/gỡ role, gắn boundary, thuộc tính account kiểu tag/path): spec riêng.
- **MFA bắt buộc cho mọi account** (TOTP/WebAuthn local, enrollment, mã khôi phục, lưu secret): spec riêng thứ hai, triển khai sau spec này.
- Đường legacy tenant: `manifest-reconciler.ts` (phần rank legacy), migrations `tenant/`, `tenant.entity.ts`, `test/manifest-sync.integration-spec.ts`, `test/permission-boundary.integration-spec.ts`. Contract và hash legacy giữ nguyên byte-for-byte.
- Hệ thống projection theo action, framework migration tổng quát, framework khóa mới.
- Hành vi mới "bỏ khỏi declarations thì tự xóa definition" trong reconciler.

**Điều kiện tiên quyết:**

- Phase B (T8–T10 của `docs/superpowers/plans/2026-10-14-foundation-hardening-and-adapters.md`) **đã commit** (`d1d78cd`, `789d7ab`, `2947dbd`). Phase B đã dùng migration product `009`–`011` và ADR `0010`/`0011`.
- Spec này dùng **số kế tiếp thực tế lúc triển khai**: hiện là migration `012`, ADR `0012`. Implementation plan đọc lại schema và ma trận quyền tại HEAD lúc viết plan.

## 2. Quyết định đã chốt với người dùng

| Câu hỏi                             | Quyết định                                                                                                                                     |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Rank                                | Bỏ hoàn toàn ở product; bảo vệ bằng boundary + deny                                                                                            |
| Root có bị policy/boundary giới hạn | Không. Root là super admin, bypass mọi kiểm tra phân quyền (grant/deny/boundary/policy) trên mọi action đã khai báo, kể cả action thêm sau này |
| Biểu diễn Root                      | `app_user.kind` ∈ {`root`, `iam`}, dùng chung login/session/OIDC/recovery                                                                      |
| Tạo pending Root                    | `identity:enroll` tạo account pending như nay; `bootstrap` chuyển `kind` từ `iam` sang `root` đúng một lần (mục 3.3, 3.5)                      |
| Marker initialized nhưng 0 holder   | Không có Root sau nâng cấp, không cho bootstrap mới; cần repair offline có duyệt (ADR 0008)                                                    |
| Fresh-auth cho Root                 | Chỉ thao tác ghi nghiệp vụ/quản trị qua `access` (mode `write`/`admin`); không áp cho identity operations                                      |
| Audit Root                          | Mọi lần Root đi qua `access` mà transaction commit, kể cả đọc rỗng và ghi không trúng; denied không audit                                      |
| API quản trị IAM                    | Chưa làm; role/grant vẫn khai báo trong manifest                                                                                               |
| MFA cho mọi account                 | Có, nhưng là spec riêng                                                                                                                        |

## 3. Root identity và bảo vệ tầng DB

### 3.1 Schema đích

- `app_user.kind text NOT NULL DEFAULT 'iam' CHECK (kind IN ('root','iam'))`.
- Partial unique index `ON app_user ((true)) WHERE kind = 'root'`: tối đa một Root.
- Không còn `app_user.authority_level`, `role_definition.authority_level` và view `account_rank`.
- View `iam_account` (`security_invoker = true`) gồm `id`, `state` của `app_user WHERE kind = 'iam'`.
- Function `resolve_session(bytea)` trả `kind` và không còn trả `authority_level`.

Marker `security_bootstrap_state` giữ nguyên schema: `operation_id`, `target_user_id` và `initialized_at` được đặt cùng lúc khi bootstrap (CHECK của 001). Vì vậy "marker initialized" nghĩa là đã từng bootstrap, và `target_user_id` là Root (hiện tại hoặc đã bị revoke).

### 3.2 Guard Root (mới)

Mọi guard Root mới có các tính chất sau:

- `SECURITY DEFINER`, owner **`product_session_owner`** (NOLOGIN NOINHERIT, đã sở hữu `resolve_session`), `search_path = pg_catalog, pg_temp`, không EXECUTE PUBLIC.
- Nhận diện caller bằng `session_user`, không dùng `current_user`. Các login product kết nối trực tiếp bằng DataSource riêng, không dùng `SET ROLE`.
- PL/pgSQL `VOLATILE` (mặc định), để mỗi câu SQL bên trong lấy snapshot mới ở READ COMMITTED. Dùng `NEW` cho giá trị đang đổi, câu SQL riêng cho facts đã commit.
- Thân hàm export làm hằng số cho probe.

1. **`guard_root_kind`** (BEFORE INSERT OR UPDATE OF `kind` ON `app_user`):
   - INSERT với `kind = 'root'` bị từ chối với mọi login.
   - Chuyển `iam → root` chỉ khi đủ mọi điều kiện:
     - `session_user = 'product_bootstrap'`;
     - `current_setting('transaction_isolation') = 'read committed'` (mục 3.3);
     - target `state = 'pending'`;
     - marker chưa initialized;
     - chưa có Root;
     - target không có dòng nào trong `user_role`, `user_boundary`, `policy_rule` (theo `user_id`), `record_exception` (theo subject `user_id`; `issued_by` không tính);
     - target không có activation token còn hạn, định nghĩa giống 008: purpose `activation`/`oidc-activation`, `consumed_at IS NULL AND expires_at > statement_timestamp()`.
   - Mọi thay đổi `kind` khác bị từ chối, kể cả `root → iam`.

2. **`require_root_marker_kind`** (CONSTRAINT TRIGGER, DEFERRABLE INITIALLY DEFERRED, AFTER UPDATE OF `kind` ON `app_user`): việc chuyển sang Root chỉ commit được khi cùng transaction đã đặt marker với `target_user_id` đúng user đó.

3. **`guard_root_not_iam_subject`** (BEFORE INSERT OR UPDATE ON `user_role`, `user_boundary`, `policy_rule`, `record_exception`): từ chối khi subject mới là Root, với mọi login kể cả `product_sync` và `product_authority`. Điều này bao gồm cả việc đổi subject của một dòng có sẵn sang Root. Với `policy_rule` chỉ xét `user_id` khác NULL; với `record_exception` chỉ xét `user_id`, không xét `issued_by`.

4. **`guard_root_activation`** (BEFORE INSERT ON `one_time_token`, thay phần `one_time_token` của 008): token `activation`/`oidc-activation` cho user `kind = 'root'` chỉ do `session_user = 'product_bootstrap'` cấp.

5. **`guard_root_lifecycle`** (BEFORE UPDATE OF `state`, `auth_epoch` ON `app_user`):
   Guard xét `OLD.kind`:
   - `OLD.kind = 'iam'`: `product_bootstrap` không được sửa. Các login khác do `protect_account_lifecycle` (004) quyết định như nay.
   - `OLD.kind = 'root'`:
     - `product_bootstrap` chỉ được chuyển sang `suspended` và tăng `auth_epoch` (revoke).
     - `product_identity` giữ đúng các chuyển đổi mà 004 đang cho phép (kích hoạt `pending → active`, tăng `auth_epoch` của luồng identity), để Root vẫn kích hoạt, đổi mật khẩu và logout-all được.
     - `product_authority` và mọi login khác bị từ chối. Đường app không bao giờ nhắm vào Root (`suspendUser` đi qua `iam_account`); chặn ở DB loại bỏ rủi ro DoS Root khi credential authority bị lộ.
     - Không login runtime nào đưa Root ra khỏi `suspended`. Gỡ suspend là repair offline (mục 4.6).

**ACL đích của `product_session_owner`** = ACL mà migration 002 và 008 đã cấp cho owner này (002:37, 46–48, 50, 61; 008:47–48), với các thay đổi sau. Danh sách này là delta trên tập đó, không thay thế nó.

- **Bỏ:**
  - SELECT(`authority_level`) trên `app_user`;
  - SELECT(`role_key`) trên `user_role`, vì guard 008 bị drop.
- **Thêm** (để guard chạy được bất kể caller, ví dụ `product_sync` không có SELECT `app_user`):
  - SELECT(`kind`) trên `app_user`. Các cột `id`, `state`, `auth_epoch`, `email_verified` đã có.
  - UPDATE(`kind`) trên `app_user`. PostgreSQL yêu cầu quyền UPDATE trên ít nhất một cột cho `SELECT … FOR SHARE`, và với SECURITY DEFINER quyền được kiểm theo owner. Owner NOLOGIN không chạy UPDATE nào; mẫu này giống `UPDATE(singleton)` của `product_fence_owner` trên `authz_state` (002). Kể cả khi owner UPDATE `kind`, `guard_root_kind` vẫn từ chối vì caller không phải `product_bootstrap`.
  - SELECT trên `security_bootstrap_state`.
  - SELECT(`user_id`) trên `user_boundary`, `policy_rule`, `record_exception`. SELECT(`user_id`) trên `user_role` đã có từ 008.
  - SELECT(`user_id`, `purpose`, `expires_at`, `consumed_at`) trên `one_time_token` đã có từ 008; giữ nguyên.

Probe tại HEAD **chưa có** tập ACL kỳ vọng cho `product_session_owner` (chỉ kiểm thuộc tính function). Implementation plan dựng tập kỳ vọng này **mới, từ đầu**: bản kê theo từng cột, lấy từ các GRANT của 002/008 rồi áp delta trên. Probe owner-hardening kiểm toàn bộ tập đó là chính xác, không thừa.

**Guard 004 giữ nguyên chế độ bảo mật và cách nhận diện caller** (`current_user = 'product_sync'` cho code-owned facts). Thay thân hàm để bỏ **toàn bộ khối** `IF TG_TABLE_NAME='user_role'` (nhánh bootstrap enroll/revoke Root và nhánh tiền tố `system.`), vì bootstrap mất quyền trên `user_role` và role `system.*` không còn. Mọi nhánh khác giữ ngữ nghĩa.

### 3.3 Chống thao tác đồng thời

Protocol nhỏ nhất đủ cho bất biến "Root không có IAM facts hay token trái phép":

- **Promotion:** bootstrap khóa dòng target trước khi kiểm, bằng `SELECT … FROM app_user WHERE id = $1 FOR NO KEY UPDATE`, sau đó mới `UPDATE kind`. `guard_root_kind` chạy các kiểm tra `EXISTS` trong statement riêng (READ COMMITTED lấy snapshot mới), sau khi đã giữ khóa.
- **Gắn fact hoặc token:** `guard_root_not_iam_subject` và `guard_root_activation` đọc `kind` của subject bằng `SELECT kind FROM app_user WHERE id = NEW.<subject> FOR SHARE`.
- `guard_root_activation` chỉ khóa (`FOR SHARE`) khi purpose là `activation`/`oidc-activation`; các purpose khác không khóa.
- `FOR SHARE` xung đột với `FOR NO KEY UPDATE`:
  - Nếu promotion đang chạy, transaction gắn fact chờ tới khi promotion commit, rồi đọc lại `kind = 'root'` và bị từ chối.
  - Nếu transaction gắn fact giữ khóa trước, promotion chờ, rồi `EXISTS` thấy fact đã commit và bị từ chối.
  - FK `FOR KEY SHARE` không đủ cho việc này, nên khóa tường minh là bắt buộc.
- **Isolation:** lập luận trên chỉ đúng ở READ COMMITTED. Ở REPEATABLE READ, promotion có thể giữ snapshot cũ và không thấy fact vừa commit, vì hàng target chỉ bị khóa chứ không bị cập nhật. Vì vậy `guard_root_kind` từ chối promotion khi isolation khác `read committed`.
  - Phía gắn fact không cần ràng buộc: ở REPEATABLE READ/SERIALIZABLE, `FOR SHARE` trên hàng đã bị promotion cập nhật và commit sẽ gây serialization failure, tức fail closed.
  - Runner vẫn dùng READ COMMITTED như nay.
  - Với ràng buộc này, protocol bảo vệ cả SQL chạy bằng credential thật ngoài runner.
- **Phạm vi lock ordering:** cam kết chỉ cho cặp promotion và gắn fact/token: cả hai khóa dòng `app_user` của subject trước khi kiểm hoặc ghi.
  - `bootstrap` và `reissue-root` (đường CLI được sửa trong spec này) khóa target `app_user` trước mọi thao tác token.
  - `issueActivation` của identity vẫn UPDATE token cũ trước khi INSERT token mới; guard chỉ khóa `app_user` lúc INSERT. Nếu chạy đồng thời với SQL ngoài runner giữ khóa theo thứ tự ngược lại, PostgreSQL có thể abort một transaction vì deadlock. Kết quả là fail closed, không tạo bypass; runner retry `40P01` có giới hạn như nay.
  - Spec không cam kết thứ tự khóa toàn cục cho mọi đường.
- Application fence của runner vẫn giữ như nay.

### 3.4 Ma trận quyền DB (thay đổi so với hiện trạng)

| Login/role                         | Thêm                                                                                              | Bỏ                                                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `product_bootstrap`                | `UPDATE(kind, state, auth_epoch)` và `SELECT(kind)` trên `app_user`, giới hạn bởi guard           | REVOKE hoàn toàn INSERT/DELETE trên `user_role` và INSERT trên `user_boundary`; SELECT `authority_level` |
| `product_session_owner`            | Delta ở mục 3.2                                                                                   | SELECT `authority_level`; SELECT(`role_key`) trên `user_role`                                            |
| `product_authority`                | SELECT trên `iam_account`; SELECT(`kind`) trên `app_user` (giữ các cột đang có, gồm `auth_epoch`) | SELECT `account_rank`; SELECT/UPDATE `authority_level`                                                   |
| `product_data`, `product_identity` | —                                                                                                 | SELECT `authority_level` nếu đang có                                                                     |
| Login của phase B (outbox…)        | —                                                                                                 | — (quyền chỉ trên `audit_outbox`, ADR 0011)                                                              |

Bảng chỉ ghi delta; các quyền khác của mỗi login giữ nguyên. Migration/owner login có quyền DDL nằm ngoài API và không phải runtime login; probe vẫn coi quyền DDL của runtime login là unsafe.

### 3.5 CLI offline (`tools/product.ts`, `product-manifest.ts`)

- `identity:enroll` / `identity:invite`: không đổi; tạo account `kind = 'iam'` pending với email/OIDC binding như nay.
- `bootstrap --user <pending id>`:
  - kiểm drift như nay;
  - trong một transaction: khóa target (mục 3.3), chuyển `kind` sang `root`, đặt marker, cấp activation proof.

  Không nhận và không hardcode boundary (xóa `account.suspend -> rootAccounts@1`). Không kiểm `systemGrants` hay role `system.root` trong release.

- `reissue-root`: giữ ngữ nghĩa; target là Root còn pending và đúng marker.
- `revoke-root`:
  - suspend Root (`state = 'suspended'`, `auth_epoch` tăng 1);
  - vẫn cần `--approval`/`--reason`; marker giữ nguyên, nên không bootstrap lại được;
  - gỡ suspend là repair offline có duyệt.
- Audit `root.*` giữ actor `PRODUCT_OFFLINE_ACTOR` và `targetUserId` (ADR 0009). Guard từ chối `userId = PRODUCT_OFFLINE_ACTOR` giữ nguyên.

## 4. Migration chuyển đổi

### 4.1 Quyền chạy và runbook

Owner hiện tại của các function bị đụng tới:

- `resolve_session` và `protect_system_activation`: `product_session_owner`.
- `require_root_marker` và các guard của 004: `product_migration` (probe ghi owner này).

`product_migration` được tạo NOINHERIT, và membership tạm của provision không đặt INHERIT, nên không kế thừa quyền sở hữu của `product_session_owner`. Membership mặc định có SET option, nên `SET LOCAL ROLE` dùng được.

Quy tắc trong migration:

- **DROP function của `product_session_owner`** (`resolve_session` cũ, `protect_system_activation`): chạy dưới `SET LOCAL ROLE product_session_owner`, rồi `RESET ROLE` ngay.
- **DROP function của `product_migration`** (`require_root_marker`) và thay thân guard 004: chạy bằng `product_migration`, không `SET ROLE`.
- **Tạo function mới** (`resolve_session` mới và các guard Root): theo đúng cách của 008, tất cả bằng `product_migration` sau `RESET ROLE`:
  1. tạo function;
  2. tạo trigger (CREATE TRIGGER cần owner bảng);
  3. REVOKE EXECUTE khỏi PUBLIC và cấp lại EXECUTE đúng như cũ cho `resolve_session` (khi `product_migration` còn là owner; NOINHERIT nên sau khi đổi owner nó không GRANT/REVOKE được nữa);
  4. `ALTER FUNCTION … OWNER TO product_session_owner` (ACL đã cấp được giữ nguyên khi đổi owner), đúng thứ tự REVOKE → GRANT → ALTER OWNER của 002/008.

  Không tạo function dưới `SET ROLE`, vì function do `product_session_owner` tạo không được default privilege của 002 áp dụng và sẽ có EXECUTE PUBLIC mặc định.

- Test migration chạy đúng qua provision thật, không dùng superuser, và assert ACL của `resolve_session` sau migration (EXECUTE đúng ba login, không PUBLIC, owner `product_session_owner`).

Đổi return type của `resolve_session` cần `DROP FUNCTION` + `CREATE FUNCTION`; `CREATE OR REPLACE` không đổi được return type.

Runbook:

1. Dừng/drain **mọi** instance API và writer cũ. Startup probe không bảo vệ một process cũ đang chạy.
2. Backup DB.
3. Provision theo quy trình hiện có: cấp membership owner tạm thời, migrate bằng `product_migration` (owner các bảng), thu hồi membership.
4. Sync release 2.
5. Khởi động binary mới; probe phải pass.

Migration khôi phục chính xác owner, `SECURITY DEFINER`, `search_path` và ACL của function được tạo lại: `resolve_session` có EXECUTE cho `product_data`, `product_identity`, `product_authority` và không có PUBLIC; các guard Root chỉ REVOKE PUBLIC, không cấp EXECUTE cho ai. Chỉ disable **trigger có tên cụ thể**, không dùng `DISABLE TRIGGER ALL`; table owner là đủ quyền.

### 4.2 Trình tự trong một transaction

1. **Khóa và đọc trạng thái:** `authz_state` (`release_sequence`, `manifest_hash`, `materialized_hash`), marker, các holder `system.root`.
2. **Kiểm không drift:**
   - Nếu `release_sequence > 0`: `protectedStateHash(runner.manager)` phải bằng `materialized_hash`, ngược lại fail với `"code-owned facts drifted; repair before migration"`.
   - Nếu `release_sequence = 0`: catalog code-owned phải rỗng, dùng đúng tập bảng và predicate của `protectedStateHash`.
3. **Preflight** (fail thì rollback toàn bộ):
   - Không có `role_definition` nào khác có key bắt đầu bằng `system.` ngoài `system.root`.
   - Số holder `system.root` và quan hệ với marker theo bảng 4.3.
   - Với Root (holder hoặc Root cũ theo marker), mọi `user_boundary` sẽ bị xóa ở bước 6 đều phải trơ (inert): Root cũ không còn **nguồn allow** nào cho cùng permission. Nguồn allow gồm: allow rule trực tiếp (`policy_rule.user_id`), allow rule qua mọi role còn được gán, allow exception trực tiếp và allow exception qua role. Kiểm tra bảo thủ theo sự tồn tại của allow facts; một deny đang có không làm binding thành trơ khi allow vẫn tồn tại. Không xây evaluator quyền tổng quát trong migration. Áp cho Root cũ; holder thì xóa toàn bộ IAM facts nên không cần.
4. **Thêm schema mới:**
   - Thêm `app_user.kind` (DEFAULT `'iam'`), CHECK, partial unique index.
   - Tạo view `iam_account`.
5. **Gỡ trigger cần gỡ** (danh sách cụ thể, mục 4.4):
   - `DISABLE TRIGGER` các trigger **được giữ** nhưng chặn bước 6 (guard code-owned của 004 trên `role_definition`, `policy_rule`, `user_role`, `user_boundary`). `protect_account_lifecycle` không cần disable vì chỉ xét thay đổi `state`.
   - `DROP TRIGGER` các trigger **bị thay thế** (007 `require_root_marker` trên `user_role`; 008 `protect_system_activation` trên `user_role` và `one_time_token`), rồi `DROP FUNCTION public.protect_system_activation()` (dưới `SET LOCAL ROLE product_session_owner`) và `DROP FUNCTION public.require_root_marker()` (bằng `product_migration`), theo mục 4.1. Bỏ hai function khỏi danh sách `protectionFunctions` của probe.
6. **Chuyển đổi Root:**
   - `user_relation` không nằm trong IAM facts bị dọn: Root bypass nên quan hệ ReBAC của Root không ảnh hưởng quyết định phân quyền. Đây là chủ ý.
   - Holder (nếu có): đặt `kind = 'root'`; xóa mọi IAM fact có subject là holder (`user_role` mọi role, `user_boundary`, `policy_rule` theo `user_id`, `record_exception` theo `user_id`).
   - Root cũ (marker initialized, 0 holder): giữ `kind = 'iam'` (không suy marker thành Root); chỉ xóa các `user_boundary` của Root cũ cho permission thuộc grants code-owned của `system.root`, sau khi preflight đã chứng minh chúng trơ.
   - Xóa `policy_rule` code-owned của role `system.root`, rồi `role_definition` `system.root`.
   - Thứ tự theo FK: `user_boundary` trước, rồi rule, rồi role definition.
   - Không xóa permission boundary definition nào (mục 5.2).
7. **Đổi schema cũ:**
   - Drop `account_rank`.
   - Drop cột `authority_level` ở `app_user` và `role_definition`.
   - `DROP`/`CREATE` `resolve_session` với cột `kind`.
   - Cập nhật grants theo mục 3.2 và 3.4.
8. **Cài guard:**
   - Thay thân function guard 004 (bỏ nhánh `system.`), giữ owner và security mode.
   - Tạo các function và trigger ở mục 3.2.
   - `ENABLE TRIGGER` lại đúng danh sách đã disable ở bước 5.
9. **Công bố hash đã chuyển đổi:** nếu `release_sequence > 0`, đặt `materialized_hash = protectedStateHash(runner.manager)` trên trạng thái sau chuyển đổi. Không đổi `release_sequence` và `manifest_hash`.

Không để lại ngoại lệ runtime lâu dài cho việc chuyển đổi. Không bỏ drift check. Không chấp nhận một trạng thái bất kỳ làm baseline.

`protectedStateHash(m: EntityManager)` hiện là hàm nội bộ không export trong `product-manifest.ts`. Plan extract nó sang một module nội bộ của `typeorm-postgres`, giữ nguyên thuật toán, để reconciler và migration cùng import. Không đưa nó lên public entrypoint.

### 4.3 Bảng trường hợp backfill

| Hiện trạng                                                           | Xử lý                                                                                                                                                                                |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Marker chưa initialized, 0 holder                                    | Không có Root. Sau nâng cấp có thể `bootstrap` bình thường                                                                                                                           |
| Marker initialized, 0 holder (Root đã bị revoke)                     | Không có Root; `bootstrap` bị từ chối; cần repair offline có duyệt. Root cũ giữ `kind = 'iam'`. Binding trơ của grants Root được xóa; binding không trơ thì preflight fail để repair |
| Marker initialized, 1 holder = `target_user_id`                      | Holder thành `kind = 'root'`, giữ nguyên `state` (pending/active/suspended) và credential; xóa mọi IAM facts của holder                                                              |
| 1 holder ≠ `target_user_id`, hoặc holder khi marker chưa initialized | Fail (vi phạm bất biến 007 hiện có)                                                                                                                                                  |
| > 1 holder                                                           | Fail, rollback toàn bộ                                                                                                                                                               |

### 4.4 Inventory trigger đích

| Nhóm                  | Trigger                                                                                                                                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Giữ (thân có thể đổi) | Guard code-owned của 004 trên các bảng hiện có; `protect_account_lifecycle`; `protect_token_consumption`; trigger 002 (marker vĩnh viễn, `release_sequence` không giảm); các trigger không liên quan khác |
| Bị thay thế (drop)    | `user_role.require_root_marker` (007); `user_role.protect_system_activation` và `one_time_token.protect_system_activation` (008); cùng hai function của chúng                                             |
| Mới                   | `app_user.guard_root_kind`, `app_user.require_root_marker_kind`, `app_user.guard_root_lifecycle`, `guard_root_not_iam_subject` trên bốn bảng IAM, `one_time_token.guard_root_activation`                  |

Probe kiểm **inventory đích** này (tên, bảng, function, sự kiện, cột `UPDATE OF`, enabled, deferrable, thân hàm). Không đòi các trigger bị thay thế tồn tại.

### 4.5 `down`

`down` **ném lỗi "irreversible; restore from backup"**. Lý do:

- Giá trị rank, role `system.root` và grants của Root không khôi phục được.
- `release_sequence` không giảm được (002), nên binary release 1 bị downgrade gate chặn dù schema có quay lại.

Rollback vận hành là restore backup chụp ở bước 2 của runbook, hoặc forward repair. ADR và runbook ghi rõ.

### 4.6 Repair gỡ suspend Root

Không có đường runtime nào gỡ suspend Root. Repair offline có duyệt do owner bảng (`product_migration`) chạy, trong một transaction:

1. `ALTER TABLE app_user DISABLE TRIGGER guard_root_lifecycle`;
2. `UPDATE` đúng dòng Root;
3. `ENABLE TRIGGER guard_root_lifecycle`.

Repair **không ghi vào `audit_outbox`**: union audit typed không có kind cho nó, và spec không thêm lệnh CLI hay kind mới (giống migration, vốn cũng là thao tác DDL-owner không qua outbox). Bằng chứng là hồ sơ approval: approval reference, người duyệt, thời điểm, câu SQL đã chạy. Runbook ghi quy trình này. Quyền DDL của owner vốn nằm ngoài API (ADR 0008).

## 5. Release, manifest và genesis

### 5.1 Tách contract product khỏi legacy

`ProductReleaseSource` hiện `extends ReleaseSource` và dùng `prepareRelease`; validator và hash legacy bắt buộc `authorityLevel`.

- Tách phần validation **không liên quan rank** (declarations, grants, seeds, boundaries, default grants) thành helper dùng chung. Helper nhận tập role keys đã validate, vì default grants kiểm role tồn tại.
- Legacy `prepareRelease` gọi helper đó cộng validation role có rank như cũ. **Envelope canonical hash legacy giữ nguyên**, không ghép các hash con thành hash mới. Test ghim hash một fixture legacy trước và sau.
- Product có `ProductRole = { key, label }`, validation role riêng; envelope hash product mới chỉ khác ở phần roles và các trường system grants đã bỏ.
- Product release từ chối role key có tiền tố `system.` (tiền tố dự trữ).
- Bỏ `systemGrants`, `removeSystemGrants`, kiểu `SystemGrant`/`SystemGrantRemoval`, `systemGrantHash` và các export tương ứng (`index.ts`, `composition.ts`).

### 5.2 Release mới và genesis

- Release mới: `sequence: '2'`, `predecessor: '1'`. Hash manifest đổi có chủ ý; test ghim hash mới.
- **Nâng cấp** (DB đã ở sequence 1): sau migration mục 4, predecessor khớp và drift check khớp hash đã công bố ở bước 9; sync release 2 thành công.
- **Boundary `rootAccounts@1`:** release 2 không còn khai báo nó.
  - Sau migration không còn binding nào của Root hay Root cũ vào nó, nên reconciler không báo `definition_in_use`.
  - Definition đó còn lại như một dòng code-owned không binding. Spec chủ ý **không** thêm hành vi tự xóa definition bị bỏ khỏi declarations, và migration (generic) không biết tên boundary của domain.
  - Nếu một IAM user khác có binding vào definition này, sync release 2 fail `definition_in_use` theo hành vi hiện có; operator repair binding đó.
- **Cài mới** (DB ở sequence 0): thêm quy tắc genesis cho reconciler product. Khi `release_sequence = 0` **và** catalog code-owned rỗng (cùng tập bảng/predicate của `protectedStateHash`), chấp nhận release bất kỳ làm release đầu tiên, không đòi predecessor. Mọi trường hợp khác giữ predecessor nghiêm ngặt. Account pending được enroll trước genesis không ảnh hưởng, vì đó không phải code-owned fact. Không dùng lại release 1 cũ.
- Boot không downgrade release; không fallback allow khi sync lỗi.

## 6. Root bypass trong bộ phân quyền

### 6.1 Nguồn sự thật

`kind` chỉ lấy từ `resolve_session` đọc trong fenced transaction của request. Không lấy từ payload, header hay cookie. Tên role không bao giờ tạo bypass.

### 6.2 Core: `planUnrestricted`

Thêm `planUnrestricted(input, snapshot)` vào `AuthorizationCore`. Core không biết chữ "root".

- **Vẫn kiểm** như `planUser`:
  - principal id canonical;
  - resource/action tồn tại trong declarations do chính instance validate (unknown thì fail closed);
  - `now`/`validUntil` hợp lệ;
  - snapshot revision.
- **Chỉ thay authorization predicate** bằng `constant true`. Không đánh giá policy, grant, deny, boundary; không có obligations.
- Projection allowlist của binding, key validation và writable-field allowlist **không đổi**. Unrestricted không làm lộ field ngoài projection (ví dụ `ownerId` của document vẫn không trả).
- **Provenance:** plan được đưa vào tập `issued` của instance như `planUser`. Kiểm provenance hiện chỉ ở evaluator (`runtime.ts`); SQL compiler và gateway không kiểm `issued`, mà dựa vào việc chỉ composition mới dựng được gateway. Spec này không mở rộng phạm vi đó và không tuyên bố cả ba tầng kiểm provenance.
- Không thêm cờ `unrestricted` lên plan: adapter đã biết `kind` và tự audit.
- `planUnrestricted` là method public của core: đây là ranh giới cho developer, không phải sandbox. Thêm ESLint rule (`no-restricted-syntax` trên lời gọi `planUnrestricted`) để chỉ `packages/typeorm-postgres/src/product-authority.ts` được gọi nó; kiểm bằng `test/package-boundaries.spec.ts` (ESLint thật) với một ca negative.

### 6.3 `ProductAuthorization.access`

- `kind = 'root'`: gọi `planUnrestricted`. Action chưa khai báo vẫn fail closed (core kiểm như `planUser`).
- `kind = 'iam'`: gọi `planUser` như nay.
- Đây là điểm rẽ nhánh duy nhất.
- Root vẫn qua mọi kiểm tra xác thực: session hợp lệ và chưa hết hạn, `auth_epoch` khớp, account không suspended, CSRF/Origin ở HTTP.

### 6.4 Fresh-auth cho thao tác ghi của Root

| Operation                                                                                                                    | Đường                  | Mode           | Bằng chứng xác thực bắt buộc với Root                     |
| ---------------------------------------------------------------------------------------------------------------------------- | ---------------------- | -------------- | --------------------------------------------------------- |
| list/detail/count                                                                                                            | `access`               | `read`         | Session hợp lệ                                            |
| document update                                                                                                              | `access`               | `write`        | Session hợp lệ + fresh                                    |
| `account.suspend`                                                                                                            | `access`               | `admin`        | Session hợp lệ + fresh                                    |
| login, activation, reauthenticate, recovery, đổi mật khẩu, logout/logout-all, OIDC begin/callback/link/unlink, session touch | identity/OIDC services | ngoài `access` | Theo luồng identity hiện có; **không** áp fresh-auth Root |

Điều kiện fresh tính **trong SQL** cùng câu đọc session, để giữ độ chính xác µs và dùng đồng hồ DB:
`reauthenticated_at IS NOT NULL AND reauthenticated_at <= statement_timestamp() AND statement_timestamp() - reauthenticated_at < interval '300 seconds'`.

Câu SQL trả về một boolean. `access` dùng boolean đó cho cả kiểm tra Root lẫn context `freshAuthentication` của IAM, thay phép tính `Date.parse` hiện tại (vốn chỉ giữ ms). Chặn trực tiếp **chỉ** áp cho Root ở mode `write`/`admin`: không fresh thì `ProductAccessDenied`. Với IAM, boolean chỉ được đưa vào context như nay, và policy (ví dụ `freshAuthentication@1`) quyết định; không có kiểm tra fresh chung cho mọi request. Root đọc không cần fresh. Đây là kiểm tra xác thực trong `access`, không phải policy.

Test: `null`; tương lai; đúng 300 giây (deny); 299.999999 giây (allow); reauth local và reauth OIDC. Context IAM giữ nguyên ngữ nghĩa, chỉ chính xác hơn ở biên. Regression: IAM có quyền đọc, không fresh, vẫn đọc được khi policy không yêu cầu fresh; Root đọc không fresh vẫn đọc được.

### 6.5 Audit Root

**Chỉ event của Root thay đổi.** Event của IAM user giữ nguyên loại event, thời điểm ghi và metadata.

- Mỗi lần Root đi qua `access` mà transaction commit đều ghi audit trong cùng transaction, gọi trực tiếp và `await`. Không đi qua obligation registry; registry rỗng vẫn có audit Root. Audit INSERT lỗi thì rollback mutation và không trả payload.
- Metadata (allowlist) của event Root thêm `principalKind: 'root'` và `outcome`. Writer nhận giá trị này từ session đã xác thực qua typed input, không từ HTTP.

| Thao tác của Root | Event                        | `outcome`                                               | Target                                                                                              |
| ----------------- | ---------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| list              | `access.<resource>.<action>` | `ok` (kể cả danh sách rỗng)                             | Không                                                                                               |
| count             | `access.<resource>.<action>` | `ok` (kể cả 0)                                          | Không                                                                                               |
| detail            | `access.<resource>.<action>` | `ok` nếu tìm thấy, `absent` nếu không                   | Key yêu cầu theo quy tắc hiện có (chỉ uuid/integer), không có `object_id` khi absent                |
| document update   | `data.update`                | `ok` khi có row, `absent` khi không                     | Như hiện tại khi `ok`; khi `absent` chỉ có resource + key yêu cầu (uuid/integer), không `object_id` |
| `account.suspend` | `account.suspend`            | `ok` khi thành công, `absent` khi vắng mặt hoặc là Root | `targetUserId` là id được yêu cầu                                                                   |

- Mở rộng union typed event của `product-audit.ts` cho mọi dòng của bảng trên: `access.*` của Root có target typed cho detail (cả `ok` lẫn `absent`), `data.update` có biến thể `absent` không `objectId`, cùng metadata `principalKind`/`outcome`. Không tạo target giả. Nhánh IAM của union giữ nguyên.
- Denied (kể cả thiếu fresh-auth) không audit, giống IAM hiện nay; transaction bị từ chối rollback.
- Identity operations giữ audit hiện có; `GET /auth/session` không audit.
- `policy_revision`/`resultingRevision` theo ADR 0009.

## 7. Phía IAM khi không còn rank

### 7.1 Resource `account` (`apps/api/src/administration/account.declarations.ts`)

- Binding chuyển từ `account_rank` sang `iam_account`; field còn `state`. Bỏ `authorityLevel` khỏi declaration, columns và projection.
- Xóa boundary `rootAccounts@1` khỏi declarations (mục 5.2).
- `account.suspend` giữ `policy: freshAuthentication@1` và `boundary: 'required'`. IAM user chỉ có quyền này khi có grant **và** boundary tường minh. Hiện không có boundary nào cho `account`, nên trên thực tế chỉ Root suspend được.

### 7.2 `suspendUser`

1. Lookup target qua `iam_account` **trước**. Vắng mặt hoặc là Root (kể cả Root tự nhắm chính mình) thì trả "không tìm thấy", map sang 404 như nay, kèm audit `outcome: 'absent'` nếu actor là Root.
2. Sau đó mới chặn actor = target (IAM user tự suspend) bằng `ProductAccessDenied` (403).
3. Chỉ chuyển sang `suspended` và tăng `auth_epoch` (ADR 0008).
4. Audit `account.suspend` với `targetUserId`.

Không còn phép so rank. Không đo timing; dùng chung một lookup qua view chỉ tránh nhánh xử lý Root riêng, không chứng minh timing bằng nhau tuyệt đối.

## 8. Bất biến và tài liệu

ADR mới (số kế tiếp, dự kiến `0012`) supersede:

- **ADR 0007:** phần "Root không bypass".
- **ADR 0008:** Root là role `system.root`; rank và `account_rank` của migration 006; bảo vệ peer bằng rank.
- **ADR 0009:** chỉ phần nhắc "Root không bypass". Semantics audit của 0009 giữ nguyên.

ADR ghi các nội dung sau:

- Root là super admin bypass phân quyền, lý do (single product, không phải SaaS) và các phần Root vẫn phải qua (xác thực, fresh-auth ghi, audit, action đã khai báo, projection);
- quy tắc genesis;
- protocol công bố `materialized_hash` của migration;
- protocol khóa ở mục 3.3, gồm ràng buộc READ COMMITTED cho promotion và phạm vi lock ordering;
- `down` không đảo ngược;
- quy trình repair gỡ suspend Root (mục 4.6);
- ranh giới provenance hiện có;
- rủi ro mục 11.

`AGENTS.md` root:

- Thêm bất biến: "Root là account `kind = root` nằm ngoài IAM, là super admin bypass mọi kiểm tra phân quyền qua `planUnrestricted`, chỉ khi `kind` đến từ session đã kiểm chứng; tối đa một Root; chỉ bootstrap offline chuyển `iam → root`; mọi `access` của Root được audit; ghi nghiệp vụ/quản trị cần fresh-auth."
- Làm rõ phạm vi: các invariant "default deny, deny thắng, policy/boundary nằm ngoài mọi allow" áp cho **IAM principals**.
- Thay "Cấm … quản trị peer/superior" bằng: "Không có rank ngầm. Bảo vệ giữa các IAM principal khai báo bằng boundary/deny. Action tác động lên principal khác phải là `boundary: 'required'`." Giữ nguyên các cấm còn lại.

Cập nhật thêm:

- `docs/permission-boundaries.md`, `docs/authz-single-product-architecture.md`, `docs/single-product-operations.md` (runbook mục 4.1, 4.5), `docs/single-product-reuse-map.md`.
- `AGENTS.md` của `packages/core`, `packages/typeorm-postgres`, `apps/api`.
- `docs/single-product-verification.md`: giữ bằng chứng lịch sử (mutation "Root bypass" từng là lỗi), thêm semantics mới và mutation mới. Không viết lại lịch sử.
- `docs/prompt.md`: thêm một dòng đầu đánh dấu là prompt lịch sử, bị supersede về Root/rank bởi ADR mới. Không viết lại nội dung.

Migrations 001–011 và ADR/plan lịch sử giữ nguyên làm lịch sử.

## 9. Bản kê thay đổi cần đưa vào implementation plan

Không xóa mọi chuỗi `system.root` hay `authorityLevel`: test dùng role/IdP group giả (ví dụ `test/product-identity.integration-spec.ts`, `packages/core/test/user-decision.spec.ts`) vẫn có giá trị; giữ hoặc điều chỉnh assertion có chủ đích. Phạm vi legacy (mục 1) không đổi theo tìm kiếm chuỗi.

| Nhóm                     | Việc                                                                                                                                                                                                                                                                                                                  |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Release fixtures         | Mọi chỗ dựng `ProductReleaseSource` phải bỏ `systemGrants`/`removeSystemGrants`: `apps/api/src/authorization/product-manifest.ts`, `test/product-system*.integration-spec.ts`, `product-values`, `product-audit`, `product-fence-io`, `product-authorization`, `system-release.spec.ts`, `package-boundaries.spec.ts` |
| Public exports           | Bỏ `SystemGrant`, `SystemGrantRemoval` (`typeorm-postgres/src/index.ts`), `systemGrantHash` (`composition.ts`); cập nhật `test/package-boundaries.spec.ts`; thêm ESLint rule giới hạn nơi gọi `planUnrestricted` (mục 6.2)                                                                                            |
| Hash helper              | Extract `protectedStateHash` sang module nội bộ, giữ thuật toán                                                                                                                                                                                                                                                       |
| Fixtures policy/boundary | `test/product-authorization.integration-spec.ts` đang dùng `system.root` làm principal chịu boundary: chuyển thành **IAM fixture**, không chuyển thành Root                                                                                                                                                           |
| Audit/values/fence/load  | `product-audit.integration-spec.ts` (direct rules cho Root); `product-values`, `product-fence-io` (release cũ); `product-load` (UPDATE cột rank)                                                                                                                                                                      |
| DB/CLI/system            | `product-database.integration-spec.ts` (số migration, inventory trigger/quyền); `product-cli.integration-spec.ts` (assert Root bằng `user_role`); `product-system*`, `system-release.spec.ts` (contract grants/removals cũ)                                                                                           |
| HTTP E2E                 | `apps/api/test/product.e2e-spec.ts`: thay có chủ ý assertion "Root không thấy documents", chặn peer và drift trên role `system.root`; giữ kiểm boot/drift trên một role code-owned còn tồn tại                                                                                                                        |
| Structure                | `apps/api/test/structure.spec.ts`: hash release và OpenAPI nếu đổi                                                                                                                                                                                                                                                    |

## 10. Kiểm thử

Mọi thứ dính tới DB, lock, trigger và quyền đều dùng PostgreSQL thật (Testcontainers).

**Migration:**

- Release 1 thật → migration → release 2 sync thành công, với mỗi dòng của bảng 4.3. Trạng thái "Root đã bị revoke" dựng bằng **bootstrap → revoke-root thật**, không seed SQL.
- Preflight binding Root cũ fail khi còn bất kỳ nguồn allow nào: allow rule trực tiếp, allow qua role, allow exception trực tiếp, allow exception qua role, và trường hợp allow + deny cùng tồn tại. Pass (binding bị xóa) khi chỉ còn deny hoặc không còn fact nào.
- Release 1 đã drift trước migration thì migration fail và rollback; DB giữ nguyên.
- Role `system.*` khác và holder lệch marker đều fail.
- DB mới (sequence 0) → migration → release 2 qua genesis. Genesis bị từ chối khi catalog code-owned không rỗng.
- Một IAM user khác có binding vào `rootAccounts@1` thì sync release 2 fail `definition_in_use`.
- Sau migration, probe pass với inventory trigger đích (mục 4.4).
- `down` ném lỗi.

**Bất biến DB** (với từng runtime login: data, identity, authority, sync, bootstrap, và login của phase B):

- Bị từ chối:
  - INSERT `kind = 'root'`;
  - `iam → root` khi không phải bootstrap, target không pending, có IAM facts, có token còn hạn, hoặc marker đã initialized;
  - `root → iam`;
  - Root thứ hai;
  - commit thiếu marker;
  - gán role, boundary, direct rule hay record exception cho Root, kể cả đổi subject sang Root;
  - login khác bootstrap cấp activation cho Root.
- Bootstrap không sửa được `state`/`auth_epoch` của IAM account. `product_authority` không sửa được `state`/`auth_epoch` của Root (SQL trực tiếp). Không login runtime nào gỡ suspend của Root. Root vẫn kích hoạt, đổi mật khẩu và logout-all được qua identity.
- Migration chạy qua provision thật (NOINHERIT, `SET LOCAL ROLE`), không superuser; function 007/008 không còn sau migration.
- `product_sync` vẫn sync code-owned facts bình thường (guard 004 không đổi ngữ nghĩa).
- DELETE `app_user` bị cấm bởi ACL/FK.
- Probe phát hiện drift của từng function, trigger, attachment mới và quyền owner (thân hàm, owner, `search_path`, enabled, deferrable, toàn bộ ACL owner chính xác).

**Concurrency** (hai connection, credential thật, ngoài runner):

- Promotion giữ khóa trước, transaction gắn `user_role`/`user_boundary`/`policy_rule`/`record_exception`/activation token chạy sau: transaction sau chờ, rồi bị từ chối.
- Thứ tự ngược lại: promotion chờ, rồi bị từ chối.
- Sau cả hai kịch bản, Root không có IAM fact nào.
- Promotion trong transaction REPEATABLE READ hoặc SERIALIZABLE (credential thật, ngoài runner) bị `guard_root_kind` từ chối.
- Thao tác IAM hợp lệ (gắn role/boundary/rule/exception cho IAM user, cấp activation cho IAM user) chạy thành công bằng credential thật sau migration, chứng minh owner guard đủ quyền khóa.

**Core:**

- `planUnrestricted` fail closed với unknown resource/action, principal không canonical và revision sai.
- Plan của instance khác bị evaluator từ chối.
- Plan không có obligations; projection giống `planUser`.

**Bypass:**

- ESLint báo lỗi khi gọi `planUnrestricted` ngoài `product-authority.ts` (ca negative trong `test/package-boundaries.spec.ts`).
- Root list/detail/count thấy mọi document kể cả khi không có grant; không thấy field ngoài projection.
- Root ghi:
  - không fresh thì denied, không audit;
  - fresh thì thành công kèm audit;
  - audit INSERT lỗi thì rollback, không payload.
- Registry obligation rỗng vẫn có audit Root.
- Event Root theo đúng bảng mục 6.5. Event IAM giữ nguyên (so sánh exact với trước).
- Role tên bất kỳ của IAM user không tạo bypass.
- IAM user giữ nguyên hành vi: toàn bộ suite hiện có pass sau khi chuyển fixture.

**Fresh-auth:** các ca biên ở mục 6.4, cho cả Root và context IAM.

**Suspend:**

- Root suspend IAM user.
- Root nhắm vào chính mình, vào Root, hoặc id vắng mặt đều 404 với audit `absent`.
- IAM user tự suspend 403.
- IAM user có grant nhưng không có boundary bị deny.

**CLI:**

- enroll → bootstrap → activation → login.
- `reissue-root`.
- `revoke-root`: Root thành suspended, không đăng nhập được, `bootstrap` sau đó bị từ chối.
- Audit `root.*`.

**Legacy:** hash và validation của release legacy giữ nguyên (fixture ghim).

**Tương thích binary:** binary mới trên schema trước migration bị probe chặn (test tự động). Binary cũ trên schema mới bị chặn: kiểm thủ công một lần, ghi vào `single-product-verification.md` kèm lệnh và kết quả.

**Mutation check** (trên bản sao cô lập; mỗi mutation phải làm ít nhất một test hành vi fail):

- coi mọi principal là Root;
- lấy `kind` từ role name;
- bỏ fresh-auth ghi Root;
- bỏ `kind = 'iam'` trong `iam_account`;
- bỏ audit Root;
- bỏ drift check trong migration;
- genesis không kiểm catalog rỗng;
- bỏ `FOR SHARE` trong guard subject;
- bỏ kiểm isolation trong `guard_root_kind`;
- cho `product_authority` sửa `state` của Root trong `guard_root_lifecycle`.

**Gate:** `pnpm install --frozen-lockfile`, `format:check`, `lint`, `typecheck`, `build`, `test:unit`, `test:integration`, `test:e2e`.

## 11. Rủi ro đã chấp nhận

- **Lộ session Root** cho phép đọc mọi dữ liệu nghiệp vụ. Nếu bị lấy cắp **trong cửa sổ 300 giây** sau reauth, kẻ tấn công ghi được mà không cần nhập lại. Reauth qua OIDC không nhất thiết dùng mật khẩu, nên mức bảo vệ phụ thuộc IdP. Giảm thiểu đầy đủ (MFA bắt buộc) thuộc spec MFA.
- **Credential identity là ranh giới tin cậy** của toàn bộ đăng nhập (ADR 0008 đã ghi). `product_identity` bị chiếm có thể tạo session, kể cả `reauthenticated_at`, cho Root đang active mà không cần đổi `kind`. "`kind` lấy từ DB" không có nghĩa mọi runtime credential đều không thể giả Root. Spec này không tách hệ thống identity.
- **Tính năng mới tự động mở cho Root:** mọi resource/action thêm sau này (kể cả nhạy cảm như cấu hình thanh toán, export dữ liệu khách hàng) Root đều làm được mà không cần quyết định riêng. Chấp nhận vì Root là super admin của chính tổ chức; nếu sau này có dữ liệu Root không được thấy, cần spec riêng.
- **Không còn bảo vệ peer mặc định giữa IAM principal;** đúng như mô hình IAM. Hiện chưa IAM user nào suspend được người khác, vì `account.suspend` yêu cầu boundary và chưa có boundary nào cho `account`.
- **Definition `rootAccounts@1` còn lại** như dòng code-owned không binding sau nâng cấp.
- **Migration import `protectedStateHash`** của chính package, nên migration và binary release 2 phải cùng version. Runbook ghi rõ.
- **`down` không đảo ngược;** rollback vận hành là restore backup hoặc forward repair.
- **Không có Root sau nâng cấp** khi Root đã bị revoke trước đó; cần repair offline có duyệt.
- **Repair gỡ suspend Root dựa vào quyền DDL của owner bảng** (mục 4.6); quyền này vốn nằm ngoài API, nên DB không chặn được owner. Repair không có event trong `audit_outbox`; bằng chứng nằm ở hồ sơ approval.
- **Chưa đo timing** giữa Root/absent ở suspend.

## 12. Thứ tự plan dự kiến

1. ADR mới, `AGENTS.md`, đánh dấu `docs/prompt.md`.
2. Extract `protectedStateHash`; tách contract release product/legacy; genesis; bỏ system grants (unit tests, hash legacy ghim).
3. Core `planUnrestricted` và ESLint rule giới hạn nơi gọi.
4. Migration chuyển đổi, guard mới, ma trận quyền, protocol khóa và probe.
5. Bypass, fresh-auth (SQL) và audit Root trong `access`.
6. Resource `account` và `suspendUser`.
7. CLI Root.
8. Chuyển fixtures/tests theo mục 9, test concurrency, E2E.
9. Docs, mutation check và full gate.
