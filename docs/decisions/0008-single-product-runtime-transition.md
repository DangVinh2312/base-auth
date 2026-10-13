# ADR 0008 — Runtime một sản phẩm và compatibility khi chuyển đổi

Ngày: 2026-10-13. Trạng thái: chấp nhận triển khai local; bằng chứng và phần chưa hoàn tất nằm trong kế hoạch chuyển đổi.

## Quyết định

- API mới chỉ sử dụng user/session và một application database. Không có tenant placeholder, tenant optional hoặc flag bỏ kiểm tra. Core có `planUser/evaluateUser` dùng chung algebra với wrapper tenant lịch sử; adapter `product-*` nhận contract không có tenant. Legacy tools/migrations/tests giữ để đối chiếu và bảo toàn dữ liệu, không được wire vào AppModule mới.
- Một fence `authz_state`, READ COMMITTED, lấy khóa trước rồi đọc session và authority mới. Data/identity/authority/sync dùng bốn login thực; API không có pool bootstrap/migration và config từ chối các credentials đó. CLI vận hành dùng file env riêng.
- Dùng trigger do migration sở hữu để bảo vệ code-owned role/grants/seed ownership; sync không takeover runtime facts. Shared fence và session projection dùng SECURITY DEFINER riêng, owner NOLOGIN tối thiểu, không EXECUTE PUBLIC. Permission boundaries và Root không có bypass.
- System grants dùng owner/key ổn định, permission/template/version/parameters exact, thay đổi có previousHash và removal có expectedHash. Hash materialized state bao phủ toàn bộ code facts, kể cả facts được giữ khi release mới bỏ khai báo. Drift chặn cả same-release lẫn newer-release; operator phải khôi phục trạng thái đã duyệt bằng quy trình offline có approval/audit trước khi publish release sửa chữa. Không tự nhận drift làm baseline mới.
- Root bootstrap yêu cầu pending target đã định danh, marker bền vững, exact mandatory boundaries, exclusive fence và audit. Local proof xuất ra artifact mới mode0600; không password mặc định, không secret trong stdout/manifest. OIDC activation cần exact issuer/subject đã bind và proof mới trong15phút, không email auto-link. Boot không seed user/assignment.
- Argon2id và openid-client được pin tại adapter; password hash/token exchange ngoài fence. Session opaque có12giờ absolute và30phút idle; idle chỉ chạm qua identity session operations, nên data-only traffic có thể hết hạn sớm hơn dự kiến người dùng. Không kéo dài absolute expiry và không hứa revoke tại IdP tức thời.
- API hiện là fixture tối thiểu: document list/detail/update title và suspend user thấp cấp. Chưa mở generic role/grant/boundary/relationship administration, files/export/jobs. Capability chưa có không nhận request hoặc trả unavailable, không fallback allow.

## Migration và các gate

Không có mapping/dữ liệu thật được cung cấp. Product migration từ chối schema tenant/identity legacy thay vì gộp/xóa dữ liệu; migration nâng cấp fixtures product và bảo vệ unversioned relation đã được test PostgreSQL. Đây không phải tool hợp nhất production.

Recovery email có delivery port; binary mặc định chưa có provider và trả503. Root recovery/elevation yêu cầu runbook hai người và audit ngoài API; chưa có automatic recovery command. Production IdP/TLS, durability/failover, Argon2/blocklist calibration, audit delivery/retention và CI remote chưa được chứng nhận. Không gọi bản này production-ready.
