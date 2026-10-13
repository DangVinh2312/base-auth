# ADR 0007 — System roles, DB privileges và theo dõi application fence

> Quyết định đã được chọn làm kiến trúc đích bởi prompt triển khai. Runtime local/bằng chứng hiện tại được ghi ở [ADR0008](0008-single-product-runtime-transition.md) và [kế hoạch chuyển đổi](../superpowers/plans/2026-10-13-single-product-transition.md); trạng thái chưa triển khai bên dưới mô tả thời điểm viết ADR ban đầu.

Ngày: 2026-10-13. Trạng thái: hợp đồng thiết kế phục vụ triển khai tiếp; chưa triển khai trong lần cập nhật tài liệu.

## Quyết định

- Bổ sung system role `system.root` vào profile một sản phẩm, có grants tường minh; không bypass policy/boundary/deny/self/peer và không đồng nghĩa DB superuser.
- Tách role definition sync, system-grant reconciliation và initial Root enrollment. `defaultGrants` cho permission mới không đủ để cấp permission cũ cho role mới.
- System grants có stable owner/key và explicit changes/removals; drift cùng release làm fail readiness. Không ghi đè runtime facts hoặc tự tái gán Root khi boot.
- Bootstrap marker một lần chống tái cấp quyền sau revoke và chống race. Local/OIDC activation chứng minh identity; không mật khẩu mặc định. Root recovery/elevation nằm ngoài API, có audit và approval độc lập.
- Code-owned rows được bảo vệ cả command lẫn DB writer; flag managed_by đơn lẻ không là enforcement.
- Triển khai đúng credential matrix data/identity/authority/sync/migration cùng function SECURITY DEFINER hẹp. Privilege tests dùng login thật; API không giữ migration/bootstrap credential.
- Giữ một application fence, đo contention và revoke latency. Chưa chia theo module/resource type khi chưa chứng minh dependencies và consistency.
- Wire boot/authority vào API thật; lỗi sync/config/privilege không mở business listener/worker.

## Hệ quả

Cần migration và tests cho bootstrap state, system-grant ownership/protection, privileges và boot E2E. Root vẫn có thể bị chặn hợp lệ; không dùng wildcard để làm demo thuận tiện. Global fence đơn giản nhưng cần benchmark mixed workloads; DB privilege separation không chống code tùy ý đã nắm mọi process secrets.

Chi tiết: [kiến trúc mục 8–11](../authz-single-product-architecture.md). Prompt triển khai đặt tại `../base-auth/docs/prompt.md` tính từ root dự án; nó giao việc cho AI khác, không phải kết quả thực thi.
