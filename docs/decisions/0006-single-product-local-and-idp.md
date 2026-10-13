# ADR 0006 — Bản thu gọn hỗ trợ local authentication và IdP

> Quyết định đã được chọn làm kiến trúc đích bởi prompt triển khai. Runtime local/bằng chứng hiện tại được ghi ở [ADR0008](0008-single-product-runtime-transition.md) và [kế hoạch chuyển đổi](../superpowers/plans/2026-10-13-single-product-transition.md); trạng thái chưa triển khai bên dưới mô tả thời điểm viết ADR ban đầu.

Ngày: 2026-10-13. Trạng thái: quyết định thiết kế theo yêu cầu; chưa triển khai runtime.

## Quyết định

Bổ sung ADR 0005: một sản phẩm không đồng nghĩa local-only. Hỗ trợ local password, OIDC hoặc cả hai, được bật tường minh. Không bắt buộc IdP cho local-only và không đưa tenancy trở lại.

Hai authenticator dùng chung user nội bộ, opaque application session và authorization engine. Policy, boundary, grant/deny và revoke tại ứng dụng không phụ thuộc nguồn đăng nhập. External identity dùng khóa `(issuer, subject)`; không tự link qua email hoặc cấp role từ claims. OIDC-only không được tạo password bằng reset flow. Link/unlink cần reauthentication, proof of provider identity, constraints, audit và revoke thích hợp.

Provider config do deploy quản lý; kiểm cấu hình theo phương thức đang bật. IdP failure không tự mở local fallback. Assurance mapping là issuer-specific. Local logout/revoke khác IdP logout/revoke; nếu chưa có event integration, session ứng dụng chịu giới hạn absolute expiry đã công bố.

Hợp đồng và tests: [Kiến trúc một sản phẩm, mục 4.5](../authz-single-product-architecture.md#45-idp-là-một-phương-thức-được-hỗ-trợ). Bản đầu chọn OIDC, chưa hỗ trợ SAML hoặc tự xây OAuth server.

## Hệ quả và kiểm chứng

Có thêm external identity mapping, OIDC login attempt và tests chống account linking/replay/downgrade. Giữ lịch sử ADR trước; không coi code hiện tại đã đáp ứng thiết kế này. Lần thay đổi này chỉ cập nhật tài liệu, chưa chạy integration với IdP.
