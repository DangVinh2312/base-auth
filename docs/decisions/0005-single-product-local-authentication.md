# ADR 0005 — Phương án một sản phẩm với đăng nhập nội bộ

> Quyết định đã được chọn làm kiến trúc đích bởi prompt triển khai. Runtime local/bằng chứng hiện tại được ghi ở [ADR0008](0008-single-product-runtime-transition.md) và [kế hoạch chuyển đổi](../superpowers/plans/2026-10-13-single-product-transition.md); trạng thái chưa triển khai bên dưới mô tả thời điểm viết ADR ban đầu.

Ngày: 2026-10-13. Trạng thái: đề xuất kiến trúc thay thế theo yêu cầu; chưa chuyển runtime hoặc schema hiện tại.

Bổ sung theo yêu cầu tiếp theo: [ADR 0006](0006-single-product-local-and-idp.md) đưa OIDC vào phạm vi hỗ trợ của bản thu gọn, cùng local authentication; không bắt buộc deploy IdP.

## Bối cảnh

Sản phẩm không cần multi-tenant nhưng vẫn cần kiểm soát quyền nghiêm ngặt. Người dùng yêu cầu một phiên bản thiết kế riêng và chấp nhận đăng nhập thông thường, không bắt buộc IdP.

## Phương án

Một NestJS modular monolith, TypeORM, một PostgreSQL database, pnpm. Bỏ tenant/membership/directory/provisioner và yêu cầu OIDC; dùng user, password Argon2id, opaque server-side sessions và luồng recovery nội bộ. Credential operations tách khỏi administration permissions; user manager không được chiếm tài khoản người khác.

Giữ RBAC/ReBAC/ABAC, permission policy, generic user permission boundary, record exceptions, shared AST cho list/detail/write, code-owned manifests, audit và chống self/peer escalation. Application fence thay tenant fence; database credentials tách theo mục đích trong cùng database. Không thêm flag bỏ tenant checks vào engine cũ.

Hợp đồng đầy đủ: [Kiến trúc một sản phẩm](../authz-single-product-architecture.md). Tài liệu multi-tenant và ADR 0001–0004 tiếp tục mô tả runtime đang có; ADR này chưa thay thế chúng cho implementation hiện tại.

## Hệ quả

Giảm provisioning/routing và adapter portability, nhưng ứng dụng phải tự bảo vệ password/session/recovery. Global fence có thể tăng contention. Một data credential vẫn đọc được ngoài row scope nếu code bypass gateway; không quảng cáo DB-enforced row isolation khi chưa thiết kế lớp đó.

Không tự gộp dữ liệu tenant cũ, xóa cột hoặc đổi identity schema. Cần quyết định chuyển implementation, migration/data mapping và kiểm chứng độc lập trước rollout. OIDC được hỗ trợ theo ADR 0006; MFA có thể thêm khi cần; MFA cục bộ không đòi IdP, và policy đòi MFA chưa được đáp ứng phải deny.

## Kiểm chứng

Lần này chỉ viết và kiểm tài liệu, không có runtime/spike tests cho phương án mới. Kết quả kiến trúc cũ không là bằng chứng migration/local authentication hoạt động.
