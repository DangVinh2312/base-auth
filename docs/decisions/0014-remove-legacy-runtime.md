# ADR 0014: Bỏ implementation tenant và compatibility legacy

Status: Accepted — 2026-10-16, theo yêu cầu trực tiếp của người dùng.

## Context

ADR 0013 gom source vào một app và tạm giữ tenant runtime để đối chiếu. Người dùng xác nhận chưa triển khai lên server thật, không cần giữ legacy. Quyết định này thay thế yêu cầu giữ implementation/fixtures legacy trong các plan trước.

## Decision

- Xóa tenant adapters, identity database cũ, migrations tenant/identity cũ, bootstrap/audit legacy, tenant CLI/config và contracts/wrappers tenant trong core.
- Chỉ giữ contracts `User*`, `planUser`, `evaluateUser`, `planUnrestricted`; không thêm tenant giả, flag hoặc fallback.
- Chuyển tests algebra, codec, SQL/collation còn hữu ích sang contracts/compiler một sản phẩm; xóa tests chỉ dành cho implementation đã bỏ và frozen release 1 compatibility fixtures.
- Giữ chuỗi product migrations 001–012 và domain migration đang dựng schema hiện tại, cùng privilege/Root/fence/audit guards và tests của runtime hiện hành. Không squash hoặc thay SQL trong task này.
- Tài liệu ADR/plan cũ là lịch sử; tài liệu vận hành và quy tắc hiện hành phải phản ánh không còn legacy CLI/runtime.

## Consequences

Không còn đường chạy hoặc công cụ chuyển dữ liệu tenant cũ. Dữ liệu ngoài disposable fixtures không được chuyển/xóa trong task này. Muốn nhập dữ liệu từ hệ thống khác sau này cần thiết kế và mapping riêng. Default deny, Root, sessions, revision, atomic audit và DB credentials giữ nguyên.
