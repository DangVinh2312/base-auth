# ADR 0003 — Permission boundary tổng quát

Ngày: 2026-10-13. Trạng thái: thiết kế bổ sung, chưa triển khai runtime/migration.

## Bối cảnh

Policy bắt buộc áp dụng chung cho permission; grant scope giới hạn từng nguồn cấp. Cần một giới hạn của membership áp dụng ngoài mọi nguồn allow, cho nhiều hành động/resource, không chỉ assignRole.

## Quyết định

Dùng typed AST hiện có để biểu diễn permission boundary và AND với policy/grants trước mọi đường truy cập dữ liệu. Boundary không cấp quyền. `ApplicationRoleBoundary` là tên cấu hình ứng dụng, không phải primitive trong core.

Bản đầu có một binding trên membership/permission; action khai báo required hoặc optional tường minh. Required thiếu binding thì deny; optional có binding vẫn phải kiểm tra. Không thêm role inheritance hoặc engine riêng. Definition version bất biến; boot chỉ cập nhật code-owned seeds và không ghi đè binding runtime.

Bổ sung ba bảng definition/entry/binding cùng requirement ở catalog bằng forward migration; composite FKs giữ tenant và permission alignment. Cập nhật authority snapshot, revision/fence, audit và compatibility readiness trước khi activate. Không sửa migration đã chạy hoặc coi binaries cũ đã thực thi boundary.

Hợp đồng, ví dụ, semantics và test bắt buộc: [Permission boundaries](../permission-boundaries.md). Kế hoạch có delta sau Task 5 và thay đổi Task 8/11. ADR 0002 mô tả runtime trước delta này; chỉ sau implementation và kiểm chứng mới bổ sung conjunct boundary vào runtime.

## Hệ quả

Có thêm authority facts cần tải/validate và migration bắt buộc. Giới hạn một binding tránh hợp/ưu tiên nhập nhằng; nhiều điều kiện phải biểu diễn tường minh trong AST. Assignment boundary chỉ chặn các lần gán tiếp theo, không tự thu hồi quyền đã cấp cho người nhận. Thiếu facts/không chứng minh subset thì từ chối.

## Còn mở

Boundary kế thừa từ role hoặc nhiều binding chưa được chọn: chỉ mở rộng khi có trường hợp sử dụng và semantics phép giao được kiểm chứng.
