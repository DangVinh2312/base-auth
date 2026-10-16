# Một NestJS app chia theo chức năng

Ngày: 2026-10-16. Phạm vi được yêu cầu: tạo nhánh mới và thực hiện phương án gom code vào một app đã trao đổi. Đây là chuyển cấu trúc source, không thay mô hình quyền hoặc dữ liệu.

## Kết quả

Giữ app hiện có tại `apps/api`, chuyển bốn package private vào source app và bỏ các package manifests/entrypoints/project references tương ứng. Dùng imports trực tiếp tới module sở hữu implementation/type, không giữ lớp SDK `composition`/`operations`/`legacy` hoặc tạo interface cho từng service/repository.

- `authorization/core`: types, validation, planner, evaluator thuần.
- `authorization/values`: codecs hiện có, giữ contract precision/normalization.
- `authorization/enforcement`: route classification và guard NestJS.
- `authorization/services`, `authorization/helpers`: authority, manifest, obligations và release validation dùng chung.
- `auth/services`: password/session và OIDC.
- `database`: transaction runner, DB configuration/probes, product migrations.
- `audit`: transactional writer và outbox delivery.
- `health`: readiness và metrics.
- `legacy`: tenant adapters/migrations/bootstrap lịch sử, không wire vào API.

Các controller/module/declarations hiện có tiếp tục ở feature tương ứng. Giữ capability facades đang giới hạn operations của controller; không thêm service chỉ chuyển tiếp. CLI offline tiếp tục chạy riêng và dùng cùng manifest/codecs với runtime.

## Bất biến

Không đổi route/status/cookie/CSRF, grants/deny/boundary/Root, AST/SQL semantics, codec precision, fence/revision/retry, audit, manifest hash hoặc migration identifiers/SQL. Không gộp DB logins, không đưa migration/bootstrap credential vào API, không chạy migration hoặc thao tác trên database thật. Shared release validation và transaction errors được tách khỏi code tenant nếu cần để API không nạp legacy implementation.

ESLint chuyển từ package entrypoints sang ranh giới nội bộ: core thuần, HTTP controllers không có driver/runner/runtime/offline capability, chỉ authority service gọi `planUnrestricted`. Đây vẫn là developer boundary, không phải process isolation. Tests hiện có được chuyển/cập nhật imports, không xóa ca kiểm bảo mật. Tests mới chứng minh app không cần package nội bộ và runtime graph không nạp legacy implementation.

## Kiểm chứng và ngoài phạm vi

Node 24.20.0, pnpm 12.3.4 hiện có. Baseline unit: 252/252 pass khi cho phép localhost; lần chạy trong sandbox: 250 pass, 2 lỗi `listen EPERM`. Chạy format có phạm vi, lint, typecheck, build, unit, PostgreSQL integration và HTTP E2E sau chuyển đổi. Dùng Testcontainers disposable, không đọc secrets hoặc dùng database cấu hình của người dùng.

Không thay thuật toán, thêm feature, bỏ legacy tests, commit/push/deploy hoặc tuyên bố production-ready. Tài liệu/ADR cũ giữ làm lịch sử; cập nhật hướng dẫn và quy định làm việc hiện hành cho đường dẫn mới.
