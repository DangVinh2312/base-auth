# ADR 0013: Bỏ legacy, giữ phiên bản multi-package

Status: Accepted — 2026-10-16, theo yêu cầu trực tiếp của người dùng.

## Decision

Nhánh `version/multi-package` giữ các package `core`, `nest`, `value-adapters`, `typeorm-postgres` và app API. Đồng bộ phần bỏ legacy/code thừa đã kiểm chứng ở `version/single-app`, không chuyển topology sang một app.

- Bỏ tenant contracts/wrappers/parser, registry/provisioner/runner/compiler/gateway/authority legacy, bootstrap/audit tenant, migrations identity/tenant cũ và CLI tương ứng.
- Core chỉ giữ contracts `User*`; không tenant giả hoặc config flag. Giữ public entrypoint của từng package; PostgreSQL adapter giữ root an toàn và subpaths `composition`/`operations`, bỏ `legacy`.
- Tách transaction errors, connection types và release validation còn dùng khỏi implementation tenant trước khi xóa. Không deep-import private source xuyên package.
- Chuyển fixtures/tests hữu ích sang product contracts/compiler; xóa tenant-only và frozen release 1 compatibility tests. Giữ E2E startup cancellation theo deadline của test.
- Giữ product migration chain 001–012 và domain migration để dựng schema hiện tại; không thay SQL, manifest hash, Root/auth/fence/audit/codec semantics.

Người dùng xác nhận chưa triển khai server thật nên không cần giữ compatibility tenant. Task không nhập/xóa dữ liệu thật. ADR/plan cũ là lịch sử, không buộc giữ implementation đã bỏ. Push được người dùng hoãn; chưa có Git remote.
