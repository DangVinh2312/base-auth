# Database

Đọc root và `apps/api/AGENTS.md`. Module này giữ fixed-purpose transactions, DB configuration/probes và product migrations; không phải package adapter hoặc generic repository framework.

- `product-transaction.runner.ts`: READ COMMITTED, fence trước facts, retry/deadline hữu hạn, shared cho read/write/identity; exclusive cho facts mutation/sync. Không nâng shared thành exclusive.
- `helpers/transaction-errors.helper.ts`: class lỗi và runtime capability của product runner; giữ một class identity để filter/retry nhận đúng lỗi.
- `helpers/product-database.helper.ts`: credential matrix, provisioning offline, exact privilege/protection probes. HTTP runtime chỉ dùng verify; provisioning/options/migration registry chỉ tools/tests dùng.
- `migrations/`: migration class names/timestamps/SQL đã áp dụng không được đổi. Chỉ forward migration khi thay semantics; không chạy DDL trong boot, `synchronize: false`.
- Một database, credentials data/identity/authority/sync/migration/bootstrap riêng. API không giữ migration/bootstrap credentials; không fallback pool khi thiếu capability.
- Chỉ dùng transaction manager truyền vào; identifiers từ registered binding, giá trị parameterized. Không dump SQL binds, URLs hoặc raw DB errors.
- Privilege/protection tests dùng credential thật và PostgreSQL disposable: kiểm owner/ACL, SECURITY DEFINER/search_path/body, trigger enabled/binding, CREATE/TEMP/grant option; không hardcode tổng trigger thay kiểm từng bảo vệ.
- Migrations ứng dụng ở feature tương ứng, đăng ký riêng trong `tools/product.ts`; không tự thay protected functions/triggers để làm probe pass.
- ADR 0014 đã bỏ tenant/identity schema cũ; product migrations ở đây vẫn là đường dựng schema hiện tại.

Tests: `test/product-database.integration-spec.ts`, `test/product-genesis.integration-spec.ts`, `test/product-root-guards.integration-spec.ts`, cùng các suite locks/fence/privileges thực tế. Cần Docker; không SQLite hoặc database thật của người dùng.
