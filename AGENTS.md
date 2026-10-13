# Base Authorization

## Phạm vi và nguồn thiết kế

- Đây là dự án độc lập: NestJS, TypeORM, PostgreSQL; không import/copy nghiệp vụ từ repo khác.
- Chuyển đổi một sản phẩm theo `docs/authz-single-product-architecture.md`, ADR 0005–0007 và `docs/superpowers/plans/2026-10-13-single-product-transition.md`. Kiến trúc/plan cũ là lịch sử tái sử dụng, không ràng buộc duy trì tenancy.
- Trạng thái task lấy từ checkbox trong kế hoạch và ADR `docs/decisions/`; bước chưa đánh dấu là chưa có bằng chứng hoàn thành.
- Mỗi package/app có `AGENTS.md` riêng (`packages/core`, `packages/nest`, `packages/typeorm-postgres`, `apps/api`): đọc file của module trước khi sửa module đó.
- Giữ thay đổi nhỏ, hoàn tất phạm vi được yêu cầu; không triển khai toàn bộ kế hoạch nếu người dùng chỉ yêu cầu một phần.
- Không sửa file ngoài task, ghi đè thay đổi của người dùng, tự commit/push/publish/deploy nếu chưa được yêu cầu.
- Quyết định ảnh hưởng tenant isolation, identity hoặc dữ liệu cần ghi ADR; không tự đổi spec bằng một config flag.

## Package manager và workspace

- Chỉ dùng pnpm. Phiên bản lấy từ `package.json#packageManager`; dùng Node 24 theo `.nvmrc` và `engines`.
- Workspace khai báo trong `pnpm-workspace.yaml`: `apps/*`, `packages/*`; giữ một `pnpm-lock.yaml` ở root.
- Không tạo `package-lock.json` hoặc `yarn.lock`, không dùng npm/yarn/npx để install hoặc scaffold.
- Dùng `pnpm exec <tool>` cho dependency local; khi cần generator chưa có, dùng `pnpm dlx <package>@<exact-version>`. Không cài CLI global hoặc dùng `@latest` trong quy trình tái lập.
- Thêm dependency tại package sở hữu: `pnpm --filter <package> add <dependency>`; tooling root dùng `pnpm add -Dw <dependency>`.
- Internal dependencies dùng `workspace:*`, khai báo trực tiếp; không dựa vào hoisting hoặc import private source xuyên package.
- Commit lockfile cùng dependency changes. CI dùng `pnpm install --frozen-lockfile`; không hand-edit lockfile.
- pnpm settings nằm trong `pnpm-workspace.yaml`. Chỉ tạo `.npmrc` khi cần registry/auth và không commit token.
- Không tắt strict peer checks để che xung đột. Build scripts của dependency chỉ bật khi đã biết vì sao cần và được giới hạn đúng package.

## Ranh giới kiến trúc

- `packages/core`: pure types, AST, validation, planning/evaluation; không NestJS, TypeORM, SQL driver, network hoặc tên domain.
- `packages/nest`: decorators, guards, route manifest, context, readiness; phụ thuộc core ports, không phụ thuộc entity nghiệp vụ.
- `packages/typeorm-postgres`: compiler SQL, data gateway, authority store, transactions, migrations và fixed-purpose product pools (tenant pools chỉ legacy).
- `apps/api`: ghép các adapter; authn/admin và domain demo nằm ở đây. D2/D3 là fixtures kiểm chứng khả năng tái sử dụng.
- Tách đọc/ghi/cache khi trách nhiệm khác nhau; không tạo cache service khi chưa có cache.
- Package public API qua `src/index.ts`; không export credentials, raw connection hoặc bypass authorization cho handler.
- `tsconfig.base.json` chỉ chứa defaults chung. Chốt module format/decorator metadata khi scaffold và test build thật; core không cần decorator metadata.

## Bất biến bảo mật

- Runtime đích không có tenant: một database, user/session chung; không tenant giả, tenantId tùy chọn hoặc flag bỏ isolation. Không gộp dữ liệu tenant thật thiếu mapping.
- Default deny; mọi deny thắng allow. Permission policy nằm ngoài mọi grant, kể cả record allow.
- Permission boundary là giới hạn tổng quát của membership/permission, không tự grant; áp dụng ngoài mọi allow kể cả record exception. Đọc `docs/permission-boundaries.md`; `ApplicationRoleBoundary` chỉ là ví dụ, không hardcode vào lõi.
- Không baseline ngầm khi thiếu policy. Unknown action/resource/scope/operator/validator/obligation làm fail closed.
- List/detail/count/export/write dùng cùng AST. Không lọc quyền sau pagination hoặc lấy quyền read suy ra update.
- Context/user/roles không lấy trực tiếp từ payload chưa kiểm chứng. Không dùng brand TypeScript như một security boundary.
- ReBAC kiểm tra source/target type, exact version và hạn trên từng cạnh; path tối đa 8 bước, không đệ quy vô hạn hoặc SQL callback tùy ý.
- Cấm tự nâng quyền trực tiếp/gián tiếp, quản trị peer/superior, sửa code-owned definitions qua UI và lấy quyền user admin để reset/link/impersonate global identity.
- Secrets/token/PII không ghi log. DTO/projection chỉ trả field được phép; foreign/absent record không phân biệt sự tồn tại.

## Database, boot và concurrency

- PostgreSQL + TypeORM, `synchronize: false` ở mọi môi trường; migrations độc lập với AppModule.
- Một database, login riêng data/identity/authority/sync/migration; API không giữ migration/bootstrap credential.
- Trong transaction chỉ dùng `QueryRunner.manager`/transaction manager được truyền vào; không global repository hoặc network I/O.
- Facts bảo mật đổi phải lấy exclusive application fence, kiểm tra affected set rồi tăng revision cùng transaction. Reads/data write giữ shared fence theo spec.
- Lock ordering nhất quán, retry có giới hạn và idempotency; không báo revoke thành công trước commit.
- Key integer lớn không ép qua JS number; money/decimal không dùng floating point. Raw SQL chỉ parameterized, identifiers từ registered binding.
- Schema migration không chạy ngầm trong boot. Boot chỉ sync manifest DML có version/hash, idempotent và chờ xong trước readiness/worker.
- Boot không ghi đè runtime relation tuples, không downgrade manifest, không fallback allow khi sync lỗi.

## Kiểm tra và tài liệu

- Commands hiện có: xem `scripts` trong `package.json` (format, lint, typecheck, build, test:unit, test:integration, db:migrate, db:provision, start:dev). Test nhận path filter sau `--`; integration cần Docker.
- Build/typecheck/unit/integration/E2E scripts chỉ thêm khi tool/source tương ứng tồn tại; không dùng placeholder hoặc `--if-present` để làm CI xanh giả.
- Logic phân quyền, money, parser và concurrency phải có test hành vi. Dùng PostgreSQL thật cho locks/FKs/transactions; không SQLite thay thế.
- Mọi DB test dùng disposable fixtures; không chạm staging/production để kiểm chứng.
- DTO có validation và Swagger examples; route có success shape và các status thực tế có thể trả.
- Khi thay contract, cập nhật callers, fixtures, manifest, migration, tests và tài liệu liên quan.
- Báo đúng lệnh đã chạy/kết quả; phân biệt test dự kiến, spike lịch sử và test hiện tại. Chưa chạy phải nói rõ.
- Giữ `docs/` được Git theo dõi. Không nâng trạng thái production-ready chỉ vì lint hoặc formatting pass.
