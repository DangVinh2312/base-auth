# Kết quả fixture tải application fence

Ngày chạy: 2026-10-13. Đây là phép đo local nhỏ bằng PostgreSQL thật, không phải kết luận hiệu năng production hoặc HTTP benchmark.

Lệnh đã chạy:

```sh
pnpm run test:integration -- test/product-load.integration-spec.ts
```

Kết quả: 2/2 tests pass. Node v24.20.0, host darwin/x64, Docker image `postgres:18.4`, server `18.4 (Debian 18.4-1.pgdg13+1)`. Container/database dùng một lần; credential thật riêng cho data/identity/authority/sync/bootstrap, không chạm staging/production.

Dataset gồm 100 dòng `product_load_item` và một user tổng hợp. Tám worker chạy 80 transaction: 40 read (gồm 8 read cố tình giữ shared fence bằng `pg_sleep(0.04)`), 24 write, 8 authority change, 8 revoke tăng auth epoch. Mỗi transaction dùng READ COMMITTED và cùng singleton application fence. Pool dùng cấu hình mặc định của TypeORM/pg; timeout mặc định 2 giây, lock timeout 1 giây, tối đa 2 retry.

Thời gian workload sau setup: **406.30 ms**. Độ trễ request p95 **127.97 ms**, p99 **141.30 ms**; 0/80 lỗi và timeout rate **0%**. Tổng các write đã commit khớp số increment trong database.

| Metric                | Số mẫu | p95 (ms) | p99 (ms) |
| --------------------- | -----: | -------: | -------: |
| Pool wait             |     80 |       21 |       23 |
| Fence lock wait       |     80 |      113 |      129 |
| Fence lock hold       |     80 |       46 |       49 |
| Transaction           |     80 |      128 |      142 |
| Revoke commit latency |      8 |      142 |      142 |

Chạy lại cùng suite authorization bằng `pnpm run test:integration -- test/product-authorization.integration-spec.ts test/product-load.integration-spec.ts`: **7/7 pass**. Workload tải vẫn 80 operation với cùng dataset/concurrency, elapsed **516.08 ms**, p95 **167.36 ms**, p99 **222.13 ms**, 0 lỗi/timeout. Hai container PostgreSQL khởi động và chạy đồng thời trên cùng máy; kết quả này minh họa độ nhiễu của phép đo local, không phải regression gate.

Test riêng tạo contention thật: một shared fence bị giữ trong lúc revoke dùng lock timeout 30 ms, tối đa một retry. PostgreSQL trả 55P03 ở cả hai lần thử; runner báo đúng 2 timeout + 1 retry và dừng bằng `TransactionConflictError`. Trường hợp cố tình này không tính vào timeout rate của workload trên.

Fixture đo transaction/fence và privilege routing trên bảng tổng hợp, không đo chi phí toàn bộ login, OIDC, session projection, authorization AST, gateway, audit hoặc HTTP. Các lần chạy đều nhỏ, không có warmup/đồ thị saturation, phân bố production, nhiều replicas hay SLA. Các suite khác có thể chạy trên cùng máy nên số đo có nhiễu. Chưa có bằng chứng cần chia fence theo module/resource; giữ singleton fence và đo workload thực trước khi đề xuất ADR khác.
