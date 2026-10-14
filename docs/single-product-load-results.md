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

## T8 — I/O trong fence trên đường service (2026-10-14)

Lệnh: `pnpm run test:integration -- test/product-fence-io.integration-spec.ts`, chạy riêng (một container) 3 lần trước và 3 lần sau thay đổi, cùng workload. Đây là đường service `ProductAuthorization.list/detail/update` và `ProductIdentityService.logout` (revoke) mà controller HTTP gọi; **không đo HTTP/Nest/cookie**. Request HTTP có route `@ProductAuthorize` còn chạy trước một transaction `checkSession` riêng (shared fence + `resolve_session`, 6 statement) do guard kiểm session sớm; transaction đó không có trong số đo dưới đây.

Môi trường: Node v24.20.0, darwin/x64, Intel Core i5-1038NG7 (4 nhân/8 luồng, 2.0 GHz), RAM host 16 GiB; Docker 29.8.2 VM 8 CPU/7.75 GiB; `postgres:18.4` (18.4 Debian), một replica, pool mặc định (max 10/login), transaction deadline 2 s, lock timeout 1 s, tối đa 2 retry. Fixture: 10 000 dòng `product_item` (3 285 khớp policy+boundary+deny), 40 permissions (`item.read`, `item.update`, 38 action khác, cùng resource), 80 rules áp dụng cho user (40 role allow code-owned + 40 identity deny runtime), 40 boundary bindings bắt buộc, obligation `audit@1` trên update. Mỗi loại thao tác: 20 warmup + 100 mẫu tuần tự; workload trộn: 8 worker, 400 thao tác (50% list 20 dòng, 20% detail, 20% update, 10% revoke).

Thay đổi: `readProductAuthority` đọc user, roles, catalog/rules/boundaries **chỉ của permission đang hỏi** trong một statement (trước: 5 statement, catalog toàn bộ); clock DB gộp vào statement session; list trả trang và `total` trong một statement (bỏ count fallback khi trang rỗng). Fence, thứ tự lock, recheck session/authority trong transaction, deny/boundary và revoke giữ nguyên.

| Statement/thao tác (gồm BEGIN..COMMIT) | Trước | Sau |
| -------------------------------------- | ----: | --: |
| list                                   |    13 |   8 |
| detail                                 |    13 |   8 |
| update (gồm 2 audit insert)            |    15 |  10 |
| revoke (identity path, không đổi)      |    10 |  10 |

Tuần tự, p50/p95 ms (3 lần chạy, trước → sau):

| Thao tác | Latency p50                     | Latency p95                     | Lock hold p50         |
| -------- | ------------------------------- | ------------------------------- | --------------------- |
| list     | 25.5/27.3/27.2 → 21.3/22.2/20.9 | 33.8/44.1/40.9 → 28.2/29.9/31.8 | 22/24/24 → 18/18/18   |
| detail   | 12.9/15.4/14.7 → 9.4/10.2/10.1  | 23.1/28.3/25.6 → 15.8/15.4/20.5 | 10/12/11 → 6/7/7      |
| update   | 17.5/19.3/20.2 → 10.8/12.4/10.8 | 29.8/30.3/30.7 → 19.2/40.0/15.5 | 14/15/16 → 8/9/8      |
| revoke   | 10.8/13.5/11.7 → 9.3/11.9/8.6   | 16.8/26.2/17.8 → 15.0/22.7/12.6 | 7/9/8 → 6/8/6 (nhiễu) |

Workload trộn (trước → sau): elapsed 4232/4129/3952 → 2264/2765/2831 ms; latency p95 356/371/353 → 160/213/194 ms, p99 619/608/583 → 255/369/399 ms; lock wait p95 329/349/334 → 141/185/182 ms; lock hold p95 65/65/58 → 38/49/55 ms; 0 lỗi ở cả 6 lần ghi số. Lần chạy thăm dò đầu tiên (trước thay đổi, khi test còn assert 0 lỗi) có 2/400 revoke bị `25P04` (transaction_timeout 2 s) nguyên nhân chưa xác minh (giả định: revoke xếp hàng sau các shared fence); không tái hiện ở 3 lần baseline sau, nên chỉ ghi nhận là dấu hiệu contention, không phải tỷ lệ lỗi.

EXPLAIN ANALYZE câu list (offset 80, 30 lần, cùng fixture, credential data): dạng cũ `count(*) OVER()` + `LIMIT/OFFSET` p50 13.46 ms (top-N heapsort); dạng mới `count(*) OVER()` + `row_number()` lọc trang p50 14.18 ms (quicksort toàn bộ 3 285 dòng khớp). Cả hai đều quét toàn bộ dòng khớp vì `total` chính xác; dạng mới đắt hơn ~0.7 ms/statement nhưng bỏ statement fallback và `total` luôn cùng snapshot với `items` (test `an empty page past the end…` tái hiện fallback cũ trả `total` của snapshot sau). Hợp đồng response không đổi; muốn tránh quét toàn bộ (keyset/ước lượng total) là đổi contract, cần ADR riêng. Sau code review (lo ngại full sort ở bảng lớn), đo thêm trên PostgreSQL 18.4 riêng với predicate tương tự (status/amount/title + `NOT EXISTS`), offset 80, median 7 lần (ms, cũ → mới): 100k dòng ORDER BY id 108 → 90, ORDER BY title,id 74 → 83; 1M dòng ORDER BY id 1201 → 1339, ORDER BY title,id 1141 → 1018. Chênh lệch ±12%, cả hai đều tăng tuyến tính vì `total` chính xác quét mọi dòng khớp; ở 1M dòng cả hai đã gần statement timeout 2 s — giới hạn thật nằm ở contract total, không ở cách lấy trang.

Không suy ra năng lực production hay nhu cầu chia fence từ số đo này: một máy, fixture tổng hợp, không warmup kéo dài, không có SLO. Còn lại trong fence: revoke giữ `last_seen_at` touch + revoke + audit + revision (T9), update có 2 audit insert (effect + obligation, khác mục đích). START/SET ISOLATION/set_config là 3 round-trip trước khi lấy fence (không tính vào lock hold), chưa gộp.
