# @base-authorization/value-adapters

Implementation của codec giá trị (`ValueCodecs`, `ScalarCodec`) mà core khai báo ở `packages/core/src/ports/value-codecs.port.ts`. Đọc root `AGENTS.md` và `packages/core/AGENTS.md` trước; file này chỉ bổ sung phần riêng của package. Quyết định: `docs/decisions/0009-value-adapters-api-structure-and-audit-semantics.md`.

## Ranh giới

- Hướng phụ thuộc: `value-adapters → core` (chỉ type/port) và thư viện giá trị (Day.js). Core không import package này; composition root (`apps/api`, `tools`) chọn adapter.
- Chỉ codec giá trị thuần. Không mail/OIDC/DB/HTTP adapter, không NestJS/TypeORM/pg, không clock hệ thống (`now()`), không global mutable default.
- `normalize` trả `undefined` cho input sai; không trim, không NFC, không đoán timezone, không làm tròn. `compare` chỉ nhận giá trị đã normalize. Lỗi codec không bao giờ thành allow.
- Day.js dùng instance toàn cục (plugin `customParseFormat`, `utc` đăng ký trên đó). Runtime 1.11 nhận `dayjs.utc(text, fmt, 'en', true)` nhưng typings chỉ có 3 tham số nên không ghim locale bằng cast. Đường parse strict này chỉ dùng token số (`YYYY MM DD HH mm ss`) và Day.js 1.11 không gọi `preparse`/`postformat` ở đó; `test/value-codecs.spec.ts` có test khoá locale toàn cục có `postformat`. Host thêm plugin/locale Day.js khác phải chạy lại conformance; lỗi chỉ làm timestamp thành `undefined` (fail closed).
- Public API duy nhất qua `src/index.ts`: `createDayjsTimestampCodec`, `createStandardValueCodecs`.

## Bản đồ file

| File                              | Trách nhiệm                                                                                         |
| --------------------------------- | --------------------------------------------------------------------------------------------------- |
| `codecs/dayjs-timestamp.codec.ts` | Timestamp UTC strict (`YYYY-MM-DDTHH:mm:ss[.f{1..6}]Z`, năm 0001..9999); microsecond giữ dạng chuỗi |
| `codecs/standard-values.codec.ts` | int64, decimal, uuid, string, boolean + `createStandardValueCodecs` (đóng băng)                     |

## Test

- `test/value-codecs.spec.ts`; chạy `pnpm run test:unit -- packages/value-adapters/test/value-codecs.spec.ts`.
- Adapter mới (vd Moment) bắt buộc vượt cùng conformance cases timestamp (hàm nhận `ScalarCodec<string>`) trước khi dùng; không thêm adapter chưa có consumer.
- Giới hạn key 256 byte do core `parseKey` thực thi, không do codec `string`.
