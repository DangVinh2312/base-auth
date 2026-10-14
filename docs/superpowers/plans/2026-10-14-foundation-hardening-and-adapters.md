# Foundation Hardening, API Structure & Pluggable Adapters — Implementation Plan

> **Dành cho AI thực hiện:** triển khai từng task theo `superpowers:executing-plans` nếu skill có sẵn. Đây là tài liệu thiết kế và kế hoạch bàn giao trong **một file**, theo yêu cầu người dùng. Phiên tạo tài liệu không triển khai code. Không tự commit/push/deploy; không tự chia agent nếu người dùng chưa chọn cách làm đó.

**Goal:** sửa các vấn đề của review, tổ chức lại `apps/api` theo chức năng và chuyển xử lý scalar của core sang interface để thay adapter/thư viện mà không đổi ngữ nghĩa phân quyền.

**Architecture:** core giữ types, AST, validation cấu trúc và algebra; nhận các codec thuần qua factory có dependency injection tường minh. Package adapter cung cấp implementation, app composition root lựa chọn implementation. PostgreSQL tiếp tục sở hữu clock quyết định quyền, transaction/fence và enforcement SQL.

**Tech Stack:** TypeScript, Node theo `.nvmrc` và `engines` hiện tại (`>=24.15.0 <25`), pnpm theo `packageManager` (`12.3.4` khi viết), NestJS, TypeORM, PostgreSQL. Day.js là adapter thời gian đầu tiên được đề xuất; không cài đồng thời Moment chỉ để minh họa khả năng thay thế.

**Spec:** phần 1–5 của chính tài liệu này; đối chiếu `docs/authz-single-product-architecture.md`, `docs/permission-boundaries.md`, ADR 0005–0008. Nếu phát hiện bất đồng về invariant, ghi quyết định ADR trước thay đổi; không tự mở rộng quyền để làm test pass.

**Trạng thái ngày 2026-10-14:** phase A (T0–T7, T11) đã triển khai cục bộ trên nhánh `feat/foundation-hardening-adapters`, chưa commit; phase B (T8–T10) chưa thực hiện; checkbox phản ánh bằng chứng trong §6.

## 1. Phạm vi, nguồn sự thật và trạng thái đầu vào

### 1.1 Repo đích và các ràng buộc chung

- Repo duy nhất: `/Users/vinhdq2312/Documents/personal/base-auth`. Không thực hiện trên `base-auth-b2b` và không lấy code từ repo đó.
- `docs/prompt.md` là prompt lịch sử còn chỉ đến `base-auth-b2b`; **không thực thi lại prompt đó**. Yêu cầu hiện tại và tài liệu này xác định repo đích.
- Đọc root `AGENTS.md` và `AGENTS.md` từng module trước khi sửa. Giữ nguyên thay đổi của người dùng; kiểm tra lại working tree ngay trước task. Không reset/restore/stash hàng loạt.
- Chỉ pnpm, dependency đúng package sở hữu, version exact và lockfile được pnpm cập nhật. Không chọn `@latest`, không tự nâng stack, không thêm Moment/decimal/UUID library nếu chưa có consumer cần implementation đó.
- Giữ single-product, một DB, credentials riêng, `synchronize: false`, migrations tách khỏi boot. Không sửa migration đã áp dụng; migration mới dùng số kế tiếp thực tế, không mặc định `008`/`009` còn trống.
- Giữ policy AND boundary ngoài mọi allow; deny thắng; Root không bypass; user/session/context chỉ từ nguồn đã kiểm chứng.
- Không đổi paths/status/cookie/CSRF/OpenAPI của HTTP khi chỉ di chuyển code. Mọi thay contract phải có tests và cập nhật caller cùng task.
- Không network I/O, mail, sink delivery hoặc password hashing khi giữ application fence. Security facts thay đổi phải exclusive fence, revision/effect/audit cùng transaction.
- Không tạo generic plugin manager, service locator toàn cục, container DI trong core, microservice identity, cache allow hoặc phân vùng fence trong đợt này.
- Các phần vận hành phụ thuộc provider/SLO thật chỉ chặn task phụ thuộc; tiếp tục các task độc lập. Không ghi “production-ready” dựa trên local pass.

### 1.2 Cần kiểm chứng lại review, không sửa theo kết luận cũ một cách máy móc

| Mục review                                                          | Quan sát khi lập kế hoạch                                                                                                   | Công việc còn phải làm                                                                 |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Timestamp nhận ngày 30/2; `24:00:00` khác semantics PostgreSQL      | `core/src/expression.ts` vẫn dùng regex + `Date.parse`, trả lại phần ngày/giờ nguyên bản                                    | Regression tests, adapter strict và differential PostgreSQL                            |
| Drift CREATE ngoài `public`, trigger Root bị tắt                    | Source hiện đã bổ sung kiểm CREATE mọi schema, TEMP và `require_root_marker`; chưa chạy lại checks trong phiên lập kế hoạch | Đọc diff, test implementation hiện tại trước; chỉ sửa khoảng trống còn tồn tại         |
| System activation                                                   | Đã xuất hiện migration `008-system-activation.ts`, trigger và startup probe liên quan                                       | Giữ thay đổi mới, kiểm regression/protection đầy đủ; không ghi đè bằng phiên review cũ |
| Audit thiếu target và revision khác nghĩa                           | `ProductAuthorization.audit` không nhận target; identity audit dùng revision đầu transaction                                | Chốt schema event/semantics, bổ sung target và tests                                   |
| API tập trung vào `ProductController`, `ProductRuntime`, facade lớn | Controllers auth/domain/ops dùng chung một lớp; app configuration, lifecycle và composition tập trung                       | Tách theo capability, giữ bootstrap ordering và enforcement                            |
| Public package API rộng                                             | Root export runner/transaction manager/gateway/ops cạnh services                                                            | Tách entrypoints và hạn chế imports của handlers                                       |
| Facts I/O, count window, limiter, delivery/retention                | Cần đo và/hoặc hoàn thiện vận hành                                                                                          | Task giai đoạn B; không gọi tất cả là lỗi bảo mật đã khai thác                         |

Bằng chứng review trước: typecheck pass; unit 120/120 và E2E 1/1 pass; full integration 147/165 do 18 test cùng lỗi startup container, chạy riêng nhóm đó 18/18 pass. Source đã tiếp tục thay đổi sau review, nên các con số này là **lịch sử**, không chứng nhận HEAD/working tree hiện tại. Hai probe ở `/private/tmp` có thể mất; chuyển ca tái hiện vào tests trong repo, không phụ thuộc artifact tạm.

## 2. Quyết định thiết kế adapter

### 2.1 Cách tiếp cận được chọn

| Phương án                                                                       | Đánh đổi                                                                | Quyết định |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------- |
| Import Day.js/Moment trực tiếp vào core                                         | Ít bước ban đầu nhưng core phụ thuộc thư viện, khó thay implementation  | Không chọn |
| Core khai báo ports, composition root inject codecs; thư viện ở adapter package | Có thay đổi public API/callers nhưng rõ dependency, kiểm được semantics | **Chọn**   |
| Abstract mọi helper, regex, validator, crypto và runtime thành plugin framework | Nhiều cấu hình/abstraction không có consumer                            | Không chọn |

Interface là điểm thay implementation, không phải cơ chế làm input an toàn tự động. Một adapter sai vẫn có thể làm quyết định sai; contract tests, parser strict và SQL parity mới là bằng chứng. Adapter là trusted code đăng ký lúc boot; không chọn adapter từ payload hoặc runtime admin UI.

“Thay regex bằng adapter” được hiểu như sau: core không tự sở hữu thuật toán parse ngày/số/UUID bằng các regex rải rác; core gọi interface. Regex kiểm cú pháp tên AST, version/handler key hoặc SQL identifier vẫn được giữ ở nơi sở hữu grammar. Không xóa validation SQL/token/CSRF chỉ vì chúng dùng regex. Adapter được phép dùng thư viện hoặc kiểm tra cú pháp nhỏ khi cần, nhưng regex đơn lẻ không được coi là kiểm lịch hợp lệ.

### 2.2 Ports và cách inject

Tạo `packages/core/src/ports/value-codecs.ts` với contract hữu hạn, tương ứng các `FieldKind` hiện có:

```ts
export type Comparison = -1 | 0 | 1;

export interface ScalarCodec<T extends string | boolean> {
  normalize(input: unknown): T | undefined;
  compare(left: T, right: T): Comparison;
}

export interface ValueCodecs {
  readonly timestamp: ScalarCodec<string>;
  readonly integer: ScalarCodec<string>;
  readonly decimal: ScalarCodec<string>;
  readonly uuid: ScalarCodec<string>;
  readonly string: ScalarCodec<string>;
  readonly boolean: ScalarCodec<boolean>;
}
```

- `normalize` trả `undefined` cho input không hợp lệ; không tự lấy thời gian hiện tại, timezone máy, trim hoặc fallback parse lỏng.
- `compare` chỉ nhận giá trị đã normalize. Planner/evaluator vẫn bao error boundary: adapter throw/invalid return không được biến thành allow. Validation declarations trả lỗi cấu hình; boot thiếu codec phải fail trước listener.
- Boolean/UUID chỉ dùng equality theo grammar hiện tại; không mở `lt/lte` cho chúng chỉ vì interface có `compare`.
- Registry cố định sáu kinds; không thêm `registerKind(name, sqlCallback)` hay SQL type tùy ý.
- Copy/freeze bảng lựa chọn adapter khi tạo runtime; không có `setDefaultAdapter()`/mutable singleton. Adapter phải deterministic và không sửa semantics sau boot.

Tạo `packages/core/src/runtime.ts`, export `createAuthorizationCore({ values }: { readonly values: ValueCodecs }): AuthorizationCore`. `AuthorizationCore` cung cấp các method dưới đây, giữ argument/return contracts hiện hữu ngoại trừ receiver instance:

| Method                                                             | Contract                                                               |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `validate(declarations)`                                           | `SystemDeclarations -> ValidationResult`                               |
| `planUser(input, snapshot)` / `evaluateUser(plan, facts)`          | Các `User*` contracts hiện có                                          |
| `plan(input, snapshot)` / `evaluate(plan, facts)`                  | Legacy contracts hiện có, vẫn kiểm tenant thật                         |
| `normalizeValue(kind, input)` / `compareValues(kind, left, right)` | `FieldKind`, `Scalar`, `undefined` khi parse sai; comparison chính xác |
| `canonicalTimestamp(input)` / `canonicalInt64(input)`              | `unknown -> string                                                     | undefined`, delegate đúng codec |
| `parseKey(kind, input)`                                            | `KeyKind, unknown -> Key`, giữ lỗi input và giới hạn key               |
| `isCanonicalUuid(input)` / `parseTenantId(input)`                  | Canonical identity/tenant checks, không nới lowercase requirement      |

Types/AST/canonical JSON/`refKey`/`keyEquals`/constants tiếp tục là exports thuần. Hàm nào thực sự không dùng codec thì không chuyển thành instance method cho đủ bộ.

`isValidated` và provenance declarations cần được gắn đúng runtime: instance B không được âm thầm dùng declarations do instance A validate với bộ codecs khác. Dùng WeakSet/metadata nội bộ theo instance, không ghi adapter function/object vào canonical JSON hoặc manifest hash. PostgreSQL binding registry phải mang đúng `AuthorizationCore` của declarations; không chỉ sửa evaluator mà để validator/planner/gateway dùng bộ parse cũ.

Public API core thay đổi là chủ ý, vì các package đang private/0.0.0. Chuyển toàn bộ workspace callers trong cùng nhóm task, cả tools và legacy tests; không giữ một default engine toàn cục để che caller chưa migrate. Tạm thời giữ helper nội bộ trong lúc chuyển được, nhưng task không hoàn thành khi còn đường production dùng parser cũ. Nếu phát hiện consumer ngoài workspace, lập compatibility mapping cho consumer đó trước khi bỏ export.

### 2.3 Implementation adapters và dependency direction

Tạo `packages/value-adapters` (`@base-authorization/value-adapters`) chỉ chứa codec implementations và conformance tests. Không dùng package này làm nơi chứa mail/OIDC/DB adapters.

```text
apps/api composition + tools/product
  ├── core: createAuthorizationCore + types/ports
  ├── value-adapters: Day.js + native scalar implementations
  ├── typeorm-postgres: core ports, SQL, DB clock, transactions
  └── nest: guards/route inventory, không import value library

value-adapters ──type imports──> core
core ──X──> Day.js / Moment / Nest / TypeORM / value-adapters
```

Public functions của adapter package:

```ts
createDayjsTimestampCodec(): ScalarCodec<string>;
createStandardValueCodecs(options: {
  readonly timestamp: ScalarCodec<string>;
}): ValueCodecs;
```

Composition root chọn:

```ts
const core = createAuthorizationCore({
  values: createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
});
```

Moment hoặc thư viện khác về sau chỉ cần implement `ScalarCodec<string>` và vượt cùng conformance suite; không sửa planner/compiler và không đổi canonical format. Chỉ implement Day.js ở đợt này. Các scalar khác dùng implementation hiện có đã tách đúng nơi: BigInt cho int64, so decimal bằng chuỗi, Unicode/code-point semantics; không tự viết lại mọi thứ thành library mới.

Đăng ký runtime tường minh trong `prepareRelease(source, core)`, `prepareProductRelease(source, core)`, product/legacy binding registries và services cần normalization. Thêm argument `core` cho factory/constructor sở hữu các thao tác này; instance đi theo composition root, không lấy từ global import. Manifest declarations vẫn là dữ liệu; `createProductRelease(core)` thay constant release được prepare ngay lúc module import.

### 2.4 Contract timestamp bắt buộc

- Chỉ UTC dạng `YYYY-MM-DDTHH:mm:ss[.f{1..6}]Z`, năm `0001..9999`; output luôn sáu chữ số phần lẻ. Việc từ chối các ngày trước đây được parser nhận sai phải được ghi trong ADR.
- Từ chối ngày không tồn tại, tháng/ngày 0, giờ 24, giây 60, hơn sáu chữ số lẻ, offset `+07:00`, thiếu `Z`, whitespace và trailing junk. Không truncate/round hoặc chuyển timezone ngầm.
- Dùng Day.js `CustomParseFormat` strict và UTC để kiểm phần calendar đến giây. Giữ phần microsecond riêng dưới dạng chuỗi đã kiểm tra, rồi pad đủ sáu chữ số; không đi qua `Date`, `valueOf()` hay millisecond number cho so sánh chính xác.
- `.000001` phải khác `.000002`; `.123456` round-trip PostgreSQL không mất ba chữ số cuối. Comparison dùng canonical strings theo contract này.
- Không thêm `now()` vào codec. `statement_timestamp()` trong DB vẫn là authoritative clock; request `now`/deadline vẫn do trusted adapter cung cấp. Không dùng Day.js clock thay DB clock trong fence.
- Nếu Day.js strict có góc cạnh ở năm `0001`, `0099`, `0100`, sửa adapter theo round-trip contract và tests; không âm thầm thu hẹp thành `1900..9999`.

Day.js có strict parsing qua `CustomParseFormat`; parsing tokens được tài liệu mô tả tới millisecond (`SSS`). Vì vậy giữ microsecond ngoài đối tượng thư viện là quyết định của thiết kế này, không phải khẳng định Day.js tự hỗ trợ độ chính xác đó. Nguồn: [String + Format](https://day.js.org/docs/en/parse/string-format), [UTC plugin](https://day.js.org/docs/en/plugin/utc).

Moment là lựa chọn có thể cắm qua cùng port khi consumer cần; không chọn làm dependency mặc định mới do trạng thái maintenance được dự án công bố: [Moment project status](https://momentjs.com/docs/#/-project-status/).

### 2.5 Các port khác: cái nào cần ngay, cái nào giữ nguyên

| Capability                          | Quyết định                                                                                                                                                               |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Integer/decimal/UUID/string/boolean | Đưa vào `ValueCodecs`, giữ exact semantics và thư viện thay thế phải pass cùng tests                                                                                     |
| Password hashing                    | Giữ `ProductPasswordHasher` đã có và Argon2 implementation; không thêm wrapper trùng trách nhiệm                                                                         |
| OIDC                                | Giữ adapter protocol hiện có, không tự viết JWT validator; chưa tổng quát hóa federation engine                                                                          |
| Session projection cho AuthZ        | Tách port nội bộ adapter khi tổ chức lại service; implementation PostgreSQL resolve session trong cùng fenced transaction, không HTTP call                               |
| Obligations                         | Dùng typed registry handler giống pattern `fulfillObligations`; đăng ký `audit@1` thực, không hardcode duy nhất handler trong generic access loop                        |
| Email input                         | Thuộc identity/HTTP, không thêm email `FieldKind` vào core. Nếu thay thư viện validation, giữ login canonicalization không bỏ dots/plus; không đổi identity mapping ngầm |
| Recovery delivery/audit sink        | Giữ/tạo port đúng mục đích ở task vận hành; provider chưa cấu hình vẫn unavailable                                                                                       |
| Random/crypto/hash manifest         | Giữ `node:crypto` trong adapter, không dùng injectable random tùy ý trong production chỉ để test dễ hơn                                                                  |

## 3. Cấu trúc đích của `apps/api`

Tách theo capability và ownership. Không tạo service chỉ forward một method, không áp dụng CQRS/repository/base-controller hàng loạt.

```text
apps/api/src/
  main.ts                         # load config, create Nest app, listen/shutdown
  app.module.ts                   # module composition, không query DB
  config/
    app.config.ts                 # env parsing hiện tại, secret-safe errors
  infrastructure/
    runtime.module.ts             # giữ providers đặc quyền private, export facade tokens
    product-runtime.ts            # pools, bootstrap sequence, cleanup; codec composition
    http-security.ts              # cookie, Origin/CSRF, shared bounded body validation
    product-error.filter.ts       # mapping lỗi và safe logging
  auth/
    auth.module.ts
    auth.controller.ts            # csrf, local activation/login/session/password/recovery/logout
    oidc.controller.ts            # begin/callback/link/unlink/activation/reauthentication
    auth.http-port.ts             # token + Pick các operations auth, không transactions
  documents/
    documents.module.ts
    documents.controller.ts       # list/detail/title update
    documents.http-port.ts        # token + operations domain đã bind resource/action
    document.declarations.ts      # declaration/binding fragment, không tự prepare release
    migrations/
      product-document.ts         # move class cũ, giữ name/timestamp/schema
  administration/
    administration.module.ts
    users.controller.ts           # suspend qua trusted command
    administration.http-port.ts
    account.declarations.ts
  health/
    health.module.ts
    health.controller.ts          # live/ready/metrics
    product-metrics.ts
  authorization/
    product-manifest.ts           # compose fragments + createProductRelease(core)
  openapi/
    openapi.controller.ts
    product-openapi.ts            # một document hiện tại; chưa thêm generator
```

- Giữ module boundary thật: chỉ `RuntimeModule` sở hữu/inject được runtime/pools; module khác chỉ nhận facade token. Không dùng `@Global()` cho raw runtime, không export `ProductRuntime` provider ra feature modules.
- Facade dùng operations bound từ service hiện có, không để controller chọn tùy ý resource/action trong body. Không cần thêm lớp service mỗi controller nếu không có orchestration riêng.
- `AppModule.register` vẫn có cách dựng bằng fixture runtime cho E2E. Instance readiness dùng chung và chỉ ready sau privilege probe + manifest sync + domain checks; thiếu classification hoặc bootstrap lỗi phải fail trước listen.
- Giữ toàn bộ DTO/body validation, cookie options, errors, `HttpCode`, decorator classifications và success shape khi move. OpenAPI giữ URL hiện hữu.
- `apps/api/src/audit/audit-outbox.service.ts` đang là adapter legacy, có test caller. Đưa về `apps/api/src/legacy/audit-outbox.service.ts` và sửa test import; không xóa như dead code hoặc wire nó vào product runtime.
- Mỗi lần move phải tìm imports cả `src`, `dist` paths trong tests, CLI, fixtures, tsconfig, scripts và docs. Không tạo nhiều file re-export ở đường dẫn cũ để che migration chưa xong.

## 4. Các quyết định hardening đi kèm

### 4.1 Audit

Giữ `policy_revision` với nghĩa **revision dùng để đánh giá quyền**. Event mutation có `resultingRevision` dạng string trong metadata allowlist để ghi revision sau commit; thay đổi nghĩa so với một số writer hiện tại phải ghi ADR, không rewrite audit lịch sử. Với read, không cần `resultingRevision`; với revoke/admin/bootstrap là `tx.revision + 1`, với sync lấy revision thực reconciler công bố.

`account.suspend` cần target user ID; `data.update` cần resource + typed key, hoặc object ID nếu đã có. Không giả vờ target user là actor. Giữ token/password/email/title/reason tùy ý khỏi metadata. Event helper có typed input, không nhận arbitrary metadata từ HTTP. Giữ effect và audit nguyên tử; lỗi audit rollback effect. Các event “access” và “mutation” nếu giữ cả hai phải có tên/mục đích khác nhau và test số lượng, không nhân bản vô tình khi move code.

### 4.2 Public API và extensions

Tách `typeorm-postgres` thành public entrypoints `.` (safe service contracts), `./composition` (constructors/wiring), `./operations` (offline migration/bootstrap/provision), `./legacy` (compatibility). Đây là ranh giới cho developer, không là sandbox chống process compromise. Root không re-export lại toàn bộ nội dung đặc quyền.

Controller chỉ import facade token/types và Nest decorators. ESLint chặn `typeorm`, driver, composition/operations/legacy, runtime provider và private source import trong feature handlers. CLI được import operations; `infrastructure` được import composition. Core contract exports vẫn qua `src/index.ts`.

Generic data update hiện chỉ phù hợp field không thay authority. Không đăng ký owner/team/rank/boundary/grant thành writable field cho tiện; các thao tác đó cần typed admin command với exclusive fence và affected-set/delegation proof. Generic administration chưa nằm trong phần sửa bắt buộc của kế hoạch này.

## 5. Review focus và thứ tự thực hiện

Năm nhóm input/điều kiện dễ bị bỏ sót phải có tests ở task sở hữu:

1. Timestamp calendar overflow, năm dưới 100, microsecond và timezone máy khác UTC: T1–T2.
2. Hai core instance dùng hai adapter khác nhau, adapter throw hoặc thiếu codec: T2–T3.
3. Drift của protection mới thêm trong migration 008 và privileges ngoài `public`: T4.
4. Controller bị move mất classification/CSRF hoặc có thể inject runtime đặc quyền: T6–T7.
5. Crash/retry giữa effect, audit và delivery; không đánh dấu delivered trước acknowledgement: T5 và T10.

**Giai đoạn A — bắt buộc để hoàn tất refactor/hardening:** T0–T7, sau đó T11 verification. **Giai đoạn B — vận hành/tối ưu:** T8–T10 với các gate ghi rõ, rồi chạy lại checks liên quan. Không tự thực hiện platform publishing/generic admin như phần mở rộng ngầm.

### T0 — Chốt baseline, ADR và phạm vi đang có thay đổi

**Files:** đọc toàn bộ `AGENTS.md` liên quan, các source trong bảng mục 1.2; cập nhật ledger cuối file này. Khi triển khai, tạo ADR tiếp theo chưa được dùng trong `docs/decisions/` cho value adapter contracts, API migration và audit semantics.

- [x] Đọc `git status --short`, diff liên quan và source migration mới nhất; ghi file đã được người dùng sửa, task đã được người khác xử lý, không suy luận từ review cũ.
- [x] Chạy `node --version`, `pnpm --version`, `pnpm run typecheck`, `pnpm run test:unit`; ghi output thật. Docker lỗi thì phân biệt fixture startup với assertion failure.
- [x] Ghi ADR theo quyết định mục 2–4, gồm strict timestamp domain, microseconds, engine identity, public API breaking change nội bộ và audit revision. Không đổi contract DB clock/Root/fence.
- [x] Kiểm kê mọi caller bằng `rg` cho `canonicalTimestamp|normalizeValue|compareValues|parseKey|canonicalInt64|isCanonicalUuid|parseTenantId|planUser|evaluateUser|prepareRelease|prepareProductRelease|ProductBindingRegistry`; gồm legacy, tools và tests.

**Acceptance:** baseline và dependency map rõ; các task dưới được điều chỉnh theo source mới, chưa có checkbox implementation nào đánh dấu bằng chứng lịch sử.

### T1 — Ports và adapter thời gian/scalar có contract tests

**Create:** `packages/core/src/ports/value-codecs.ts`; `packages/value-adapters/{AGENTS.md,package.json,tsconfig.json}`; `src/index.ts`, `src/dayjs-timestamp.ts`, `src/standard-values.ts`, `test/value-codecs.spec.ts` trong package mới.

**Modify:** core `src/index.ts`; root `tsconfig.build.json`, package manifests cần dependency direct, `pnpm-lock.yaml` qua pnpm. `pnpm-workspace.yaml` đã có `packages/*`, không thêm glob trùng.

**Interfaces:** `ScalarCodec`, `ValueCodecs`, `createDayjsTimestampCodec`, `createStandardValueCodecs` đúng mục 2. Dependencies runtime của package mới chỉ core (`workspace:*`) và Day.js version exact được kiểm tra khi triển khai; core source không phụ thuộc adapter.

- [x] Viết conformance tests trước implementation: invalid date `2026-02-30`, valid leap `2024-02-29`, invalid leap `2025-02-29`, `24:00`, leap second, thiếu Z, offset, 7 fractional digits; năm `0001/0099/0100/9999` round-trip.
- [x] Assert `normalize('2026-10-14T00:00:00.1Z') === '2026-10-14T00:00:00.100000Z'`, `.000001 < .000002`, invalid inputs trả `undefined`; chạy tests và ghi failure đúng nguyên nhân.
- [x] Implement Day.js strict UTC calendar validation + microsecond preservation. Kiểm tra APIs/version từ nguồn chính thức; không serialize Day.js object qua port.
- [x] Tách implementation scalar đang có: int64 string/bigint, từ chối JS number; decimal không qua floating point, `10.0` bằng `10.00` khi compare nhưng không đổi literal trong manifest; UUID normalize lowercase nhưng canonical identity check vẫn từ chối uppercase; Unicode không trim/NFC hóa tự động.
- [x] Test int64 min/max và ngoài biên; decimal lớn/với scale khác nhau/âm/negative zero; UUID malformed; lone surrogate; key text giới hạn 256 UTF-8 bytes vẫn do core key contract thực thi.
- [x] Run `pnpm run test:unit -- packages/value-adapters/test/value-codecs.spec.ts` và `pnpm run typecheck`. Kiểm package ESM/declaration output thật.

**Acceptance:** adapter thật có tests; chưa tuyên bố core hết dùng parser cũ cho tới T2–T3.

### T2 — Core dùng instance có injected codecs, không mutable default

**Create:** `packages/core/src/runtime.ts`, `packages/core/test/runtime.spec.ts`.

**Modify:** `core/src/{expression,key-codec,types,policy-validator,planner,evaluator,index}.ts`, `core/test/*.spec.ts`, `core/test/fixtures.ts`, `core/AGENTS.md`; tất cả production callers được nối tiếp trong T3 trước khi kết thúc nhóm này.

**Interfaces:** factory và runtime methods mục 2.2; giữ types/AST output hiện có. Validation/planning/evaluation cùng instance, delegates đến codecs; không copy một planner thứ hai cho adapter mới.

- [x] Viết tests instance A/B độc lập, declarations provenance, missing codec, codec throw và parser permissive bị conformance suite phát hiện. Chạy và xác nhận red.
- [x] Factory capture bộ codecs, chuyển normalization/comparison trong validator/planner/evaluator/key helpers vào dependency instance. Giữ fail-closed catch, max rules/path/nodes và deny-null semantics.
- [x] Test seam bằng codec spy có input valid: xác nhận validator/planner/evaluator/gateway path thực sự gọi adapter, không có regex/Date.parse fallback âm thầm.
- [x] Test core import không tải Day.js/Moment/Nest/TypeORM; core không có production dependency. Nếu core tests dùng adapter thật, khai báo devDependency explicit; không thêm TS production reference từ core sang adapter hoặc tạo production dependency cycle.
- [x] Chuyển tests hiện hữu sang core instance; giữ cả tenant compatibility assertions. Không xóa suite vì signature thay đổi.
- [x] Run `pnpm run test:unit -- packages/core/test` và `pnpm run typecheck` khi callers ở T3 đã chuyển. Có thể chia edits T2/T3 nội bộ, nhưng không bàn giao workspace đang không build.

**Acceptance:** một algebra, một bộ value semantics cho mỗi runtime; không còn public default parser/engine cũ được production gọi.

### T3 — Nối adapters xuyên PostgreSQL, manifest, CLI và fixtures

**Modify:** `typeorm-postgres/src/{manifest-reconciler,product-manifest,sql-compiler,product-sql,data-gateway,product-gateway,product-authority,product-identity,product-oidc,authority-store,tenant-transaction,datasource-registry,tenant-provisioner,index}.ts` khi có caller; `apps/api/src/product-runtime.ts`, `product-manifest.ts`; `tools/{product,provision,migrate}.ts`; root/test/package fixtures và TS references/package manifests liên quan.

**Create:** `test/product-values.integration-spec.ts`.

**Interfaces:** release preparation nhận `core`; binding registry giữ `core` và declarations đã validate bởi instance đó; CLI và API inject adapter giống nhau. Pure SQL compilation không tự gọi clock/library khác để sửa semantics plan.

- [x] Viết regression PostgreSQL cho timestamp literals/fields, deny, expiry và boundary; so IDs của query SQL với `evaluateUser` trên cùng facts và timestamp DB.
- [x] Với input không hợp lệ, assert bị từ chối trước SQL; không đòi SQL parse ngày 30/2 thành giá trị hợp lệ. Với `.123456`, assert DB output giữ nguyên cả sáu digits.
- [x] Wire instance qua mọi caller vừa liệt kê bằng `rg`; release source giữ data-only, không thêm adapter name/function vào hash. Manifest hợp lệ trước đó giữ hash trừ thay đổi dữ liệu có chủ ý được ADR cho phép.
- [x] Test API và CLI dùng cùng adapter; không có lệch boot validation với request evaluation. Giữ native PK binds và decimal SQL types.
- [x] Run `pnpm run test:unit`, `pnpm run test:integration -- test/product-values.integration-spec.ts test/product-authorization.integration-spec.ts test/compiler.integration-spec.ts test/permission-boundary.integration-spec.ts`, `pnpm run typecheck` và `pnpm run build`.

**Acceptance:** đổi codec implementation không cần sửa planner/compiler; không mất precision và không còn caller cũ trốn dưới default singleton.

### T4 — Hoàn thiện và kiểm chứng DB protection drift hiện tại

**Modify:** `packages/typeorm-postgres/src/product-database.ts`, `test/product-database.integration-spec.ts`, `test/product-system-regression.integration-spec.ts`; chỉ tạo forward migration nếu thay enforcement/schema thực sự. Đọc migration 004–008 hiện hữu, không sửa chúng.

- [x] Kiểm tra bản hiện tại đã reject CREATE ngoài public, TEMP và disabled Root trigger hay chưa; viết tests trước, phân biệt “đã pass nhờ sửa có sẵn” với lỗi mới.
- [x] Test mỗi runtime login với direct/PUBLIC grant CREATE schema, database TEMP/CREATE, grant option, role membership; fixtures thực hiện grant bằng admin disposable, probe bằng runtime credentials.
- [x] Test disabled/missing/miswired `require_root_marker` và `protect_system_activation`, wrong function/table/deferrability. Kiểm inventory đầy đủ, không chỉ tổng số trigger trùng tên.
- [x] Nếu probe chưa bao phủ owner/ACL/search_path của security-definer mới `protect_system_activation`, bổ sung exact expected protection và negative tests; không chỉ kiểm hai functions cũ.
- [x] Run `pnpm run test:integration -- test/product-database.integration-spec.ts test/product-system-regression.integration-spec.ts test/product-system.integration-spec.ts`.

**Acceptance:** regression đủ cho source mới; lỗi probe ngăn startup. Không tạo migration trùng hoặc “sửa lại” phần người dùng vừa hoàn thành.

### T5 — Audit contract rõ target/revision, obligations qua typed registry

**Create:** `packages/typeorm-postgres/src/product-audit.ts`, `packages/typeorm-postgres/src/product-obligations.ts`, `test/product-audit.integration-spec.ts`.

**Modify:** product authority/identity/OIDC/manifest writers, typed registry wiring ở API runtime, tests hiện hữu, ADR/operations docs.

**Interfaces:** `ProductObligationHandler = (tx: ProductTransaction, plan: UserAuthorizedPlan) => Promise<void>`; registry nội bộ `Readonly<Record<string, ProductObligationHandler>>`. Handler không export cho controller. Audit helper nhận actor, kind, target typed và evaluated/resulting revision theo mục 4.1; không raw HTTP metadata.

- [x] Test suspend ghi đúng actor và target khác nhau; update ghi resource/key đúng; read revision giữ nguyên; revoke/admin ghi evaluated revision R và resulting R+1; transaction rollback không để event/effect.
- [x] Test registry thiếu handler hoặc handler throw thì deny/rollback. `audit@1` được đăng ký thật; thêm test handler độc lập trong fixture chứng minh thay implementation không sửa generic access loop.
- [x] Implement audit helper chung cho product writers; không tái sử dụng helper tenant với tenant giả. Không rewrite historical events; ghi rõ mốc semantics mới.
- [x] Run `pnpm run test:integration -- test/product-audit.integration-spec.ts test/product-authorization.integration-spec.ts test/product-identity.integration-spec.ts test/product-system.integration-spec.ts`.

**Acceptance:** truy được actor/target/revision, không token/PII, failure không release payload. Audit sink delivery vẫn thuộc T10.

### T6 — Tổ chức lại API theo chức năng, giữ behavior

**Files:** tạo/move đúng cây mục 3; bỏ `product.controller.ts` và facade lớn cũ sau khi chuyển xong callers. Sửa `apps/api/test/product.e2e-spec.ts`, `test/product-http.spec.ts`, `test/workspace.smoke-spec.ts`, `test/obligations.integration-spec.ts`, `tools/product.ts` và mọi direct imports phát hiện được.

- [x] Chụp inventory method/path/status/classification/OpenAPI và facade exposure bằng test trước khi move. Bổ sung assertion thiếu classification fail boot, cookie/CSRF giữ nguyên, absent/hidden cùng 404.
- [x] Move config/security/error/metrics theo ownership; tách auth/OIDC/documents/admin/health/OpenAPI controllers. Dùng bound operations/facade, không tạo forwarding services không cần thiết.
- [x] Tách declaration fragments và `createProductRelease(core)`; runtime/CLI cùng compose một manifest. Move domain migration class nhưng giữ tên và timestamp để DB không chạy lại migration cũ.
- [x] Đưa pools/runtime provider vào infrastructure module private; feature module chỉ import các token được export. Bootstrap vẫn hoàn tất trước listener và worker; shutdown cleanup idempotent, startup thất bại không leak pools.
- [x] Test một provider trong feature module cố inject raw runtime không resolve được; facade runtime object không có `transactions`, `manager`, `pools`, DB URLs hoặc offline commands. Kiểm behavioral DI, không chỉ TypeScript `Pick`.
- [x] Di chuyển legacy audit helper và sửa test imports, không xóa historical suite.
- [x] Run `pnpm run typecheck`, `pnpm run test:unit -- test/product-http.spec.ts test/workspace.smoke-spec.ts packages/nest/test`, `pnpm run test:e2e`.

**Acceptance:** HTTP behavior không đổi; cây file phản ánh chức năng; core/authz logic không bị chuyển vào controllers.

### T7 — Public exports và import boundaries cho developer

**Create:** `packages/typeorm-postgres/src/{composition,operations,legacy}.ts`, `test/package-boundaries.spec.ts`.

**Modify:** adapter `package.json#exports`, `src/index.ts`, `eslint.config.js`, callers trong API/CLI/tests, package/module AGENTS và README.

- [x] Test root exports không chứa raw transaction/runner, provision/bootstrap/migration entrypoints; các subpath chính thức build/import được với `.d.ts` tương ứng.
- [x] Root giữ service types/errors và facade-safe contracts; composition sở hữu constructors/low-level adapters, operations sở hữu offline capability, legacy giữ historical APIs. Không re-export credentials/pools thực từ facade.
- [x] Thêm lint restrictions cho feature controllers; viết negative fixture/assert qua ESLint cho imports `typeorm`, adapter `composition/operations/legacy`, runtime và private source. Đừng chặn infrastructure/CLI hợp lệ.
- [x] Cập nhật trực tiếp mọi import; không dựa hoisting/private `dist` path ở application code. Tests low-level có thể dùng entrypoint composition/legacy được chỉ định.
- [x] Run `pnpm run lint`, `pnpm run typecheck`, `pnpm run build`, `pnpm run test:unit -- test/package-boundaries.spec.ts test/workspace.smoke-spec.ts` và `pnpm run test:e2e`.

**Acceptance:** đường mặc định của developer là facade; các lối đặc quyền được phân loại/lint rõ. Không tuyên bố đây là process isolation.

### T8 — Giảm I/O trong fence bằng số đo, giữ semantics

**Files:** `product-authority.ts`, `product-gateway.ts`, `product-transaction.ts`, `test/product-authorization.integration-spec.ts`, `test/product-load.integration-spec.ts`; metric file sau T6; cập nhật `docs/single-product-load-results.md`.

- [x] Đo baseline số query, latency và lock wait/hold cho HTTP list/detail/update và revoke trên fixture; ghi row count, số permissions/rules, replicas/workers và hardware.
- [x] Lọc catalog/rules/boundaries theo permission đang dùng trong `readProductAuthority`; giữ user/roles và fail-closed cho rule malformed thuộc permission đó. Không bỏ deny để tiết kiệm query.
- [x] Test parity trước/sau với nhiều permissions, direct/role deny, required boundary thiếu binding và revoke racing read. Tối ưu facts statements sau khi lấy fence; không `Promise.all` trên cùng QueryRunner như một tối ưu giả.
- [x] Kiểm `count(*) OVER()`/empty-page fallback bằng EXPLAIN và concurrent domain writes. Nếu cần đổi contract total hoặc pagination, ghi ADR/API contract riêng; không tự đổi response hiện có trong task performance.
- [x] Run targeted integration, benchmark cùng điều kiện trước/sau; không kết luận cần partition fence chỉ từ fixture 100 rows. Chưa có SLO thật thì báo số đo, không tự đặt production capacity.

**Acceptance:** ít I/O hơn hoặc chứng minh chưa đáng đổi; đúng semantics. Không thêm cache allow, không bỏ recheck trong fenced service.

### T9 — Limiter, session activity và resource bounds

**Files:** `product-identity.ts`, runtime configuration sau T6, `test/product-identity.integration-spec.ts`, `test/product-load.integration-spec.ts`, operations docs; forward migration nếu thật sự cần index/retention support.

- [ ] Thêm test mô phỏng nhiều user hợp lệ chung NAT và nhiều replica cùng login; đo advisory-lock wait khi revoke diễn ra. Phân biệt IP/network limit với account failure counter.
- [ ] Chốt threshold/window từ use case deployment trước khi thay policy; không bỏ limiter, không reset account failure bucket bằng login giả, không làm lộ account qua response. Nếu thiếu yêu cầu tải, giữ policy hiện tại, ghi giới hạn thay vì tự chọn ngưỡng mới.
- [ ] Ghi rõ data-only request không touch idle. Nếu thay behavior, dùng identity capability hẹp và throttled touch, recheck expiry trong fence; data credential không được quyền UPDATE session tùy ý. Test request liên tục/idle/absolute-expiry/revoke races.
- [ ] Thiết kế cleanup theo batch cho expired sessions/tokens, giữ retention được yêu cầu, không full-table cleanup trên mọi login. Test không xóa live token/session hoặc phá concurrent reset.

**Acceptance:** không giải quyết contention bằng nới bảo mật. Thay limiter/session semantics cần ADR và updated contract tests; task policy chưa đủ thông tin không cản T0–T8.

### T10 — Durable audit/recovery delivery (giai đoạn vận hành riêng)

**Create khi task được triển khai:** `packages/typeorm-postgres/src/product-outbox.ts`, forward migration cho lease/retry nếu schema hiện tại thiếu; `apps/api/src/audit/audit-worker.ts`, `test/product-outbox.integration-spec.ts`. Chọn provider qua port đã có, không hardcode vendor mới.

**Modify:** credential matrix/probes, composition/config, recovery request operation/controller sau T6, operations docs.

- [ ] Audit sink port nhận event với `eventId`; sink phải deduplicate. Worker claim batch bằng lease/`SKIP LOCKED` trong transaction ngắn, release transaction rồi mới network delivery; acknowledge trong transaction khác. Không giữ authz fence lúc gọi sink.
- [ ] Test crash trước send, sau send trước ack, lease hết hạn, hai workers, retry có giới hạn/backoff và poison event; duplicate delivery được dự kiến và sink idempotent. Không hứa exactly-once network delivery.
- [ ] Recovery không ghi plaintext reset token vào `audit_outbox`. Trước triển khai durable recovery, chốt kênh delivery và lưu trữ payload nhạy cảm (mã hóa + key ownership + TTL + ACL); chưa có provider/key management thì giữ 503 và ghi blocked riêng phần này.
- [ ] Cấp worker quyền tối thiểu vào outbox, không migration/bootstrap credentials, không SELECT credential/session tables. Nếu thêm login purpose phải có ADR/migration/probe bằng login thật và không inject vào controller.
- [ ] Test atomic creation của token + delivery job, process restart không mất job, expiry không gửi token cũ; response không khác nhau theo account tồn tại và không chứa token.
- [ ] Run `pnpm run test:integration -- test/product-outbox.integration-spec.ts test/product-database.integration-spec.ts` và relevant HTTP E2E.

**Acceptance:** audit delivery có crash/retry proof; recovery delivery chỉ hoàn tất khi provider/secret-storage gate được giải quyết. Không tạo fake provider trả success để đánh dấu task xong.

### T11 — Regression gate, tài liệu và bàn giao

**Files:** tài liệu này, README, AGENTS của module đã đổi, `docs/single-product-operations.md`, `docs/single-product-verification.md`, `docs/single-product-reuse-map.md`, ADR mới; CI chỉ đổi khi có nhu cầu/tool thật.

- [x] Chạy `pnpm install --frozen-lockfile`, `pnpm run format:check`, `pnpm run lint`, `pnpm run typecheck`, `pnpm run build`, `pnpm run test:unit`, `pnpm run test:integration`, `pnpm run test:e2e`.
- [x] Nếu Testcontainers startup timeout, ghi suite failure đúng nguyên nhân và chạy nhóm bị ảnh hưởng riêng; không ghi full-suite pass khi chỉ targeted rerun pass. Không tăng application timeout để che Docker startup.
- [x] Mutation-check trên checkout/fixture cô lập: bỏ boundary conjunct, bypass Root, bỏ fence và dùng timestamp adapter truncate microseconds phải làm behavioral tests fail. Không mutate working tree có thay đổi người dùng; khôi phục fixture sau check.
- [x] Hướng dẫn copy/paste composition dùng Day.js adapter, viết adapter thay thế cùng interface và chạy conformance; thêm walkthrough một resource từ declaration → migration/privileges → binding → route → tests.
- [x] Ghi public API migration map, package dependency graph, bootstrap order, legacy status và capability còn chưa triển khai. Không quảng cáo delegation/generic admin/resource-to-resource domain binding đã có nếu chưa làm.
- [x] Kiểm toàn bộ changed files thuộc phạm vi, source không còn imports/parser fallback cũ, không secret trong logs/docs. Cập nhật ledger từng task với lệnh và kết quả thực.

**Acceptance:** giai đoạn A hoàn tất chỉ khi T0–T7 và các checks tương ứng ở T11 pass; T8–T10 có trạng thái riêng, không được tick hộ. Không commit/push/publish/deploy nếu chưa có yêu cầu riêng.

## 6. Ledger cho AI thực hiện

| Task                 | Trạng thái                    | Lệnh/bằng chứng mới                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Rủi ro hoặc gate còn lại                                                                                                                                                                                                                                                                     |
| -------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T0 baseline/ADR      | Hoàn tất (2026-10-14)         | `node --version` v24.20.0, `pnpm --version` 12.3.4, `pnpm run typecheck` exit 0, `pnpm run test:unit` 120/120 (baseline trước thay đổi); ADR 0009; kiểm kê caller `rg` 289 match. Review clean                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Integration/E2E không chạy ở baseline; số 147/165 chỉ là lịch sử                                                                                                                                                                                                                             |
| T1 value adapters    | Hoàn tất (2026-10-14)         | RED rồi GREEN `pnpm run test:unit -- packages/value-adapters/test/value-codecs.spec.ts` 61/61; `pnpm run test:unit` 181/181; typecheck/lint 0; dayjs 1.11.23 exact. Review clean                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Conformance cases nằm trong spec file, phải copy/promote cho adapter thứ hai; chưa có case `0400-02-29`/`0300-02-29`/`0099-02-29`                                                                                                                                                            |
| T2 core DI           | Hoàn tất cùng T3 (2026-10-14) | RED `runtime.spec.ts` (thiếu export `createAuthorizationCore`); `pnpm run test:unit -- packages/core/test packages/value-adapters/test` xanh; `pnpm run test:unit` 199/199; typecheck/build/lint 0. Review Approved + 1 fix round (lowercase UUID tại core, `validate` trả `ValidationResult`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `product-authority` còn `Date.parse` cho freshness 300s (số học clock DB, không phải validation); gateway/compile công khai không kiểm provenance plan                                                                                                                                       |
| T3 end-to-end wiring | Hoàn tất cùng T2 (2026-10-14) | `pnpm run test:integration -- test/product-values.integration-spec.ts test/product-authorization.integration-spec.ts test/compiler.integration-spec.ts test/permission-boundary.integration-spec.ts` 58/58; full integration 171/171 (trước fix) và 17/17 targeted sau fix; `pnpm run test:e2e` 1/1; hash manifest giữ nguyên                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `tools/provision.ts` (legacy) ghép codec riêng; lỗi codec vẫn nhãn chung "value codec failure" (fail closed)                                                                                                                                                                                 |
| T4 protection drift  | Hoàn tất (2026-10-14)         | `pnpm run test:integration -- test/product-database.integration-spec.ts test/product-system-regression.integration-spec.ts test/product-system.integration-spec.ts` 36/36; thêm kiểm USAGE/CONNECT WITH GRANT OPTION (2 khoảng trống thật); typecheck/lint 0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Test `rejectsDrift` chưa ghim thông điệp cụ thể cho các case mới; owner-hardening gắn với owner `resolve_session`/fence                                                                                                                                                                      |
| T5 audit/obligations | Hoàn tất (2026-10-14)         | `pnpm run test:integration -- test/product-audit.integration-spec.ts test/product-authorization.integration-spec.ts test/product-identity.integration-spec.ts test/product-system.integration-spec.ts test/product-cli.integration-spec.ts` 35/35 sau fix round 1 (actor offline, string key không vào metadata); unit 199/199; e2e 1/1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Sink delivery thuộc T10; handler throw trả 500 (fail closed); chưa test trực tiếp audit của `root.reissue`                                                                                                                                                                                   |
| T6 API structure     | Hoàn tất (2026-10-14)         | `pnpm run test:unit` 206/206 (gồm `apps/api/test/structure.spec.ts`: 24 route, OpenAPI hash, DI hành vi, bootstrap fail trước listen); `pnpm run test:e2e` 1/1; integration 19/19 + 22/22 file chạm; typecheck/lint/build 0. 1 fix round: route inventory chuyển sang `onModuleInit`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `ReadinessGate` trong `HealthController` còn lộ `markReady`; `ModuleRef.get(strict:false)` là escape hatch của Nest, chỉ ESLint chặn                                                                                                                                                         |
| T7 public API        | Hoàn tất (2026-10-14)         | `pnpm run lint`, `typecheck`, `build` exit 0; `pnpm run test:unit` 227/227 (boundaries 21/21); full integration 184/184 và e2e 1/1 (trước fix round, chạy lại trong T11). Fix round: glob ESLint đệ quy, prettier 9 file                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Root còn re-export `TransactionConflictError`/`ReleaseRejectedError` từ module legacy; `openid-client`/`argon2` chưa bị chặn trong feature folders                                                                                                                                           |
| T8 I/O               | Hoàn tất (2026-10-14, local)  | Benchmark mới `test/product-fence-io.integration-spec.ts` (đường service sau HTTP: list/detail/update + revoke/logout; 10 000 dòng, 40 permissions, 80 rules, 40 boundaries; 1 replica, 8 worker; i5-1038NG7, Docker 8 CPU/7.75 GiB) chạy riêng 3 lần trước/3 lần sau: statement list/detail 13→8, update 15→10, revoke 10→10; p50 list ~27→21 ms, detail ~14→10, update ~19→11; workload trộn elapsed ~4.1→2.6 s, lock wait p95 ~337→169 ms (chi tiết `docs/single-product-load-results.md`). RED: authority trả cả `item.update` khi hỏi `item.read`; trang rỗng trả `total` '3' thay vì '2' khi có insert đồng thời; số statement 13/13/15. GREEN: `pnpm run test:integration -- test/product-authorization.integration-spec.ts test/product-values.integration-spec.ts test/product-fence-io.integration-spec.ts` 13/13 (sau thêm ca role deny: authorization 9/9). Thay đổi: `readProductAuthority(tx, userId, permission, …)` một statement chỉ facts của permission; clock gộp vào statement session; list trang + total một statement | HTTP (gồm transaction `checkSession` của guard) chưa đo; câu list mới chậm hơn ~0.7 ms/statement (full sort thay top-N) để total cùng snapshot; total chính xác vẫn quét mọi dòng khớp — đổi sang keyset/ước lượng cần ADR; không có SLO thật, không kết luận năng lực production/chia fence |
| T9 limiter/session   | Chưa thực hiện                | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Deployment policy/tải thật                                                                                                                                                                                                                                                                   |
| T10 delivery         | Chưa thực hiện                | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Provider, secret storage, retention                                                                                                                                                                                                                                                          |
| T11 verification     | Hoàn tất (2026-10-14, local)  | Chạy từ root trên working tree chưa commit: `pnpm install --frozen-lockfile` exit 0 (lockfile không đổi); `pnpm run lint`/`typecheck`/`build` exit 0; `pnpm run test:unit` 227/227; `pnpm run test:integration` 184/184 (không timeout Testcontainers); `pnpm run test:e2e` 1/1; `pnpm run format:check` exit 1 chỉ vì 23 file trong `.superpowers/`, file nguồn/tài liệu của branch sạch (`prettier --check`). Mutation check trên bản sao cô lập: bỏ boundary conjunct, bypass Root, bỏ fence, timestamp cắt microsecond đều làm test hành vi fail (chi tiết ở `docs/single-product-verification.md`)                                                                                                                                                                                                                                                                                                                                                                                                                                       | Local không thay CI/production; chạy lại `format:check` sau khi xóa `.superpowers/`; phase B (T8–T10), delegation, generic administration, resource-to-resource binding chưa có; không production-ready                                                                                      |

## 7. Prompt ngắn để giao AI khác

> Làm việc duy nhất trong `/Users/vinhdq2312/Documents/personal/base-auth`. Đọc `AGENTS.md` và `docs/superpowers/plans/2026-10-14-foundation-hardening-and-adapters.md`, rồi thực hiện giai đoạn A: T0–T7 và T11. Bắt đầu bằng kiểm kê working tree vì migration/protection có thay đổi mới; không ghi đè công việc đang có. Giữ core thuần, inject value codecs theo interface, dùng Day.js adapter strict UTC bảo toàn microseconds; tổ chức API theo capability và giữ HTTP/security behavior. Hoàn tất callers, fixtures, package exports và tests, cập nhật checkbox bằng bằng chứng mới. Không triển khai T8–T10 ngoài phạm vi được giao, không tự mở generic admin/partition fence/cache allow, không sửa migration lịch sử, không commit/push/deploy. Báo rõ test đã chạy, failure môi trường, phần chưa hoàn tất và rủi ro; không dừng ở việc viết lại kế hoạch này.
