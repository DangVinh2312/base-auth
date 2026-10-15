# IAM thuần và Root tách khỏi IAM — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** bỏ rank khỏi product, biến Root thành account `kind = 'root'` nằm ngoài IAM và bypass phân quyền qua `planUnrestricted`, kèm migration `012`, guard DB, release 2/genesis, fresh-auth ghi, audit Root, suspend và CLI.

**Architecture:** PostgreSQL giữ bất biến Root (cột `kind`, partial unique index, năm guard SECURITY DEFINER owner `product_session_owner`, protocol khóa `FOR NO KEY UPDATE`/`FOR SHARE`); migration `012` chuyển đổi dữ liệu release 1 rồi công bố lại `materialized_hash`. Core thêm `planUnrestricted` (cùng kiểm tra target/principal/validity/revision, predicate `true`, không obligations) và chỉ `ProductAuthorization.access` được gọi nó (ESLint). Adapter rẽ nhánh duy nhất theo `kind` từ `resolve_session`, tính fresh-auth bằng SQL và tự ghi audit Root trong cùng transaction.

**Tech Stack:** TypeScript 6.0.3, Node `>=24.15.0 <25`, pnpm `12.3.4`, NestJS, TypeORM 1.1.2, PostgreSQL 18.4 qua Testcontainers 12.2.0, `node:test`, ESLint 10.12.0 + typescript-eslint 8.71.1.

**Spec:** `docs/superpowers/specs/2026-10-14-iam-root-separation-design.md` (đọc toàn bộ trước mỗi task; plan này không đổi quyết định của spec, chỗ lệch ghi ở mục **Spec deviations**).

**Baseline khi viết plan:** source tại `50d6053` (nhánh `feat/foundation-hardening-adapters`); trong lúc viết plan người dùng đã merge vào `main` (`8f58f18`), khác `50d6053` chỉ ở `docs/superpowers/plans/2026-10-14-foundation-hardening-and-adapters.md`. Mọi `git show 50d6053:` trong plan vẫn đúng. `dist/` khớp source đó: `createProductRelease(core).hash = c1fbb3451d9292477ae24ed1d342f581612b68d9519ffccce6f08a9a3c874fa9`, hash canonical declarations `b374c005…`, hash `productBindings` `fc00a301…`, OpenAPI `a32d4366…`. Trước Task 1, kiểm `git status` và nhánh làm việc; không sửa plan foundation.

## Global Constraints

- Chỉ pnpm, phiên bản theo `package.json#packageManager` (`pnpm@12.3.4`); Node 24 theo `.nvmrc` và `engines` (`>=24.15.0 <25`). Không npm/yarn/npx, không `@latest`, không sửa `pnpm-lock.yaml` bằng tay. Plan này không thêm dependency.
- `synchronize: false` ở mọi môi trường; migration độc lập với AppModule; schema migration không chạy ngầm trong boot.
- Migration mới dùng số kế tiếp thực tế: `012` (`ProductIamRoot1792108800012`); ADR mới `0012`. Không sửa migrations `001`–`011`, ADR `0001`–`0011` hay plan/spec lịch sử.
- Mọi thứ dính DB, lock, trigger, quyền dùng PostgreSQL thật (Testcontainers, image `postgres:18.4` ở `test/setup-postgres.ts`); không SQLite; test quyền chạy bằng đúng credential của login đang chứng minh, superuser/owner chỉ chuẩn bị fixture.
- Đường legacy tenant giữ nguyên: contract và hash legacy byte-for-byte (`manifest-reconciler.ts` phần rank, migrations `tenant/`, `tenant.entity.ts`, `test/manifest-sync.integration-spec.ts`, `test/permission-boundary.integration-spec.ts`).
- Rank: bỏ hoàn toàn ở product; bảo vệ bằng boundary + deny.
- Root không bị policy/boundary giới hạn: Root là super admin, bypass mọi kiểm tra phân quyền (grant/deny/boundary/policy) trên mọi action đã khai báo, kể cả action thêm sau này.
- Biểu diễn Root: `app_user.kind` ∈ {`root`, `iam`}, dùng chung login/session/OIDC/recovery.
- Tạo pending Root: `identity:enroll` tạo account pending như nay; `bootstrap` chuyển `kind` từ `iam` sang `root` đúng một lần.
- Marker initialized nhưng 0 holder: không có Root sau nâng cấp, không cho bootstrap mới; cần repair offline có duyệt (ADR 0008).
- Fresh-auth cho Root: chỉ thao tác ghi nghiệp vụ/quản trị qua `access` (mode `write`/`admin`); không áp cho identity operations.
- Audit Root: mọi lần Root đi qua `access` mà transaction commit, kể cả đọc rỗng và ghi không trúng; denied không audit.
- API quản trị IAM chưa làm; role/grant vẫn khai báo trong manifest. MFA là spec riêng.
- `kind` chỉ lấy từ `resolve_session` đọc trong fenced transaction của request; không lấy từ payload, header hay cookie. Tên role không bao giờ tạo bypass.
- Guard Root mới: `SECURITY DEFINER`, owner `product_session_owner`, `search_path = pg_catalog, pg_temp`, không EXECUTE PUBLIC, nhận diện caller bằng `session_user`, PL/pgSQL `VOLATILE`, thân hàm export làm hằng số cho probe.
- Quy tắc tạo function trong migration: tạo function → tạo trigger → REVOKE (và GRANT với `resolve_session`) → `ALTER FUNCTION … OWNER TO product_session_owner`; DROP function của `product_session_owner` dưới `SET LOCAL ROLE product_session_owner` rồi `RESET ROLE`; chỉ disable trigger có tên cụ thể, không `DISABLE TRIGGER ALL`.
- `down` của `012` ném `"irreversible; restore from backup"`.
- Không baseline ngầm, không bỏ drift check, không fallback allow khi sync lỗi, boot không downgrade release.
- Bước commit trong plan chỉ chạy khi người dùng đã yêu cầu commit trong phiên thực thi (AGENTS.md: không tự commit/push). Không `git add -A`; chỉ add đúng file của task.
- Mỗi task chạy `pnpm exec prettier --write` trên đúng file đã sửa, rồi `pnpm run lint` và `pnpm run typecheck` trước commit; không tắt rule hay nới assertion để xanh.

## Review Focus

1. Session Root cấp **trước** `revoke-root` vẫn đang mở: lần gọi kế tiếp phải 401 (state `suspended` + `auth_epoch` tăng), không chỉ chặn login mới → test ở Task 9.
2. Root gửi key sai định dạng (detail/update) hoặc action/resource chưa khai báo: 400/403, rollback, không có event Root và không lộ tồn tại → test ở Task 7.
3. Root truy cập resource có key kiểu `string`: event Root không ghi key vào metadata (chỉ uuid/integer như quy tắc hiện có) → test ở Task 7.
4. Root gọi suspend với id không canonical (chữ hoa): 403 trước `access`, không event; Root nhắm chính mình: 404 kèm event `absent`, Root không bị đổi → test ở Task 8.
5. Repair gỡ suspend Root (spec 4.6) do owner bảng chạy trong một transaction thành công; probe chặn boot khi `guard_root_lifecycle` đang disable và pass lại sau `ENABLE` → test ở Task 3.

---

## Bản đồ file

| File                                                                                 | Hành động           | Trách nhiệm                                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `packages/typeorm-postgres/src/protected-state.ts`                                   | Create (T1)         | `protectedStateHash`, `codeOwnedCatalogIsEmpty`; nội bộ, không export qua entrypoint                               |
| `packages/typeorm-postgres/src/manifest-reconciler.ts`                               | Modify (T1)         | Helper validation dùng chung (`validateRoleKeys`, `validateReleaseContent`, `releaseContentHash`); legacy giữ hash |
| `packages/typeorm-postgres/src/product-manifest.ts`                                  | Modify (T1,3,4)     | Genesis; role SQL không rank; bootstrap/reissue/revoke theo `kind`; release product v2 không system grants         |
| `packages/core/src/planner.ts`, `packages/core/src/runtime.ts`                       | Modify (T2)         | `resolveTarget` dùng chung, `planUnrestricted`                                                                     |
| `eslint.config.js`                                                                   | Modify (T2)         | `no-restricted-syntax` cho `planUnrestricted`                                                                      |
| `packages/typeorm-postgres/src/migrations/product/012-iam-root.ts`                   | Create (T3)         | Migration chuyển đổi, thân guard/resolve_session export cho probe                                                  |
| `packages/typeorm-postgres/src/product-database.ts`                                  | Modify (T3,5)       | Đăng ký `012`, ma trận quyền, inventory function/trigger đích, ACL owner; tham số `migrations` cho provisioning    |
| `packages/typeorm-postgres/src/product-authority.ts`                                 | Modify (T3,7,8)     | Suspend không rank; nhánh Root, fresh SQL, audit Root; thứ tự lookup → self                                        |
| `packages/typeorm-postgres/src/product-audit.ts`                                     | Modify (T7)         | Union event Root (`principalKind`/`outcome`, target typed, `data.update` absent)                                   |
| `packages/typeorm-postgres/src/index.ts`, `composition.ts`                           | Modify (T4,7)       | Bỏ `SystemGrant*`/`systemGrantHash`; export `PRODUCT_FRESH_AUTH_SQL` ở `./composition`                             |
| `apps/api/src/administration/account.declarations.ts`                                | Modify (T3)         | Binding `iam_account`, field `state`, bỏ `rootAccounts@1` và system grant                                          |
| `apps/api/src/authorization/product-manifest.ts`                                     | Modify (T3,4)       | Release 2 (`sequence '2'`, `predecessor '1'`)                                                                      |
| `apps/api/src/openapi/product-openapi.ts`                                            | Modify (T8)         | Summary suspend                                                                                                    |
| `tools/product.ts`                                                                   | Modify (T3)         | Bootstrap không boundary; thông điệp revoke = suspend                                                              |
| `test/fixtures/release-one/*.ts`                                                     | Create (T5)         | Bản đóng băng của `50d6053` để dựng release 1 thật                                                                 |
| `test/product-genesis.integration-spec.ts`                                           | Create (T1)         | Genesis                                                                                                            |
| `packages/core/test/unrestricted.spec.ts`                                            | Create (T2)         | Core `planUnrestricted`                                                                                            |
| `test/product-root-guards.integration-spec.ts`                                       | Create (T3)         | Bất biến DB theo từng login, repair 4.6                                                                            |
| `test/product-iam-migration.integration-spec.ts`                                     | Create (T5)         | Release 1 thật → `012` → release 2, bảng 4.3, drift, down, tương thích binary                                      |
| `test/product-root-concurrency.integration-spec.ts`                                  | Create (T6)         | Protocol khóa hai connection, isolation                                                                            |
| `test/product-root.integration-spec.ts`                                              | Create (T7,8)       | Bypass, fresh-auth, audit Root, suspend                                                                            |
| Tests hiện có (mục 9 spec)                                                           | Modify (T3–T9)      | Chuyển fixture/assertion có chủ đích                                                                               |
| `docs/decisions/0012-iam-root-separation.md`, docs, `AGENTS.md` ×4, `docs/prompt.md` | Create/Modify (T10) | ADR, runbook, bất biến, bằng chứng                                                                                 |

## Thứ tự task

Theo mục 12 của spec, với hai điều chỉnh có lý do (ghi lại ở **Spec deviations** #6): bước 1 (ADR/`AGENTS.md`/`docs/prompt.md`) dời về Task 10 theo yêu cầu người giao plan; bước 2 tách đôi vì reconciler product đang ghi `role_definition.authority_level` và bootstrap đang ghi `user_role`/`user_boundary` — cả hai chỉ đổi được cùng migration `012`. Kết quả: mỗi task kết thúc với `typecheck`, `lint`, `test:unit` và các file integration của task đều xanh.

1. Task 1 — `protectedStateHash`, helper validation legacy/product, genesis.
2. Task 2 — Core `planUnrestricted` và ESLint rule.
3. Task 3 — Migration `012`, guard, ma trận quyền, probe và các đường ghi DB phụ thuộc schema (release 2, bootstrap/reissue/revoke, account, chuyển fixture).
4. Task 4 — Contract release product v2: bỏ system grants, role `{ key, label }`, `system.` dự trữ.
5. Task 5 — Test nâng cấp từ release 1 thật (bảng 4.3, drift, down, tương thích binary).
6. Task 6 — Protocol khóa: test concurrency hai connection.
7. Task 7 — Bypass, fresh-auth SQL và audit Root trong `access`.
8. Task 8 — Resource `account` và `suspendUser`.
9. Task 9 — CLI Root end-to-end.
10. Task 10 — Docs, ADR 0012, `AGENTS.md`, `docs/prompt.md`, mutation check, full gate.

---

### Task 1: `protectedStateHash`, helper validation và genesis

**Files:**

- Create: `packages/typeorm-postgres/src/protected-state.ts`
- Modify: `packages/typeorm-postgres/src/manifest-reconciler.ts:115-338` (`sizeLimits`, `prepareRelease`)
- Modify: `packages/typeorm-postgres/src/product-manifest.ts:183-211` (`reconcile`), `:333-357` (xóa `protectedStateHash` cục bộ), `:1-21` (imports)
- Test: `test/system-release.spec.ts` (thêm test ghim hash legacy)
- Test: `test/product-genesis.integration-spec.ts` (create)

**Interfaces:**

- Consumes: không.
- Produces:

```ts
// packages/typeorm-postgres/src/protected-state.ts (nội bộ package; không export qua index/composition/operations/legacy)
export async function protectedStateHash(m: EntityManager): Promise<string>;
export async function codeOwnedCatalogIsEmpty(m: EntityManager): Promise<boolean>;

// packages/typeorm-postgres/src/manifest-reconciler.ts (export nội bộ; entrypoint ./legacy không đổi)
export type ReleaseContentSource = Omit<ReleaseSource, 'roles'>;
export type ValidatedReleaseContent = Omit<VerifiedReleaseManifest, 'roles' | 'hash'>;
export function validateRoleKeys(
  roles: readonly { readonly key: string; readonly label: string }[],
): ReadonlySet<string>;
export function validateReleaseContent(
  source: ReleaseContentSource,
  core: AuthorizationCore,
  roleKeys: ReadonlySet<string>,
): ValidatedReleaseContent;
export function releaseContentHash(
  content: ValidatedReleaseContent,
  roles: readonly object[],
): string;
```

- [ ] **Step 1: Viết test ghim hash legacy (characterization) và test genesis fail**

Thêm vào cuối `test/system-release.spec.ts`:

```ts
test('legacy release hash and validation are unchanged by the product/legacy split', () => {
  const source = {
    sequence: '1',
    predecessor: '0',
    declarations: declarations(),
    roles: [
      { key: 'reviewer', label: 'Reviewer', authorityLevel: 10 },
      { key: 'system.root', label: 'Root', authorityLevel: 1000 },
    ],
    defaultGrants: [
      {
        permission: 'submission.read',
        role: 'reviewer',
        template: { key: 'all', version: 1 },
        parameters: {},
      },
    ],
    seeds: [],
    removeSeeds: [],
    boundaryBindings: [],
    removeBoundaryBindings: [],
  };
  // Computed from the 50d6053 build, before the split: the legacy envelope stays byte-for-byte.
  assert.equal(
    prepareRelease(source, core).hash,
    'b8fef6264647e605444e39f908addf9822cbed066c57323fd556c0354301361b',
  );
  for (const authorityLevel of [-1, 1001, 1.5])
    assert.throws(
      () =>
        prepareRelease(
          {
            ...source,
            roles: [{ key: 'reviewer', label: 'Reviewer', authorityLevel }],
            defaultGrants: [],
          },
          core,
        ),
      /authority level/,
    );
  assert.throws(
    () => prepareRelease({ ...source, roles: [...source.roles, source.roles[0]!] }, core),
    /role reviewer/,
  );
  assert.throws(
    () =>
      prepareRelease(
        { ...source, roles: [{ key: 'reviewer', label: ' ', authorityLevel: 10 }] },
        core,
      ),
    /label/,
  );
});
```

Create `test/product-genesis.integration-spec.ts`:

```ts
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import type { ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductManifestReconciler,
  ProductTransactionRunner,
  prepareProductRelease,
} from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import {
  createProductAuthorizationCore,
  productReleaseSource,
} from '../apps/api/dist/authorization/product-manifest.js';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
    p,
    randomBytes(24).toString('hex'),
  ]),
) as Record<ProductDatabasePurpose, string>;
let fixture: TestPostgres;
before(async () => {
  fixture = await startPostgres();
});
after(async () => {
  await fixture?.stop();
});

/** A freshly provisioned product database (release_sequence 0) and its sync reconciler. */
async function freshDatabase(name: string) {
  await withClient(fixture.superuser, (c) => c.query(`CREATE DATABASE ${name}`));
  const settings = await provisionProductDatabase(
    { ...fixture.superuser, database: name },
    passwords,
  );
  const sync = await new DataSource(productDataSourceOptions(settings.sync)).initialize();
  const reconciler = new ProductManifestReconciler(new ProductTransactionRunner({ sync }), {
    core,
    actor: randomUUID() as IdentityId,
    capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  });
  const sequence = async () =>
    (await sync.query<{ s: string }[]>('SELECT release_sequence::text s FROM authz_state'))[0]!.s;
  return { sync, reconciler, sequence };
}
const release = (sequence: string, predecessor: string) =>
  prepareProductRelease({ ...productReleaseSource, sequence, predecessor }, core);

test('a fresh database accepts any release as its first; later releases keep a strict predecessor', async () => {
  const { sync, reconciler, sequence } = await freshDatabase('genesis_fresh');
  try {
    assert.equal((await reconciler.reconcile(release('2', '1'))).changed, true);
    assert.equal(await sequence(), '2');
    await assert.rejects(reconciler.reconcile(release('4', '3')), /predecessor_mismatch/);
    assert.equal((await reconciler.reconcile(release('3', '2'))).changed, true);
  } finally {
    await sync.destroy();
  }
});

test('genesis needs an empty code-owned catalog; otherwise the predecessor stays strict', async () => {
  const { sync, reconciler, sequence } = await freshDatabase('genesis_dirty');
  try {
    // A code-owned fact although nothing was published yet (release_sequence is still 0).
    await sync.query(
      "INSERT INTO resource_type(type_key,key_kind,binding_key) VALUES($1,'uuid',$1)",
      [Buffer.from('stray')],
    );
    await assert.rejects(reconciler.reconcile(release('2', '1')), /predecessor_mismatch/);
    assert.equal(await sequence(), '0');
    // The ordinary first release (predecessor 0) is unchanged.
    assert.equal((await reconciler.reconcile(release('1', '0'))).changed, true);
  } finally {
    await sync.destroy();
  }
});
```

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:unit -- test/system-release.spec.ts`
Expected: PASS ở HEAD (test ghim hành vi trước refactor). Nếu literal `b8fef626…` FAIL ngay ở HEAD (dist cũ hơn source), thay literal bằng giá trị `actual` in ra **ở HEAD, trước mọi thay đổi**, không bao giờ sau refactor.

Run: `pnpm run test:integration -- test/product-genesis.integration-spec.ts`
Expected: FAIL ở test đầu với `Release rejected (predecessor_mismatch): unexpected previous release`.

- [ ] **Step 3: Tạo `protected-state.ts`**

```ts
import { createHash } from 'node:crypto';
import { canonicalJson } from '@base-authorization/core';
import type { EntityManager } from 'typeorm';

/**
 * The code-owned catalog: every table/predicate whose rows `materialized_hash` covers. Registered
 * code, never request identifiers. The reconciler, genesis and migration 012 share this one list.
 */
const codeOwned: readonly (readonly [table: string, predicate: string])[] = [
  ['resource_type', 'true'],
  ['permission_policy', 'true'],
  ['permission_catalog', 'true'],
  ['scope_template', 'true'],
  ['permission_boundary', 'true'],
  ['permission_boundary_entry', 'true'],
  ['resource_relation_definition', 'true'],
  ['role_definition', "managed_by='code'"],
  ['policy_rule', "managed_by='code'"],
  ['relation_edge', 'seed_owner IS NOT NULL'],
  ['user_boundary', 'seed_owner IS NOT NULL'],
];

/** Hash of every code-owned fact, compared with and published as `authz_state.materialized_hash`. */
export async function protectedStateHash(m: EntityManager): Promise<string> {
  const rows: unknown[] = [];
  for (const [table, predicate] of codeOwned)
    rows.push(
      await m.query(
        `SELECT to_jsonb(t) fact FROM public.${table} t WHERE ${predicate} ORDER BY to_jsonb(t)::text COLLATE "C"`,
      ),
    );
  return createHash('sha256').update(canonicalJson(rows)).digest('hex');
}

/** Genesis condition (spec 5.2): no code-owned fact, judged by the same tables and predicates. */
export async function codeOwnedCatalogIsEmpty(m: EntityManager): Promise<boolean> {
  for (const [table, predicate] of codeOwned) {
    const rows = await m.query<unknown[]>(
      `SELECT 1 FROM public.${table} t WHERE ${predicate} LIMIT 1`,
    );
    if (rows.length > 0) return false;
  }
  return true;
}
```

Trong `product-manifest.ts`: xóa hàm `protectedStateHash` cục bộ (dòng 333–357) và thêm `import { codeOwnedCatalogIsEmpty, protectedStateHash } from './protected-state.js';`. Thuật toán không đổi (cùng câu SQL, cùng `sha256(canonicalJson(rows))`).

- [ ] **Step 4: Genesis trong `ProductManifestReconciler.reconcile`**

Thay hai dòng kiểm predecessor (`product-manifest.ts:198-199`):

```ts
if (BigInt(release.sequence) < BigInt(current!.sequence)) reject('downgrade', 'older release');
// Genesis (ADR 0012): a fresh database (sequence 0, empty code-owned catalog) accepts any
// release as its first. Every other case keeps the strict predecessor.
const genesis = current!.sequence === '0' && (await codeOwnedCatalogIsEmpty(m));
if (!genesis && release.predecessor !== current!.sequence)
  reject('predecessor_mismatch', 'unexpected previous release');
```

- [ ] **Step 5: Tách helper validation trong `manifest-reconciler.ts`**

Giữ `sizeLimits` nhưng bỏ khóa `roles` khỏi vòng lặp của nội dung; thêm các hàm sau ngay trước `prepareRelease`, rồi viết lại `prepareRelease`:

```ts
/** Release fields without roles: shared by legacy (ranked roles) and product (key + label) releases. */
export type ReleaseContentSource = Omit<ReleaseSource, 'roles'>;
export type ValidatedReleaseContent = Omit<VerifiedReleaseManifest, 'roles' | 'hash'>;
const contentLimits = {
  defaultGrants: 1_000,
  seeds: 1_000,
  removeSeeds: 1_000,
  boundaryBindings: 1_000,
  removeBoundaryBindings: 1_000,
};
const maxRoles = 200;

/** Key grammar, uniqueness, label and count of release roles; rank is the legacy caller's. */
export function validateRoleKeys(
  roles: readonly { readonly key: string; readonly label: string }[],
): ReadonlySet<string> {
  if (roles.length > maxRoles) reject('invalid_release', 'too many roles');
  const keys = new Set<string>();
  for (const role of roles) {
    if (!identifier.test(role.key) || keys.has(role.key))
      reject('invalid_release', `role ${role.key}`);
    if (role.label.trim().length === 0 || role.label.length > 120)
      reject('invalid_release', `role ${role.key} label`);
    keys.add(role.key);
  }
  return keys;
}
```

`validateReleaseContent(source, core, roleKeys)` chứa nguyên văn phần thân hiện tại của `prepareRelease` từ kiểm `sequence/predecessor` đến hết `removeBoundaryBindings` (dòng 138–284), với ba khác biệt: vòng size-limit lặp `contentLimits` thay `sizeLimits`; khối `const roleKeys = …` (dòng 155–169) bị xóa vì `roleKeys` là tham số; trả về:

```ts
return {
  sequence: sequence!,
  predecessor: predecessor!,
  declarations,
  defaultGrants,
  seeds,
  removeSeeds,
  boundaryBindings,
  removeBoundaryBindings,
};
```

```ts
const byJson = <T>(items: readonly T[]) =>
  [...items].sort((a, b) => (canonicalJson(a) < canonicalJson(b) ? -1 : 1));
/** Canonical release envelope: unchanged keys and order, so legacy hashes stay byte-for-byte. */
export function releaseContentHash(
  content: ValidatedReleaseContent,
  roles: readonly object[],
): string {
  return sha256(
    canonicalJson({
      declarations: JSON.parse(content.declarations.canonical) as unknown,
      roles: byJson(roles),
      defaultGrants: byJson(content.defaultGrants),
      seeds: byJson(content.seeds),
      removeSeeds: byJson(content.removeSeeds),
      boundaryBindings: byJson(content.boundaryBindings),
      removeBoundaryBindings: byJson(content.removeBoundaryBindings),
    }),
  );
}

export function prepareRelease(
  source: ReleaseSource,
  core: AuthorizationCore,
): VerifiedReleaseManifest {
  const roleKeys = validateRoleKeys(source.roles);
  for (const role of source.roles)
    if (
      !Number.isSafeInteger(role.authorityLevel) ||
      role.authorityLevel < 0 ||
      role.authorityLevel > 1000
    )
      reject('invalid_release', `role ${role.key} authority level`);
  const content = validateReleaseContent(source, core, roleKeys);
  const roles = source.roles.map((r) => ({
    key: r.key,
    authorityLevel: r.authorityLevel,
    label: r.label,
  }));
  const manifest: VerifiedReleaseManifest = Object.freeze({
    ...content,
    roles,
    hash: releaseContentHash(content, roles),
  });
  verified.set(manifest, core);
  return manifest;
}
```

Xóa `byJson`/`hash` cục bộ cũ trong `prepareRelease`. `legacy.ts` không đổi.

- [ ] **Step 6: Chạy test**

Run: `pnpm run test:unit -- test/system-release.spec.ts`
Expected: PASS (hash legacy `b8fef626…` không đổi).

Run: `pnpm run test:integration -- test/product-genesis.integration-spec.ts test/manifest-sync.integration-spec.ts test/permission-boundary.integration-spec.ts test/product-system.integration-spec.ts`
Expected: PASS (genesis mới; legacy và product hiện có không đổi).

- [ ] **Step 7: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write packages/typeorm-postgres/src/protected-state.ts packages/typeorm-postgres/src/manifest-reconciler.ts packages/typeorm-postgres/src/product-manifest.ts test/system-release.spec.ts test/product-genesis.integration-spec.ts && pnpm run lint && pnpm run typecheck && pnpm run test:unit`
Expected: exit 0.

```bash
git add packages/typeorm-postgres/src/protected-state.ts packages/typeorm-postgres/src/manifest-reconciler.ts packages/typeorm-postgres/src/product-manifest.ts test/system-release.spec.ts test/product-genesis.integration-spec.ts
git commit -m "refactor: shared protected-state hash and release validation; product genesis"
```

---

### Task 2: Core `planUnrestricted` và ESLint rule giới hạn nơi gọi

**Files:**

- Modify: `packages/core/src/planner.ts:65-113`
- Modify: `packages/core/src/runtime.ts:35-55,126-160`
- Modify: `eslint.config.js` (thêm block cuối)
- Create: `packages/core/test/unrestricted.spec.ts`
- Modify: `packages/core/test/runtime.spec.ts:86-100` (danh sách free export bị cấm)
- Modify: `test/package-boundaries.spec.ts` (thêm test trong `describe('ESLint import boundaries')`)

**Interfaces:**

- Consumes: không.
- Produces:

```ts
// AuthorizationCore (packages/core/src/runtime.ts)
readonly planUnrestricted: (input: UserTrustedInput, snapshot: UserAuthoritySnapshot) => UserDecision;
// Deny reasons dùng chung với planUser: 'unvalidated_declarations' | 'invalid_principal' | 'inactive_user'
//   | 'invalid_now' | 'invalid_valid_until' | 'invalid_validity_window' | 'unknown_resource'
//   | 'unknown_action' | 'permission_not_in_catalog' | 'permission_unavailable'; riêng: 'invalid_revision'.
// Plan allow: { userId, resource, action, permission, revision, predicate: { op: 'constant', value: true },
//   validUntil, obligations: [] }, deep-frozen, nằm trong tập issued của instance.
```

- [ ] **Step 1: Viết test core fail**

Create `packages/core/test/unrestricted.spec.ts`:

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createAuthorizationCore,
  type UserAuthoritySnapshot,
  type UserDecision,
  type UserTrustedInput,
} from '@base-authorization/core';
import {
  createDayjsTimestampCodec,
  createStandardValueCodecs,
} from '@base-authorization/value-adapters';
import { alice, core, input, rule, snapshot, submission } from './fixtures.ts';

function userInput(overrides: Partial<UserTrustedInput> = {}): UserTrustedInput {
  const { tenant: _tenant, ...value } = input();
  void _tenant;
  return { ...value, ...overrides };
}
function userSnapshot(overrides: Partial<UserAuthoritySnapshot> = {}): UserAuthoritySnapshot {
  const { tenant: _tenant, membership: _membership, ...value } = snapshot();
  void _tenant;
  void _membership;
  return { ...value, user: { id: alice, state: 'active' }, ...overrides };
}
function allowed(decision: UserDecision) {
  assert.equal(decision.effect, 'allow');
  if (decision.effect !== 'allow') throw new Error('unreachable');
  return decision.plan;
}
const record = submission('record', '1', { amount: '999.00', status: 'closed' });
const facts = {
  now: '2026-10-13T10:00:01.000000Z',
  record,
  objects: [record],
  edges: [],
  exceptions: [],
};

test('unrestricted plan: same target, revision and validity as planUser; predicate true, no obligations', () => {
  // A direct deny on approve and an approval policy with an obligation would bind planUser.
  const plan = allowed(
    core.planUnrestricted(
      userInput({ action: 'approve' }),
      userSnapshot({
        roles: [],
        rules: [rule('submission.approve', { kind: 'identity', identity: alice }, 'deny', 'all@1')],
      }),
    ),
  );
  assert.deepEqual(plan.predicate, { op: 'constant', value: true });
  assert.deepEqual(plan.obligations, []);
  assert.deepEqual(
    [plan.userId, plan.resource, plan.action, plan.permission, plan.revision],
    [alice, 'submission', 'approve', 'submission.approve', '7'],
  );
  assert.equal(Object.isFrozen(plan), true);
  const user = allowed(
    core.planUser(
      userInput(),
      userSnapshot({
        rules: [rule('submission.read', { kind: 'role', role: 'reviewer' }, 'allow', 'all@1')],
      }),
    ),
  );
  const unrestricted = allowed(core.planUnrestricted(userInput(), userSnapshot()));
  assert.deepEqual(
    [unrestricted.resource, unrestricted.action, unrestricted.permission, unrestricted.validUntil],
    [user.resource, user.action, user.permission, user.validUntil],
  );
  // Issued by this instance: the evaluator accepts it and every record matches.
  assert.equal(core.evaluateUser(unrestricted, facts).effect, 'allow');
});

test('unrestricted plan fails closed on target, principal, user, window, revision and provenance', () => {
  const cases: (readonly [string, UserTrustedInput, UserAuthoritySnapshot])[] = [
    ['unknown_resource', userInput({ resource: 'missing' }), userSnapshot()],
    ['unknown_action', userInput({ action: 'delete' }), userSnapshot()],
    [
      'invalid_principal',
      userInput({ principal: { id: alice.toUpperCase() as typeof alice, assurance: 1 } }),
      userSnapshot(),
    ],
    ['inactive_user', userInput(), userSnapshot({ user: { id: alice, state: 'suspended' } })],
    ['invalid_now', userInput({ now: 'not-a-time' }), userSnapshot()],
    ['invalid_validity_window', userInput({ validUntil: userInput().now }), userSnapshot()],
    ['permission_not_in_catalog', userInput(), userSnapshot({ permissions: [] })],
    ...['', '0', '-1', '07', 'x'].map(
      (revision) => ['invalid_revision', userInput(), userSnapshot({ revision })] as const,
    ),
  ];
  for (const [reason, value, authority] of cases)
    assert.deepEqual(
      core.planUnrestricted(value, authority),
      { effect: 'deny', internalReason: reason },
      reason,
    );
  const other = createAuthorizationCore({
    values: createStandardValueCodecs({ timestamp: createDayjsTimestampCodec() }),
  });
  assert.deepEqual(other.planUnrestricted(userInput(), userSnapshot()), {
    effect: 'deny',
    internalReason: 'unvalidated_declarations',
  });
  const plan = allowed(core.planUnrestricted(userInput(), userSnapshot()));
  assert.deepEqual(other.evaluateUser(plan, facts), {
    effect: 'deny',
    internalReason: 'foreign_plan',
  });
});
```

Trong `packages/core/test/runtime.spec.ts`, thêm `'planUnrestricted',` vào mảng free export bị cấm (sau `'evaluateUser',`).

Thêm test vào cuối `describe('ESLint import boundaries', …)` của `test/package-boundaries.spec.ts`:

```ts
test('only product-authority.ts may reach planUnrestricted', async () => {
  const restricted = async (filePath: string, code: string) => {
    const [result] = await eslint.lintText(`${code}\n`, { filePath: abs(filePath) });
    assert.ok(result);
    return result.messages.filter((m) => m.ruleId === 'no-restricted-syntax');
  };
  const call =
    'declare const core: { planUnrestricted(a: unknown, b: unknown): unknown };\ncore.planUnrestricted({}, {});';
  const destructured =
    'declare const core: { planUnrestricted: unknown };\nconst { planUnrestricted } = core;\nexport { planUnrestricted };';
  for (const file of [
    'packages/typeorm-postgres/src/product-gateway.ts',
    'packages/typeorm-postgres/src/product-identity.ts',
    'apps/api/src/documents/documents.controller.ts',
    'apps/api/src/infrastructure/product-runtime.ts',
    'tools/product.ts',
    'test/product-root.integration-spec.ts',
  ])
    for (const code of [call, destructured])
      assert.equal((await restricted(file, code)).length, 1, `${file}: ${code}`);
  assert.deepEqual(
    await restricted('packages/typeorm-postgres/src/product-authority.ts', call),
    [],
  );
});
```

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:unit -- packages/core/test/unrestricted.spec.ts packages/core/test/runtime.spec.ts test/package-boundaries.spec.ts`
Expected: FAIL — `core.planUnrestricted is not a function` (TypeError ở hai test core) và `0 !== 1` ở test ESLint.

- [ ] **Step 3: Implement trong `planner.ts`**

Thêm sau `const deny = …`:

```ts
/** One mapping for every planner entry point: denials, configuration faults and the rest. */
function denied(error: unknown): Extract<Decision, { effect: 'deny' }> {
  if (error instanceof Denied) return { effect: 'deny', internalReason: error.message };
  if (error instanceof ConfigurationError)
    return { effect: 'deny', internalReason: `configuration: ${error.message}` };
  return { effect: 'deny', internalReason: 'internal_error' };
}

/**
 * Checks every plan shares, in planUser's order: provenance, principal, active user, validity
 * window, declared resource/action and its catalog row.
 */
function resolveTarget(
  core: AuthorizationCore,
  input: UserTrustedInput,
  snapshot: UserAuthoritySnapshot,
) {
  const declarations = snapshot.declarations;
  if (!core.isValidated(declarations)) deny('unvalidated_declarations');
  const principal = input.principal;
  if (!core.isCanonicalUuid(principal.id) || typeof principal.assurance !== 'number')
    deny('invalid_principal');
  if (snapshot.user?.id !== principal.id || snapshot.user.state !== 'active') deny('inactive_user');
  const now = core.canonicalTimestamp(input.now) ?? deny('invalid_now');
  const validUntil = core.canonicalTimestamp(input.validUntil) ?? deny('invalid_valid_until');
  if (core.compareValues('timestamp', validUntil, now) <= 0) deny('invalid_validity_window');
  const resource = Object.hasOwn(declarations.resources, input.resource)
    ? declarations.resources[input.resource]!
    : deny('unknown_resource');
  const action = Object.hasOwn(resource.actions, input.action)
    ? resource.actions[input.action]!
    : deny('unknown_action');
  const permissionKey = `${resource.key}.${input.action}`;
  const permission =
    snapshot.permissions.find((p) => p.key === permissionKey) ?? deny('permission_not_in_catalog');
  if (
    permission.resource !== resource.key ||
    permission.action !== input.action ||
    permission.lifecycle === 'retired'
  )
    deny('permission_unavailable');
  return { declarations, principal, validUntil, resource, action, permissionKey, permission };
}
```

Trong `plan` và `planUser`, thay khối `catch` bằng `return denied(error);`. Trong `buildPlan`, thay dòng 86–113 bằng:

```ts
const { declarations, principal, validUntil, resource, action, permissionKey, permission } =
  resolveTarget(core, input, snapshot);
```

(phần còn lại của `buildPlan` từ `if (refKey(permission.policy) !== refKey(action.policy))` giữ nguyên). Thêm cuối file:

```ts
/**
 * Plan for a principal the adapter verified as unrestricted (Root, ADR 0012). Same target,
 * principal, user, validity and revision checks as planUser; only the authorization predicate
 * becomes `true`: no policy, grant, deny, boundary or obligation is evaluated. The core never
 * learns why a caller is unrestricted; projection and writable fields stay the adapter's.
 */
export function planUnrestricted(
  core: AuthorizationCore,
  input: UserTrustedInput,
  snapshot: UserAuthoritySnapshot,
): UserDecision {
  try {
    const { principal, validUntil, resource, permissionKey } = resolveTarget(core, input, snapshot);
    if (
      core.canonicalInt64(snapshot.revision) !== snapshot.revision ||
      BigInt(snapshot.revision) < 1n
    )
      deny('invalid_revision');
    const authorized: UserAuthorizedPlan = deepFreeze({
      userId: principal.id,
      resource: resource.key,
      action: input.action,
      permission: permissionKey,
      revision: snapshot.revision,
      predicate: { op: 'constant', value: true },
      validUntil,
      obligations: [],
    });
    return { effect: 'allow', plan: authorized, obligations: authorized.obligations };
  } catch (error) {
    return denied(error);
  }
}
```

- [ ] **Step 4: Implement trong `runtime.ts`**

Import `planUnrestricted as planUnrestrictedWith` từ `./planner.js`. Thêm vào interface `AuthorizationCore` sau `evaluateUser`:

```ts
  /**
   * planUser's checks with predicate `true` and no obligations, for a principal the adapter has
   * verified as unrestricted. Only ProductAuthorization.access may call it (ESLint, ADR 0012):
   * a developer boundary, not a sandbox.
   */
  readonly planUnrestricted: (input: UserTrustedInput, snapshot: UserAuthoritySnapshot) => UserDecision;
```

và vào object `core` sau `evaluateUser`:

```ts
    planUnrestricted: (input: UserTrustedInput, snapshot: UserAuthoritySnapshot) =>
      issue(planUnrestrictedWith(core, input, snapshot)),
```

- [ ] **Step 5: ESLint rule**

Thêm block cuối mảng trong `eslint.config.js`:

```js
  {
    // planUnrestricted is the Root branch of ProductAuthorization.access only (ADR 0012); core
    // unit tests exercise it directly. Developer boundary, not process isolation.
    files: ['**/*.ts'],
    ignores: ['packages/typeorm-postgres/src/product-authority.ts', 'packages/core/test/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[property.name='planUnrestricted']",
          message: 'Only ProductAuthorization.access may plan unrestricted access (ADR 0012).',
        },
        {
          selector: "ObjectPattern > Property[key.name='planUnrestricted']",
          message: 'Only ProductAuthorization.access may plan unrestricted access (ADR 0012).',
        },
      ],
    },
  },
```

- [ ] **Step 6: Chạy test**

Run: `pnpm run test:unit -- packages/core/test test/package-boundaries.spec.ts`
Expected: PASS (mọi test core cũ, gồm `user-decision.spec.ts` với role tên `system.root` không bypass, vẫn PASS).

- [ ] **Step 7: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write packages/core/src/planner.ts packages/core/src/runtime.ts eslint.config.js packages/core/test/unrestricted.spec.ts packages/core/test/runtime.spec.ts test/package-boundaries.spec.ts && pnpm run lint && pnpm run typecheck && pnpm run test:unit`
Expected: exit 0.

```bash
git add packages/core/src/planner.ts packages/core/src/runtime.ts eslint.config.js packages/core/test/unrestricted.spec.ts packages/core/test/runtime.spec.ts test/package-boundaries.spec.ts
git commit -m "feat(core): planUnrestricted with planUser checks and an ESLint call boundary"
```

---

### Task 3: Migration `012`, guard Root, ma trận quyền, probe và đường ghi DB

**Files:**

- Create: `packages/typeorm-postgres/src/migrations/product/012-iam-root.ts`
- Modify: `packages/typeorm-postgres/src/product-database.ts:1-45,190-342,403-447`
- Modify: `packages/typeorm-postgres/src/product-manifest.ts:622-643` (role SQL), `:782-1024` (bootstrap/reissue/revoke)
- Modify: `packages/typeorm-postgres/src/product-authority.ts:273-299` (`suspendUser`)
- Modify: `apps/api/src/administration/account.declarations.ts`, `apps/api/src/authorization/product-manifest.ts:16-62`
- Modify: `tools/product.ts:216-261`
- Create: `test/product-root-guards.integration-spec.ts`
- Modify tests: `test/product-database.integration-spec.ts`, `test/product-system.integration-spec.ts`, `test/product-system-regression.integration-spec.ts`, `test/product-authorization.integration-spec.ts`, `test/product-audit.integration-spec.ts`, `test/product-load.integration-spec.ts:95`, `test/product-cli.integration-spec.ts`, `test/system-release.spec.ts:100-113`, `apps/api/test/structure.spec.ts:322-330`, `apps/api/test/product.e2e-spec.ts`

**Interfaces:**

- Consumes: `protectedStateHash`, `codeOwnedCatalogIsEmpty` (Task 1).
- Produces:

```ts
// packages/typeorm-postgres/src/migrations/product/012-iam-root.ts
export const resolveSessionKindBody: string;
export const productRowsIamBody: string;
export const guardRootKindBody: string;
export const requireRootMarkerKindBody: string;
export const guardRootNotIamSubjectBody: string;
export const guardRootActivationBody: string;
export const guardRootLifecycleBody: string;
export class ProductIamRoot1792108800012 implements MigrationInterface {}
// Messages (tests match them): 'code-owned facts drifted; repair before migration',
// 'code-owned facts exist before the first release; repair before migration',
// 'unknown system.* role; repair before migration', 'more than one Root holder; repair before migration',
// 'Root holder does not match the bootstrap marker; repair before migration',
// 'former Root boundary binding is not inert; repair before migration', 'irreversible; restore from backup'.

// DB: app_user.kind text ('root'|'iam'), ux_app_user_root, view iam_account(id,state),
// resolve_session(bytea) RETURNS TABLE(user_id uuid,kind text,state text,auth_epoch bigint,method text,
//   assurance text,authenticated_at timestamptz,reauthenticated_at timestamptz,expires_at timestamptz)

// packages/typeorm-postgres/src/product-manifest.ts
export interface RootBootstrapInput {
  readonly operationId: string;
  readonly userId: IdentityId;
  readonly method: 'local' | 'oidc';
  readonly issuer?: string;
  readonly subject?: string;
}
// bootstrapProductRoot(runner, release, input) / reissueRootActivation(runner, input, core) /
// revokeProductRoot(runner, input, core): chữ ký giữ nguyên ngoài việc bỏ `boundaries`.
// revokeProductRoot = state 'suspended' + auth_epoch+1 cho Root chưa suspended; { revoked: false } nếu không có.
```

- [ ] **Step 1: Viết test guard DB fail**

Create `test/product-root-guards.integration-spec.ts`:

```ts
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import type { ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductIdentityService,
  ProductManifestReconciler,
  ProductTransactionRunner,
  createProductPasswordHasher,
  prepareProductRelease,
  sessionDigest,
  verifyProductPrivileges,
} from '@base-authorization/typeorm-postgres/composition';
import {
  bootstrapProductRoot,
  productDataSourceOptions,
  provisionProductDatabase,
  revokeProductRoot,
} from '@base-authorization/typeorm-postgres/operations';
import {
  createProductAuthorizationCore,
  productDeclarations,
  productReleaseSource,
} from '../apps/api/dist/authorization/product-manifest.js';
import { sqlState, startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
const utf8 = (value: string) => Buffer.from(value);
// Release 2 plus one boundary on document.read, so user_boundary facts can be written at all.
const release = prepareProductRelease(
  {
    ...productReleaseSource,
    declarations: {
      ...productDeclarations,
      boundaries: [
        ...productDeclarations.boundaries,
        {
          key: 'documentLimit',
          version: 1,
          entries: [
            {
              permission: 'document.read',
              contextRequirements: [],
              requiredScope: { op: 'constant', value: true },
            },
          ],
        },
      ],
    },
  },
  core,
);
type Runtime = 'data' | 'identity' | 'authority' | 'sync' | 'bootstrap';
const runtime: readonly (Runtime | 'outbox')[] = [
  'data',
  'identity',
  'authority',
  'sync',
  'bootstrap',
  'outbox',
];
let pg: TestPostgres;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
let pools: Record<Runtime, DataSource>;
let migration: DataSource;
let runner: ProductTransactionRunner;
let identity: ProductIdentityService;
const object = randomUUID();
const root = randomUUID() as IdentityId;
const member = randomUUID() as IdentityId;
const rootPassword = 'a long unique root guard password';
let activationSecret = '';
let rootSession = '';

const pending = async (email?: string): Promise<IdentityId> => {
  const id = randomUUID() as IdentityId;
  await migration.query(`INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`, [
    id,
    email ?? `${id}@example.test`,
  ]);
  return id;
};
const promote = (id: string) =>
  runner.run('bootstrap', (tx) =>
    tx.manager.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [id]),
  );
/** Writes one IAM fact for `user` through the authority (or sync) credential. */
const facts: Record<string, (user: string) => Promise<unknown>> = {
  user_role: (user) =>
    runner.run('admin', (tx) =>
      tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
        user,
        utf8('reviewer'),
      ]),
    ),
  user_boundary: (user) =>
    runner.run('admin', (tx) =>
      tx.manager.query(
        'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
        [user, utf8('document.read'), utf8('documentLimit')],
      ),
    ),
  policy_rule: (user) =>
    runner.run('admin', (tx) =>
      tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
        [randomUUID(), utf8('document.read'), user, utf8('ownedDocuments')],
      ),
    ),
  record_exception: (user) =>
    runner.run('admin', (tx) =>
      tx.manager.query(
        "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,'allow','manual',statement_timestamp(),'fixture',$6)",
        [randomUUID(), object, utf8('document'), utf8('document.read'), user, member],
      ),
    ),
};

before(async () => {
  pg = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
      p,
      randomBytes(24).toString('hex'),
    ]),
  ) as Record<ProductDatabasePurpose, string>;
  connections = await provisionProductDatabase(pg.superuser, passwords);
  pools = {} as typeof pools;
  for (const p of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[p] = await new DataSource(productDataSourceOptions(connections[p])).initialize();
  migration = await new DataSource(productDataSourceOptions(connections.migration)).initialize();
  runner = new ProductTransactionRunner(pools);
  identity = new ProductIdentityService(runner, await createProductPasswordHasher(new Set()));
  await new ProductManifestReconciler(runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities: release.declarations.capabilities,
  }).reconcile(release);
  await migration.query(
    `INSERT INTO app_user(id,email_canonical,state,email_verified) VALUES($1,'member@example.test','active',true)`,
    [member],
  );
  await migration.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'root@example.test','pending')`,
    [root],
  );
  await runner.run('admin', (tx) =>
    tx.manager.query(
      "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
      [object, utf8('document'), utf8(object)],
    ),
  );
});
after(async () => {
  await migration?.destroy();
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await pg?.stop();
});

test('promotion: only bootstrap, only a pending fact-free target without a live invitation', async () => {
  const target = await pending();
  for (const login of ['data', 'identity', 'authority', 'sync', 'outbox'] as const)
    await withClient(connections[login], async (c) =>
      assert.equal(
        await sqlState(c.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target])),
        '42501',
        login,
      ),
    );
  // The table owner has the column privilege; the guard still refuses everyone but bootstrap.
  await assert.rejects(
    migration.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target]),
    /offline bootstrap only/,
  );
  await assert.rejects(
    migration.query(`INSERT INTO app_user(id,state,kind) VALUES($1,'pending','root')`, [
      randomUUID(),
    ]),
    /created only by promotion/,
  );
  await assert.rejects(promote(member), /must be pending/);
  for (const [name, write] of Object.entries(facts)) {
    const holder = await pending();
    await write(holder);
    await assert.rejects(promote(holder), /holds IAM facts/, name);
  }
  const invited = await pending();
  await runner.run('revoke', (tx) => identity.issueActivation(tx, invited));
  await assert.rejects(promote(invited), /live activation token/);
  // Issuing a record exception for someone else is not an IAM fact of the issuer: the guard
  // accepts the promotion (rolled back here, so the marker stays free).
  const issuer = await pending();
  await facts.record_exception!(member);
  await runner.run('admin', (tx) =>
    tx.manager.query('UPDATE record_exception SET issued_by=$1 WHERE user_id=$2', [issuer, member]),
  );
  await assert.rejects(
    runner.run('bootstrap', async (tx) => {
      await tx.manager.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [issuer]);
      throw new Error('guard accepted; roll back');
    }),
    /guard accepted; roll back/,
  );
});

test('one Root: bootstrap promotes once; root→iam and a second Root are refused', async () => {
  const result = await bootstrapProductRoot(runner, release, {
    operationId: randomUUID(),
    userId: root,
    method: 'local',
  });
  assert.ok(result.activationSecret);
  activationSecret = result.activationSecret;
  assert.deepEqual(await migration.query('SELECT kind FROM app_user WHERE id=$1', [root]), [
    { kind: 'root' },
  ]);
  await assert.rejects(
    runner.run('bootstrap', (tx) =>
      tx.manager.query(`UPDATE app_user SET kind='iam' WHERE id=$1`, [root]),
    ),
    /immutable/,
  );
  await assert.rejects(
    migration.query(`UPDATE app_user SET kind='iam' WHERE id=$1`, [root]),
    /immutable/,
  );
  await assert.rejects(promote(await pending()), /one-time/);
});

test('Root holds no IAM fact: every subject change is refused; issued_by is no subject', async () => {
  for (const [name, write] of Object.entries(facts))
    await assert.rejects(write(root), /outside IAM/, name);
  await facts.user_role!(member);
  await assert.rejects(
    runner.run('admin', (tx) =>
      tx.manager.query('UPDATE user_role SET user_id=$1 WHERE user_id=$2', [root, member]),
    ),
    /outside IAM/,
  );
  await assert.rejects(
    pools.sync.query(
      'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version,seed_owner) VALUES($1,$2,$3,1,$4)',
      [root, utf8('document.read'), utf8('documentLimit'), utf8('seed')],
    ),
    /outside IAM/,
  );
  await assert.rejects(
    pools.sync.query(
      "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','code')",
      [randomUUID(), utf8('document.read'), root, utf8('ownedDocuments')],
    ),
    /outside IAM/,
  );
  await runner.run('admin', (tx) =>
    tx.manager.query(
      "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,'deny','manual',statement_timestamp(),'issued by Root',$6)",
      [randomUUID(), object, utf8('document'), utf8('document.read'), member, root],
    ),
  );
  assert.deepEqual(
    await migration.query(
      `SELECT (SELECT count(*)::int FROM user_role WHERE user_id=$1)+(SELECT count(*)::int FROM user_boundary WHERE user_id=$1)+(SELECT count(*)::int FROM policy_rule WHERE user_id=$1)+(SELECT count(*)::int FROM record_exception WHERE user_id=$1) AS n`,
      [root],
    ),
    [{ n: 0 }],
  );
});

test('only bootstrap issues Root activation; other token purposes are unaffected', async () => {
  for (const purpose of ['activation', 'oidc-activation'])
    await assert.rejects(
      pools.identity.query(
        `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,statement_timestamp()+interval '1 minute')`,
        [randomBytes(32), root, purpose],
      ),
      /bootstrap credential only/,
      purpose,
    );
  await assert.rejects(
    runner.run('revoke', (tx) => identity.issueActivation(tx, root)),
    /bootstrap credential only/,
  );
  await pools.identity.query(
    `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($1,$2,'reset',statement_timestamp()+interval '1 minute')`,
    [randomBytes(32), root],
  );
});

test('lifecycle: bootstrap never touches IAM, authority never touches Root, identity keeps its flows', async () => {
  for (const sql of [
    `UPDATE app_user SET state='suspended' WHERE id=$1`,
    'UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1',
  ]) {
    await assert.rejects(pools.bootstrap.query(sql, [member]), /may not change IAM/);
    await assert.rejects(pools.authority.query(sql, [root]), /offline or identity only/);
  }
  for (const login of ['data', 'sync', 'outbox'] as const)
    await withClient(connections[login], async (c) =>
      assert.equal(
        await sqlState(c.query(`UPDATE app_user SET state='suspended' WHERE id=$1`, [root])),
        '42501',
        login,
      ),
    );
  await identity.activate(activationSecret, rootPassword, 'guard-root');
  const first = await identity.login('root@example.test', rootPassword, 'guard-root');
  await identity.changePassword(
    first.secret,
    rootPassword,
    `${rootPassword} changed`,
    'guard-root',
  );
  rootSession = (await identity.login('root@example.test', `${rootPassword} changed`, 'guard-root'))
    .secret;
  const extra = await identity.login('root@example.test', `${rootPassword} changed`, 'guard-root');
  await identity.logout(extra.secret, true);
  rootSession = (await identity.login('root@example.test', `${rootPassword} changed`, 'guard-root'))
    .secret;
  assert.deepEqual(await migration.query('SELECT state,kind FROM app_user WHERE id=$1', [root]), [
    { state: 'active', kind: 'root' },
  ]);
});

test('iam_account hides Root, DELETE app_user is refused, resolve_session reports kind', async () => {
  assert.deepEqual(
    await pools.authority.query('SELECT id FROM iam_account WHERE id=ANY($1::uuid[])', [
      [root, member],
    ]),
    [{ id: member }],
  );
  await withClient(connections.data, async (c) =>
    assert.equal(await sqlState(c.query('SELECT id FROM iam_account')), '42501'),
  );
  for (const login of runtime)
    await withClient(connections[login], async (c) =>
      assert.equal(
        await sqlState(c.query('DELETE FROM app_user WHERE id=$1', [member])),
        '42501',
        login,
      ),
    );
  assert.deepEqual(
    await pools.data.query('SELECT user_id,kind FROM public.resolve_session($1)', [
      sessionDigest(rootSession),
    ]),
    [{ user_id: root, kind: 'root' }],
  );
});

test('no runtime login lifts a Root suspension; the approved offline repair does (spec 4.6)', async () => {
  assert.deepEqual(
    await revokeProductRoot(
      runner,
      {
        operationId: randomUUID(),
        userId: root,
        approval: 'CHG-guard',
        reason: 'Fixture revocation',
      },
      core,
    ),
    { revoked: true },
  );
  await assert.rejects(
    pools.identity.query(`UPDATE app_user SET state='active' WHERE id=$1`, [root]),
    /identity may only activate pending accounts/,
  );
  await assert.rejects(
    pools.bootstrap.query(`UPDATE app_user SET state='active' WHERE id=$1`, [root]),
    /may only suspend Root/,
  );
  await assert.rejects(
    pools.authority.query(`UPDATE app_user SET state='active' WHERE id=$1`, [root]),
    /offline or identity only/,
  );
  // A disabled guard is drift: startup refuses it.
  await migration.query('ALTER TABLE app_user DISABLE TRIGGER guard_root_lifecycle');
  try {
    await assert.rejects(verifyProductPrivileges(pools), /protection drift/);
  } finally {
    await migration.query('ALTER TABLE app_user ENABLE TRIGGER guard_root_lifecycle');
  }
  // The repair: table owner, one transaction, exactly the Root row (ADR 0012 runbook).
  await migration.transaction(async (m) => {
    await m.query('ALTER TABLE public.app_user DISABLE TRIGGER guard_root_lifecycle');
    await m.query(
      `UPDATE public.app_user SET state='active' WHERE id=$1 AND kind='root' AND state='suspended'`,
      [root],
    );
    await m.query('ALTER TABLE public.app_user ENABLE TRIGGER guard_root_lifecycle');
  });
  assert.deepEqual(await migration.query('SELECT state FROM app_user WHERE id=$1', [root]), [
    { state: 'active' },
  ]);
  await verifyProductPrivileges(pools);
});
```

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:integration -- test/product-root-guards.integration-spec.ts`
Expected: FAIL ở test đầu, `column "kind" of relation "app_user" does not exist` (hoặc assertion regex không khớp vì chưa có guard).

- [ ] **Step 3: Viết migration `012`**

Create `packages/typeorm-postgres/src/migrations/product/012-iam-root.ts`:

```ts
import type { MigrationInterface, QueryRunner } from 'typeorm';
import { codeOwnedCatalogIsEmpty, protectedStateHash } from '../../protected-state.js';

/**
 * IAM without rank, Root outside IAM (ADR 0012, spec 2026-10-14):
 * - `app_user.kind` ('iam'|'root'): at most one Root, promoted once by the offline bootstrap login
 *   under READ COMMITTED together with the marker, never given an IAM fact or a foreign invitation;
 * - `account_rank`, both `authority_level` columns and the `system.*` guards (004 branch, 007, 008)
 *   are gone; `resolve_session` returns `kind`;
 * - a Root holder becomes `kind = 'root'` without IAM facts; the code-owned `system.root` role and
 *   grants leave; `materialized_hash` is republished for the converted state (drift checked first).
 * Runs offline through provisioning (product_migration with temporary owner membership).
 * Bodies are exact; the startup probe compares them.
 */
export const resolveSessionKindBody = `
        SELECT u.id,u.kind,u.state,u.auth_epoch,s.method,s.assurance,s.authenticated_at,s.reauthenticated_at,s.expires_at
        FROM public.application_session s JOIN public.app_user u ON u.id=s.user_id
        LEFT JOIN public.local_credential c ON c.user_id=u.id
        LEFT JOIN public.external_identity e ON e.issuer=s.external_issuer AND e.subject=s.external_subject AND e.user_id=u.id
        WHERE s.token_hash=p_digest AND u.state='active' AND s.auth_epoch=u.auth_epoch
          AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.last_seen_at>statement_timestamp()-interval '30 minutes'
          AND ((s.method='local' AND u.email_verified AND c.version=s.credential_version)
            OR (s.method='oidc' AND e.enabled AND e.binding_version=s.binding_version AND EXISTS (SELECT FROM public.oidc_provider p WHERE p.issuer=e.issuer AND p.enabled AND p.version=s.provider_version)))
        `;
/** 004 guard without its user_role branch; every other branch keeps its semantics. */
export const productRowsIamBody = `
      DECLARE old_code boolean:=false; new_code boolean:=false; old_role bytea; new_role bytea;
      BEGIN
        IF TG_TABLE_NAME IN ('role_definition','policy_rule') THEN
          IF TG_OP<>'INSERT' THEN old_code:=OLD.managed_by='code'; END IF;
          IF TG_OP<>'DELETE' THEN new_code:=NEW.managed_by='code'; END IF;
        ELSIF TG_TABLE_NAME IN ('relation_edge','user_boundary') THEN
          IF TG_OP<>'INSERT' THEN old_code:=OLD.seed_owner IS NOT NULL; END IF;
          IF TG_OP<>'DELETE' THEN new_code:=NEW.seed_owner IS NOT NULL; END IF;
        END IF;
        IF current_user='product_sync' THEN
          IF (TG_OP<>'INSERT' AND NOT old_code) OR (TG_OP<>'DELETE' AND NOT new_code) THEN
            RAISE EXCEPTION 'sync cannot take over runtime facts' USING ERRCODE='42501';
          END IF;
        ELSIF old_code OR new_code THEN
          RAISE EXCEPTION 'code owned facts protected' USING ERRCODE='42501';
        END IF;
        IF TG_TABLE_NAME IN ('policy_rule','record_exception')
          AND NOT (TG_TABLE_NAME='policy_rule' AND current_user='product_sync') THEN
          IF TG_OP<>'INSERT' THEN old_role:=OLD.role_key; END IF;
          IF TG_OP<>'DELETE' THEN new_role:=NEW.role_key; END IF;
          IF EXISTS(SELECT FROM public.role_definition WHERE role_key IN (old_role,new_role) AND managed_by='code') THEN
            RAISE EXCEPTION 'system role references protected' USING ERRCODE='42501';
          END IF;
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
      END `;
/**
 * iam→root once: bootstrap login, READ COMMITTED (each EXISTS below sees facts committed after the
 * caller locked the target), pending, unmarked, Rootless, fact-free and without a live invitation.
 */
export const guardRootKindBody = `
BEGIN
  IF TG_OP='INSERT' THEN
    IF NEW.kind='root' THEN
      RAISE EXCEPTION 'Root accounts are created only by promotion' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.kind IS NOT DISTINCT FROM OLD.kind THEN RETURN NEW; END IF;
  IF NOT (OLD.kind='iam' AND NEW.kind='root') THEN
    RAISE EXCEPTION 'account kind is immutable except the one Root promotion' USING ERRCODE='42501';
  END IF;
  IF session_user<>'product_bootstrap' THEN
    RAISE EXCEPTION 'Root promotion is offline bootstrap only' USING ERRCODE='42501';
  END IF;
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'Root promotion requires READ COMMITTED' USING ERRCODE='42501';
  END IF;
  IF OLD.state<>'pending' THEN
    RAISE EXCEPTION 'Root promotion target must be pending' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT FROM public.security_bootstrap_state WHERE singleton AND initialized_at IS NOT NULL)
    OR EXISTS(SELECT FROM public.app_user WHERE kind='root') THEN
    RAISE EXCEPTION 'Root promotion is one-time' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT FROM public.user_role WHERE user_id=NEW.id)
    OR EXISTS(SELECT FROM public.user_boundary WHERE user_id=NEW.id)
    OR EXISTS(SELECT FROM public.policy_rule WHERE user_id=NEW.id)
    OR EXISTS(SELECT FROM public.record_exception WHERE user_id=NEW.id) THEN
    RAISE EXCEPTION 'Root promotion target holds IAM facts' USING ERRCODE='42501';
  END IF;
  IF EXISTS(SELECT FROM public.one_time_token WHERE user_id=NEW.id AND purpose IN ('activation','oidc-activation')
      AND consumed_at IS NULL AND expires_at>statement_timestamp()) THEN
    RAISE EXCEPTION 'Root promotion target holds a live activation token' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;
/** Deferred: a promotion commits only with the marker naming that account. */
export const requireRootMarkerKindBody = `
BEGIN
  IF NEW.kind='root' AND OLD.kind IS DISTINCT FROM 'root' THEN
    IF NOT EXISTS(SELECT FROM public.security_bootstrap_state
        WHERE singleton AND initialized_at IS NOT NULL AND target_user_id=NEW.id) THEN
      RAISE EXCEPTION 'Root promotion requires the bootstrap marker naming it' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NULL;
END`;
/** FOR SHARE conflicts with the promotion's FOR NO KEY UPDATE (spec 3.3); FK KEY SHARE does not. */
export const guardRootNotIamSubjectBody = `
DECLARE v_kind text;
BEGIN
  IF NEW.user_id IS NULL THEN RETURN NEW; END IF;
  SELECT kind INTO v_kind FROM public.app_user WHERE id=NEW.user_id FOR SHARE;
  IF v_kind='root' THEN
    RAISE EXCEPTION 'Root is outside IAM: no role, boundary, rule or exception' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;
export const guardRootActivationBody = `
DECLARE v_kind text;
BEGIN
  IF NEW.purpose IN ('activation','oidc-activation') THEN
    SELECT kind INTO v_kind FROM public.app_user WHERE id=NEW.user_id FOR SHARE;
    IF v_kind='root' AND session_user<>'product_bootstrap' THEN
      RAISE EXCEPTION 'Root activation is issued by the bootstrap credential only' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NEW;
END`;
/** OLD.kind decides; 004 (protect_account_lifecycle) still bounds identity and authority. */
export const guardRootLifecycleBody = `
BEGIN
  IF OLD.kind='iam' THEN
    IF session_user='product_bootstrap' THEN
      RAISE EXCEPTION 'bootstrap may not change IAM account lifecycle' USING ERRCODE='42501';
    END IF;
  ELSIF session_user='product_bootstrap' THEN
    IF NEW.state<>'suspended' OR NEW.auth_epoch<=OLD.auth_epoch THEN
      RAISE EXCEPTION 'bootstrap may only suspend Root and end its sessions' USING ERRCODE='42501';
    END IF;
  ELSIF session_user<>'product_identity' THEN
    RAISE EXCEPTION 'Root lifecycle is offline or identity only' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END`;

const root = `convert_to('system.root','UTF8')`;
const rootGrantPermissions = `SELECT permission_key FROM public.policy_rule WHERE role_key=${root} AND managed_by='code'`;
/** A former Root binding stays live while any allow fact could grant its permission (spec 4.2). */
const liveFormerRootBinding = `
  SELECT 1 FROM public.user_boundary b
  WHERE b.user_id=$1 AND b.permission_key IN (${rootGrantPermissions})
    AND (EXISTS(SELECT FROM public.policy_rule r WHERE r.permission_key=b.permission_key AND r.effect='allow'
          AND (r.user_id=$1 OR r.role_key IN (SELECT role_key FROM public.user_role WHERE user_id=$1)))
      OR EXISTS(SELECT FROM public.record_exception x WHERE x.permission_key=b.permission_key AND x.effect='allow'
          AND (x.user_id=$1 OR x.role_key IN (SELECT role_key FROM public.user_role WHERE user_id=$1))))
  LIMIT 1`;
const guards = [
  ['guard_root_kind', guardRootKindBody],
  ['require_root_marker_kind', requireRootMarkerKindBody],
  ['guard_root_not_iam_subject', guardRootNotIamSubjectBody],
  ['guard_root_activation', guardRootActivationBody],
  ['guard_root_lifecycle', guardRootLifecycleBody],
] as const;
const iamTables = ['user_role', 'user_boundary', 'policy_rule', 'record_exception'] as const;
const disabledDuringConversion = ['role_definition', 'policy_rule', 'user_role', 'user_boundary'];

export class ProductIamRoot1792108800012 implements MigrationInterface {
  name = 'ProductIamRoot1792108800012';
  async up(runner: QueryRunner): Promise<void> {
    const m = runner.manager;
    // 1. Lock and read the application state and the marker.
    const [state] = await m.query<{ sequence: string; materialized: string | null }[]>(
      `SELECT release_sequence::text sequence,encode(materialized_hash,'hex') materialized FROM public.authz_state WHERE singleton FOR UPDATE`,
    );
    const [marker] = await m.query<{ target: string | null }[]>(
      'SELECT target_user_id::text target FROM public.security_bootstrap_state WHERE singleton FOR UPDATE',
    );
    if (!state || !marker) throw new Error('application state missing; repair before migration');
    // 2. No drift: the converted state is republished in step 9, so it must start from the published one.
    if (state.sequence !== '0') {
      if ((await protectedStateHash(m)) !== state.materialized)
        throw new Error('code-owned facts drifted; repair before migration');
    } else if (!(await codeOwnedCatalogIsEmpty(m)))
      throw new Error('code-owned facts exist before the first release; repair before migration');
    // 3. Preflight (spec table 4.3).
    const [unknown] = await m.query<unknown[]>(
      `SELECT 1 FROM public.role_definition WHERE substring(role_key FROM 1 FOR 7)=convert_to('system.','UTF8') AND role_key<>${root} LIMIT 1`,
    );
    if (unknown) throw new Error('unknown system.* role; repair before migration');
    const holders = await m.query<{ id: string }[]>(
      `SELECT user_id::text id FROM public.user_role WHERE role_key=${root}`,
    );
    if (holders.length > 1) throw new Error('more than one Root holder; repair before migration');
    const holder = holders[0]?.id;
    if (holder !== undefined && holder !== marker.target)
      throw new Error('Root holder does not match the bootstrap marker; repair before migration');
    const former = holder === undefined ? marker.target : null;
    if (former !== null) {
      const [live] = await m.query<unknown[]>(liveFormerRootBinding, [former]);
      if (live)
        throw new Error('former Root boundary binding is not inert; repair before migration');
    }
    // 4. New schema.
    await runner.query(`
      ALTER TABLE public.app_user ADD COLUMN kind text NOT NULL DEFAULT 'iam' CONSTRAINT ck_app_user_kind CHECK (kind IN ('root','iam'));
      CREATE UNIQUE INDEX ux_app_user_root ON public.app_user ((true)) WHERE kind='root';
      CREATE VIEW public.iam_account WITH (security_invoker=true) AS SELECT id,state FROM public.app_user WHERE kind='iam';
      REVOKE ALL ON public.iam_account FROM PUBLIC;
    `);
    // 5. Kept guards that would block step 6 are disabled by name; replaced ones are dropped.
    for (const table of disabledDuringConversion)
      await runner.query(`ALTER TABLE public.${table} DISABLE TRIGGER protect_product_rows`);
    await runner.query(`
      DROP TRIGGER require_root_marker ON public.user_role;
      DROP TRIGGER protect_system_activation ON public.user_role;
      DROP TRIGGER protect_system_activation ON public.one_time_token;
      DROP FUNCTION public.require_root_marker();
      SET LOCAL ROLE product_session_owner;
      DROP FUNCTION public.protect_system_activation();
      RESET ROLE;
    `);
    // 6. Root conversion; user_relation is untouched on purpose (Root bypasses ReBAC).
    if (holder !== undefined) {
      await m.query(`UPDATE public.app_user SET kind='root' WHERE id=$1`, [holder]);
      for (const table of ['user_boundary', 'policy_rule', 'record_exception', 'user_role'])
        await m.query(`DELETE FROM public.${table} WHERE user_id=$1`, [holder]);
    }
    if (former !== null)
      await m.query(
        `DELETE FROM public.user_boundary WHERE user_id=$1 AND permission_key IN (${rootGrantPermissions})`,
        [former],
      );
    await m.query(`DELETE FROM public.policy_rule WHERE role_key=${root} AND managed_by='code'`);
    await m.query(`DELETE FROM public.role_definition WHERE role_key=${root}`);
    // 7. Old schema out; resolve_session recreated (return type change); grants (spec 3.2, 3.4).
    await runner.query(`
      DROP VIEW public.account_rank;
      SET LOCAL ROLE product_session_owner;
      DROP FUNCTION public.resolve_session(bytea);
      RESET ROLE;
      ALTER TABLE public.app_user DROP COLUMN authority_level;
      ALTER TABLE public.role_definition DROP COLUMN authority_level;
      CREATE FUNCTION public.resolve_session(p_digest bytea)
        RETURNS TABLE(user_id uuid,kind text,state text,auth_epoch bigint,method text,assurance text,authenticated_at timestamptz,reauthenticated_at timestamptz,expires_at timestamptz)
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$${resolveSessionKindBody}$fn$;
      REVOKE ALL ON FUNCTION public.resolve_session(bytea) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION public.resolve_session(bytea) TO product_data,product_identity,product_authority;
      ALTER FUNCTION public.resolve_session(bytea) OWNER TO product_session_owner;
      REVOKE SELECT(role_key) ON public.user_role FROM product_session_owner;
      GRANT SELECT(kind),UPDATE(kind) ON public.app_user TO product_session_owner;
      GRANT SELECT ON public.security_bootstrap_state TO product_session_owner;
      GRANT SELECT(user_id) ON public.user_boundary,public.policy_rule,public.record_exception TO product_session_owner;
      REVOKE INSERT,DELETE ON public.user_role FROM product_bootstrap;
      REVOKE INSERT ON public.user_boundary FROM product_bootstrap;
      GRANT SELECT(kind),UPDATE(kind,state,auth_epoch) ON public.app_user TO product_bootstrap;
      GRANT SELECT(kind) ON public.app_user TO product_authority;
      GRANT SELECT ON public.iam_account TO product_authority;
    `);
    // 8. Guards: 004 body replaced in place (owner/mode kept); Root guards created by this login
    //    (default privileges apply), triggers next, then REVOKE and owner change (002/008 order).
    await runner.query(`
      CREATE OR REPLACE FUNCTION public.protect_product_rows() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$${productRowsIamBody}$fn$;
      REVOKE ALL ON FUNCTION public.protect_product_rows() FROM PUBLIC;
    `);
    for (const [name, body] of guards)
      await runner.query(
        `CREATE FUNCTION public.${name}() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$${body}$fn$`,
      );
    await runner.query(`
      CREATE TRIGGER guard_root_kind BEFORE INSERT OR UPDATE OF kind ON public.app_user
        FOR EACH ROW EXECUTE FUNCTION public.guard_root_kind();
      CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON public.app_user
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind();
      CREATE TRIGGER guard_root_lifecycle BEFORE UPDATE OF state,auth_epoch ON public.app_user
        FOR EACH ROW EXECUTE FUNCTION public.guard_root_lifecycle();
      CREATE TRIGGER guard_root_activation BEFORE INSERT ON public.one_time_token
        FOR EACH ROW EXECUTE FUNCTION public.guard_root_activation();
    `);
    for (const table of iamTables)
      await runner.query(
        `CREATE TRIGGER guard_root_not_iam_subject BEFORE INSERT OR UPDATE ON public.${table} FOR EACH ROW EXECUTE FUNCTION public.guard_root_not_iam_subject()`,
      );
    for (const [name] of guards)
      await runner.query(`
        REVOKE ALL ON FUNCTION public.${name}() FROM PUBLIC;
        ALTER FUNCTION public.${name}() OWNER TO product_session_owner;
      `);
    for (const table of disabledDuringConversion)
      await runner.query(`ALTER TABLE public.${table} ENABLE TRIGGER protect_product_rows`);
    // 9. Publish the converted state; release_sequence and manifest_hash stay.
    if (state.sequence !== '0')
      await m.query(
        `UPDATE public.authz_state SET materialized_hash=decode($1,'hex') WHERE singleton`,
        [await protectedStateHash(m)],
      );
  }
  down(): Promise<void> {
    return Promise.reject(new Error('irreversible; restore from backup'));
  }
}
```

- [ ] **Step 4: Đăng ký migration và cập nhật probe trong `product-database.ts`**

1. Imports: bỏ `resolveSessionBody` khỏi import 002, bỏ `productRowsBody` khỏi import 004, bỏ import 007 (`requireRootMarkerBody`) và `systemActivationBody` của 008; thêm:

```ts
import {
  guardRootActivationBody,
  guardRootKindBody,
  guardRootLifecycleBody,
  guardRootNotIamSubjectBody,
  ProductIamRoot1792108800012,
  productRowsIamBody,
  requireRootMarkerKindBody,
  resolveSessionKindBody,
} from './migrations/product/012-iam-root.js';
```

và thêm `ProductIamRoot1792108800012` vào cuối `productMigrations`.

2. `expectedPrivileges`: `data` dùng `columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch'])`; `authority` dùng `columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch', 'kind'])`, `columns('UPDATE', 'app_user', ['state', 'auth_epoch'])`, thay `'table:account_rank:SELECT'` bằng `'table:iam_account:SELECT'`; `bootstrap`:

```ts
  bootstrap: [
    ...tables(['SELECT'], [...authorityTables, 'authz_state']),
    ...columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch', 'email_canonical', 'kind']),
    ...columns('UPDATE', 'app_user', ['kind', 'state', 'auth_epoch']),
    'column:local_credential.user_id:SELECT',
    ...columns('SELECT', 'external_identity', [
      'issuer',
      'subject',
      'user_id',
      'enabled',
      'binding_version',
    ]),
    'column:authz_state.revision:UPDATE',
    ...tables(['SELECT', 'UPDATE'], ['security_bootstrap_state']),
    'table:one_time_token:INSERT',
    ...columns('SELECT', 'one_time_token', ['user_id', 'purpose', 'consumed_at']),
    'column:one_time_token.consumed_at:UPDATE',
    audit,
  ],
```

3. Thay `protectionFunctions` và `protectionTriggers`:

```ts
const protectionFunctions: Readonly<Record<string, readonly [string, boolean, string]>> = {
  authz_acquire_shared_fence: ['product_fence_owner', true, sharedFenceBody],
  resolve_session: ['product_session_owner', true, resolveSessionKindBody],
  protect_product_state: ['product_migration', false, productStateBody],
  protect_product_rows: ['product_migration', false, productRowsIamBody],
  protect_account_lifecycle: ['product_migration', false, accountLifecycleBody],
  protect_token_consumption: ['product_migration', false, tokenConsumptionBody],
  guard_root_kind: ['product_session_owner', true, guardRootKindBody],
  require_root_marker_kind: ['product_session_owner', true, requireRootMarkerKindBody],
  guard_root_not_iam_subject: ['product_session_owner', true, guardRootNotIamSubjectBody],
  guard_root_activation: ['product_session_owner', true, guardRootActivationBody],
  guard_root_lifecycle: ['product_session_owner', true, guardRootLifecycleBody],
};
const protectionTriggers = new Set([
  ...[
    'role_definition',
    'policy_rule',
    'record_exception',
    'user_role',
    'relation_edge',
    'user_boundary',
  ].map((table) => `${table}.protect_product_rows:protect_product_rows:31::O:false:false`),
  ...['user_role', 'user_boundary', 'policy_rule', 'record_exception'].map(
    (table) => `${table}.guard_root_not_iam_subject:guard_root_not_iam_subject:23::O:false:false`,
  ),
  'security_bootstrap_state.protect_product_state:protect_product_state:19::O:false:false',
  'authz_state.protect_product_state:protect_product_state:19::O:false:false',
  'app_user.protect_account_lifecycle:protect_account_lifecycle:19::O:false:false',
  'app_user.guard_root_kind:guard_root_kind:23:kind:O:false:false',
  'app_user.require_root_marker_kind:require_root_marker_kind:17:kind:O:true:true',
  'app_user.guard_root_lifecycle:guard_root_lifecycle:19:auth_epoch,state:O:false:false',
  'one_time_token.guard_root_activation:guard_root_activation:7::O:false:false',
  'one_time_token.protect_token_consumption:protect_token_consumption:19::O:false:false',
]);
```

4. ACL owner chính xác (spec 3.2). Thêm sau `protectedTables`:

```ts
/**
 * Exact ACL of the NOLOGIN owner of resolve_session and the Root guards: the 002/008 grants with
 * the 012 delta (spec 3.2). Anything more widens what every SECURITY DEFINER guard can do.
 */
const sessionOwnerAcl: readonly string[] = [
  'schema:public:USAGE',
  ...columns('SELECT', 'app_user', ['id', 'state', 'auth_epoch', 'email_verified', 'kind']),
  'column:app_user.kind:UPDATE',
  ...columns('SELECT', 'application_session', [
    'token_hash',
    'user_id',
    'auth_epoch',
    'method',
    'assurance',
    'authenticated_at',
    'reauthenticated_at',
    'expires_at',
    'revoked_at',
    'last_seen_at',
    'credential_version',
    'external_issuer',
    'external_subject',
    'binding_version',
    'provider_version',
  ]),
  ...columns('SELECT', 'local_credential', ['user_id', 'version']),
  ...columns('SELECT', 'external_identity', [
    'issuer',
    'subject',
    'user_id',
    'enabled',
    'binding_version',
  ]),
  ...columns('SELECT', 'oidc_provider', ['issuer', 'version', 'enabled']),
  ...['user_role', 'user_boundary', 'policy_rule', 'record_exception'].map(
    (table) => `column:${table}.user_id:SELECT`,
  ),
  ...columns('SELECT', 'one_time_token', ['user_id', 'purpose', 'consumed_at', 'expires_at']),
  'table:security_bootstrap_state:SELECT',
  ...[
    'resolve_session(bytea)',
    'guard_root_kind()',
    'require_root_marker_kind()',
    'guard_root_not_iam_subject()',
    'guard_root_activation()',
    'guard_root_lifecycle()',
  ].map((fn) => `function:${fn}:EXECUTE`),
];
```

Trong `verifyProductPrivileges`, ngay sau khối `if (!hardening?.valid) throw …`:

```ts
const ownerGrants = await source.query<{ grant: string }[]>(
  `WITH owner AS (SELECT oid FROM pg_roles WHERE rolname='product_session_owner'),
      schemas AS (SELECT oid,nspname,CASE WHEN nspname='public' THEN '' ELSE nspname||'.' END AS prefix FROM pg_namespace
        WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg\\_toast%' AND nspname NOT LIKE 'pg\\_temp\\_%'),
      acl AS (
        SELECT 'schema:'||q.nspname AS object,a.privilege_type,a.is_grantable,a.grantee
          FROM pg_namespace n JOIN schemas q ON q.oid=n.oid,aclexplode(n.nspacl) a
        UNION ALL
        SELECT 'table:'||q.prefix||c.relname,a.privilege_type,a.is_grantable,a.grantee
          FROM pg_class c JOIN schemas q ON q.oid=c.relnamespace,aclexplode(c.relacl) a
        UNION ALL
        SELECT 'column:'||q.prefix||c.relname||'.'||t.attname,a.privilege_type,a.is_grantable,a.grantee
          FROM pg_attribute t JOIN pg_class c ON c.oid=t.attrelid JOIN schemas q ON q.oid=c.relnamespace,
          aclexplode(t.attacl) a WHERE t.attnum>0 AND NOT t.attisdropped
        UNION ALL
        SELECT 'function:'||q.prefix||p.proname||'('||oidvectortypes(p.proargtypes)||')',a.privilege_type,a.is_grantable,a.grantee
          FROM pg_proc p JOIN schemas q ON q.oid=p.pronamespace,aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a)
      SELECT DISTINCT object||':'||privilege_type||CASE WHEN is_grantable THEN '+grant' ELSE '' END AS grant
        FROM acl WHERE grantee=(SELECT oid FROM owner)`,
);
const ownerActual = new Set(ownerGrants.map((g) => g.grant));
if (ownerActual.size !== sessionOwnerAcl.length || sessionOwnerAcl.some((g) => !ownerActual.has(g)))
  throw new Error('Product protection drift');
```

- [ ] **Step 5: Đường ghi DB theo schema mới trong `product-manifest.ts`**

1. Vòng `release.roles` trong `apply` (dòng 622–643):

```ts
// No rank since 012: a role is its key, owner and label.
for (const role of release.roles) {
  const rows = await m.query<{ managed_by: string; label: string }[]>(
    'SELECT managed_by, label FROM role_definition WHERE role_key = $1',
    [utf8(role.key)],
  );
  if (rows.length === 0) {
    await m.query(
      `INSERT INTO role_definition(role_key, managed_by, label) VALUES ($1, 'code', $2)`,
      [utf8(role.key), role.label],
    );
  } else if (rows[0]!.managed_by !== 'code') {
    reject('collision', `role ${role.key} is runtime-managed`);
  } else if (rows[0]!.label !== role.label) {
    await m.query('UPDATE role_definition SET label = $2 WHERE role_key = $1', [
      utf8(role.key),
      role.label,
    ]);
  }
}
```

2. `RootBootstrapInput`: bỏ trường `boundaries`. Thân `bootstrapProductRoot` sau đoạn drift check (giữ nguyên marker `FOR UPDATE` và drift check), thay toàn bộ phần từ `const role = release.roles.find(…)` tới trước `await appendProductAudit(…)` bằng:

```ts
// Lock the target before any check (spec 3.3): a concurrent fact or token insert either
// waits for this promotion or is already visible to the DB guard.
const [target] = await m.query<{ state: string; email_canonical: string | null }[]>(
  'SELECT state,email_canonical FROM app_user WHERE id=$1 FOR NO KEY UPDATE',
  [input.userId],
);
if (target?.state !== 'pending')
  reject('collision', 'Root enrollment target must already be pending');
if (input.method === 'local') {
  if (!target!.email_canonical)
    reject('missing_reference', 'local target needs verified delivery address enrollment');
} else if (input.method === 'oidc') {
  if (!input.issuer || !input.subject)
    reject('invalid_release', 'OIDC enrollment requires exact issuer and subject');
  const [binding] = await m.query<{ only: boolean }[]>(
    'SELECT (SELECT count(*) FROM external_identity WHERE user_id=$3 AND enabled)=1 AS only FROM external_identity WHERE issuer=$1 AND subject=$2 AND user_id=$3 AND enabled',
    [input.issuer, input.subject, input.userId],
  );
  if (!binding?.only) reject('missing_reference', 'pending OIDC binding does not match target');
} else reject('invalid_release', 'unsupported Root activation method');
const { randomBytes } = await import('node:crypto');
const activationSecret = randomBytes(32).toString('base64url');
// Promotion before the proof: the guard refuses a target holding IAM facts or a live invitation.
await m.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [input.userId]);
await m.query(
  `INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,statement_timestamp()+interval '15 minutes')`,
  [
    createHash('sha256').update(activationSecret).digest(),
    input.userId,
    input.method === 'local' ? 'activation' : 'oidc-activation',
  ],
);
await m.query(
  'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
  [input.operationId, input.userId],
);
```

Docstring của hàm: `Offline capability only: promotes one pending IAM account to Root (kind = 'root') with the permanent marker and a one-time proof (ADR 0012). No role, grant or boundary is written.`

3. `reissueRootActivation`: câu đọc target thành

```ts
const [target] = await m.query<
  { state: string; delivery: boolean; root: boolean; credential: boolean; bindings: number }[]
>(
  `SELECT u.state,u.email_canonical IS NOT NULL delivery,u.kind='root' root,
        EXISTS(SELECT FROM local_credential c WHERE c.user_id=u.id) credential,
        (SELECT count(*) FROM external_identity e WHERE e.user_id=u.id AND e.enabled)::int bindings
       FROM security_bootstrap_state b JOIN app_user u ON u.id=b.target_user_id
       WHERE b.singleton AND b.initialized_at IS NOT NULL AND u.id=$1 FOR UPDATE OF b FOR NO KEY UPDATE OF u`,
  [input.userId],
);
```

(phần còn lại giữ nguyên; target `app_user` bị khóa trước mọi thao tác token).

4. `revokeProductRoot`: docstring `Offline capability only: suspends the Root and ends its sessions (auth_epoch) under the exclusive fence with audit. The marker stays, so no new Root can follow (ADR 0012).`; câu ghi:

```ts
const removed = await tx.manager.query<unknown[]>(
  `WITH revoked AS (UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1 AND kind='root' AND state<>'suspended' RETURNING 1) SELECT * FROM revoked`,
  [input.userId],
);
```

- [ ] **Step 6: `suspendUser` không còn rank (`product-authority.ts`)**

Xóa khối đọc `account_rank` (dòng 279–286); thân callback còn:

```ts
if (plan.userId === target) throw new ProductAccessDenied();
// iam_account (012) holds IAM accounts only; rank no longer exists (ADR 0012).
const row = await this.gateway.detail(plan, this.bindings.core.parseKey('uuid', target), tx);
if (!row) return false;
await tx.manager.query(
  `UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1`,
  [target],
);
await appendProductAudit(tx, {
  kind: 'account.suspend',
  actor: plan.userId,
  permission: plan.permission,
  target: { userId: target },
});
return true;
```

- [ ] **Step 7: Release 2 và resource `account` ở `apps/api`**

`apps/api/src/administration/account.declarations.ts`:

```ts
import type { SystemDeclarations } from '@base-authorization/core';
import type { ProductStorageBindings } from '@base-authorization/typeorm-postgres';

/** Account administration fragment: data only, composed into the release in authorization/. */
export const accountDeclarations: Pick<
  SystemDeclarations,
  'resources' | 'policies' | 'templates' | 'boundaries'
> = {
  resources: [
    {
      key: 'account',
      keyKind: 'uuid',
      fields: { state: { kind: 'string' } },
      actions: {
        // An IAM principal needs a grant and an explicit boundary; Root bypasses both (ADR 0012).
        suspend: { policy: { key: 'freshAuthentication', version: 1 }, boundary: 'required' },
      },
    },
  ],
  policies: [
    {
      key: 'freshAuthentication',
      version: 1,
      contextRequirements: [{ validator: 'fresh@1', parameters: {} }],
      requiredScope: { op: 'constant', value: true },
      obligations: [{ handler: 'audit@1' }],
    },
  ],
  templates: [
    {
      key: 'allAccounts',
      version: 1,
      resource: 'account',
      parameters: {},
      expression: { op: 'constant', value: true },
    },
  ],
  boundaries: [],
};
export const accountBinding: ProductStorageBindings['resources'][number] = {
  resource: 'account',
  // IAM accounts only: Root and absent ids look the same to every account action.
  table: 'iam_account',
  objectIdColumn: 'id',
  keyColumn: 'id',
  columns: { state: 'state' },
  projection: ['state'],
};
```

`apps/api/src/authorization/product-manifest.ts`: import chỉ `accountBinding, accountDeclarations`; `productReleaseSource`:

```ts
/** Release content is data only; codecs are provenance and never enter the manifest hash. */
export const productReleaseSource: ProductReleaseSource = {
  // Release 2 (ADR 0012): Root left IAM; no system role, system grant or rank boundary remains.
  sequence: '2',
  predecessor: '1',
  declarations: productDeclarations,
  roles: [{ key: 'reviewer', label: 'Reviewer', authorityLevel: 10 }],
  defaultGrants: documentDefaultGrants,
  systemGrants: [],
  removeSystemGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};
```

(`authorityLevel`, `systemGrants`, `removeSystemGrants` biến mất ở Task 4.)

- [ ] **Step 8: CLI `tools/product.ts`**

Khối `bootstrap`: xóa thuộc tính `boundaries: […]`; thông điệp idempotent `'Operation already committed; marker and Root unchanged.'`. Khối `revoke-root`:

```ts
console.log(
  result.revoked
    ? 'Root suspended and its sessions revoked; marker unchanged.'
    : 'No unsuspended Root for this user; nothing changed.',
);
```

- [ ] **Step 9: Chuyển các test hiện có (spec mục 9)**

`test/product-database.integration-spec.ts`:

1. Imports dist: giữ `ProductInitial1792108800000`, `tokenConsumptionBody` (008); bỏ import 004/007 và `systemActivationBody`; thêm `guardRootActivationBody, guardRootKindBody, guardRootLifecycleBody, guardRootNotIamSubjectBody, productRowsIamBody, requireRootMarkerKindBody` từ `../packages/typeorm-postgres/dist/migrations/product/012-iam-root.js`.
2. Test `code rows and ownership transitions protected…`: `const key = Buffer.from('coded');`, insert `"INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'code','Coded')"`; insert runtime `"INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime')"`.
3. Test `startup rejects missing, miswired or inventory-diverging protection triggers and functions`: thay khai báo đầu test và toàn bộ mảng case bằng:

```ts
const markerKind =
  'CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()';
const dropMarker = 'DROP TRIGGER require_root_marker_kind ON app_user';
const kindGuard =
  'CREATE TRIGGER guard_root_kind BEFORE INSERT OR UPDATE OF kind ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_kind()';
const lifecycle =
  'CREATE TRIGGER guard_root_lifecycle BEFORE UPDATE OF state,auth_epoch ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_lifecycle()';
const activation =
  'CREATE TRIGGER guard_root_activation BEFORE INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION public.guard_root_activation()';
const subject = (table: string) =>
  `CREATE TRIGGER guard_root_not_iam_subject BEFORE INSERT OR UPDATE ON ${table} FOR EACH ROW EXECUTE FUNCTION public.guard_root_not_iam_subject()`;
const fn = (name: string, body: string, definer = '') =>
  `CREATE OR REPLACE FUNCTION public.${name}() RETURNS trigger LANGUAGE plpgsql ${definer} SET search_path=pg_catalog,pg_temp AS $fn$${body}$fn$`;
const guardBodies = [
  ['guard_root_kind', guardRootKindBody, 'BEGIN RETURN NEW; END'],
  ['require_root_marker_kind', requireRootMarkerKindBody, 'BEGIN RETURN NULL; END'],
  ['guard_root_not_iam_subject', guardRootNotIamSubjectBody, 'BEGIN RETURN NEW; END'],
  ['guard_root_activation', guardRootActivationBody, 'BEGIN RETURN NEW; END'],
  ['guard_root_lifecycle', guardRootLifecycleBody, 'BEGIN RETURN NEW; END'],
] as const;
const iamTables = ['user_role', 'user_boundary', 'policy_rule', 'record_exception'];
const cases: (readonly [string, string])[] = [
  // Missing triggers.
  [dropMarker, markerKind],
  ['DROP TRIGGER guard_root_kind ON app_user', kindGuard],
  ['DROP TRIGGER guard_root_lifecycle ON app_user', lifecycle],
  ['DROP TRIGGER guard_root_activation ON one_time_token', activation],
  ...iamTables.map(
    (t) => [`DROP TRIGGER guard_root_not_iam_subject ON ${t}`, subject(t)] as const,
  ),
  // Marker check: not deferrable, initially immediate, wrong function, wider event, WHEN, copy.
  [
    `${dropMarker}; CREATE TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()`,
    `${dropMarker}; ${markerKind}`,
  ],
  [
    `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()`,
    `${dropMarker}; ${markerKind}`,
  ],
  [
    `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.protect_product_state()`,
    `${dropMarker}; ${markerKind}`,
  ],
  [
    `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()`,
    `${dropMarker}; ${markerKind}`,
  ],
  [
    `${dropMarker}; CREATE CONSTRAINT TRIGGER require_root_marker_kind AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (false) EXECUTE FUNCTION public.require_root_marker_kind()`,
    `${dropMarker}; ${markerKind}`,
  ],
  [
    'CREATE CONSTRAINT TRIGGER require_root_marker_kind_copy AFTER UPDATE OF kind ON app_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_root_marker_kind()',
    'DROP TRIGGER require_root_marker_kind_copy ON app_user',
  ],
  // Firing modes other than origin-only.
  [
    'ALTER TABLE user_role ENABLE REPLICA TRIGGER guard_root_not_iam_subject',
    'ALTER TABLE user_role ENABLE TRIGGER guard_root_not_iam_subject',
  ],
  [
    'ALTER TABLE app_user ENABLE ALWAYS TRIGGER require_root_marker_kind',
    'ALTER TABLE app_user ENABLE TRIGGER require_root_marker_kind',
  ],
  // Same trigger name bound to a same-named function in another schema.
  [
    `CREATE SCHEMA shadow; CREATE FUNCTION shadow.guard_root_activation() RETURNS trigger LANGUAGE plpgsql AS $f$BEGIN RETURN NEW; END$f$; REVOKE ALL ON FUNCTION shadow.guard_root_activation() FROM PUBLIC; DROP TRIGGER guard_root_activation ON one_time_token; CREATE TRIGGER guard_root_activation BEFORE INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION shadow.guard_root_activation()`,
    `DROP TRIGGER guard_root_activation ON one_time_token; ${activation}; DROP SCHEMA shadow CASCADE`,
  ],
  // Timing, event, column list and granularity.
  [
    'DROP TRIGGER guard_root_activation ON one_time_token; CREATE TRIGGER guard_root_activation AFTER INSERT ON one_time_token FOR EACH ROW EXECUTE FUNCTION public.guard_root_activation()',
    `DROP TRIGGER guard_root_activation ON one_time_token; ${activation}`,
  ],
  [
    'DROP TRIGGER guard_root_kind ON app_user; CREATE TRIGGER guard_root_kind BEFORE UPDATE OF kind ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_kind()',
    `DROP TRIGGER guard_root_kind ON app_user; ${kindGuard}`,
  ],
  [
    'DROP TRIGGER guard_root_lifecycle ON app_user; CREATE TRIGGER guard_root_lifecycle BEFORE UPDATE OF state ON app_user FOR EACH ROW EXECUTE FUNCTION public.guard_root_lifecycle()',
    `DROP TRIGGER guard_root_lifecycle ON app_user; ${lifecycle}`,
  ],
  [
    'DROP TRIGGER guard_root_not_iam_subject ON user_role; CREATE TRIGGER guard_root_not_iam_subject BEFORE INSERT OR UPDATE ON user_role FOR EACH STATEMENT EXECUTE FUNCTION public.guard_root_not_iam_subject()',
    `DROP TRIGGER guard_root_not_iam_subject ON user_role; ${subject('user_role')}`,
  ],
  // Neutralized bodies behind the same name, owner and settings.
  ...guardBodies.map(
    ([name, body, neutral]) =>
      [fn(name, neutral, 'SECURITY DEFINER'), fn(name, body, 'SECURITY DEFINER')] as const,
  ),
  [fn('protect_token_consumption', 'BEGIN RETURN NEW; END'), fn('protect_token_consumption', tokenConsumptionBody)],
  // Function inventory: overload, search_path, owner.
  [
    'CREATE FUNCTION public.guard_root_kind(int) RETURNS int LANGUAGE sql AS $f$SELECT 1$f$; REVOKE ALL ON FUNCTION public.guard_root_kind(int) FROM PUBLIC',
    'DROP FUNCTION public.guard_root_kind(int)',
  ],
  [
    'ALTER FUNCTION guard_root_not_iam_subject() SET search_path=public',
    'ALTER FUNCTION guard_root_not_iam_subject() SET search_path=pg_catalog,pg_temp',
  ],
  [
    'ALTER FUNCTION guard_root_lifecycle() OWNER TO product_migration',
    'ALTER FUNCTION guard_root_lifecycle() OWNER TO product_session_owner',
  ],
  [
    'ALTER FUNCTION protect_product_rows() OWNER TO product_session_owner',
    'ALTER FUNCTION protect_product_rows() OWNER TO product_migration',
  ],
  // Owner hardening.
  ['ALTER ROLE product_session_owner LOGIN', 'ALTER ROLE product_session_owner NOLOGIN'],
  ['GRANT product_data TO product_session_owner', 'REVOKE product_data FROM product_session_owner'],
  [
    'GRANT CREATE ON SCHEMA public TO product_session_owner',
    'REVOKE CREATE ON SCHEMA public FROM product_session_owner',
  ],
  // Exact owner ACL (spec 3.2): one grant too many or one missing.
  [
    'GRANT SELECT(password_hash) ON local_credential TO product_session_owner',
    'REVOKE SELECT(password_hash) ON local_credential FROM product_session_owner',
  ],
  [
    'GRANT UPDATE(state) ON app_user TO product_session_owner',
    'REVOKE UPDATE(state) ON app_user FROM product_session_owner',
  ],
  [
    'GRANT SELECT(role_key) ON user_role TO product_session_owner',
    'REVOKE SELECT(role_key) ON user_role FROM product_session_owner',
  ],
  [
    'REVOKE SELECT(kind) ON app_user FROM product_session_owner',
    'GRANT SELECT(kind) ON app_user TO product_session_owner',
  ],
  [
    'REVOKE SELECT ON security_bootstrap_state FROM product_session_owner',
    'GRANT SELECT ON security_bootstrap_state TO product_session_owner',
  ],
];
for (const [alter, restore] of cases) {
```

Thân vòng lặp giữ nguyên. Khối cuối test (drop function CASCADE) dùng `guard_root_activation`:

```ts
await withClient(fixture.superuser, (c) =>
  c.query('DROP FUNCTION public.guard_root_activation() CASCADE'),
);
try {
  await assert.rejects(verifyProductPrivileges(pools), /protection drift/);
} finally {
  await withClient(fixture.superuser, (c) =>
    c.query(`${fn('guard_root_activation', guardRootActivationBody, 'SECURITY DEFINER')};
        ${activation};
        REVOKE ALL ON FUNCTION public.guard_root_activation() FROM PUBLIC;
        ALTER FUNCTION public.guard_root_activation() OWNER TO product_session_owner;`),
  );
}
await verifyProductPrivileges(pools);
```

4. Test `protection function ACL is exact for every runtime login`: `const targets = ['guard_root_kind', 'require_root_marker_kind', 'guard_root_not_iam_subject', 'guard_root_activation', 'guard_root_lifecycle', 'protect_token_consumption'];`.
5. Test `startup rejects disabled or weakened protection triggers`: thay sáu case đầu (`require_root_marker`, `tginitdeferred`, hai `protect_system_activation`) và ba case `ALTER FUNCTION protect_system_activation() …` bằng:

```ts
    [
      'ALTER TABLE app_user DISABLE TRIGGER require_root_marker_kind',
      'ALTER TABLE app_user ENABLE TRIGGER require_root_marker_kind',
    ],
    [
      // Constraint triggers cannot be altered by DDL; simulate catalog drift as superuser.
      "UPDATE pg_trigger SET tginitdeferred=false WHERE tgname='require_root_marker_kind'",
      "UPDATE pg_trigger SET tginitdeferred=true WHERE tgname='require_root_marker_kind'",
    ],
    ...(['guard_root_kind', 'guard_root_lifecycle'] as const).map(
      (t) => [`ALTER TABLE app_user DISABLE TRIGGER ${t}`, `ALTER TABLE app_user ENABLE TRIGGER ${t}`] as const,
    ),
    [
      'ALTER TABLE one_time_token DISABLE TRIGGER guard_root_activation',
      'ALTER TABLE one_time_token ENABLE TRIGGER guard_root_activation',
    ],
    ...['user_role', 'user_boundary', 'policy_rule', 'record_exception'].map(
      (t) =>
        [
          `ALTER TABLE ${t} DISABLE TRIGGER guard_root_not_iam_subject`,
          `ALTER TABLE ${t} ENABLE TRIGGER guard_root_not_iam_subject`,
        ] as const,
    ),
    ['ALTER FUNCTION guard_root_kind() SECURITY INVOKER', 'ALTER FUNCTION guard_root_kind() SECURITY DEFINER'],
    [
      'ALTER FUNCTION guard_root_activation() RESET search_path',
      'ALTER FUNCTION guard_root_activation() SET search_path=pg_catalog,pg_temp',
    ],
    [
      'ALTER FUNCTION require_root_marker_kind() OWNER TO product_fence_owner',
      'ALTER FUNCTION require_root_marker_kind() OWNER TO product_session_owner',
    ],
```

giữ các case `protect_token_consumption` (disable, AFTER INSERT), `protect_account_lifecycle`, `protect_product_rows` (INSERT OR DELETE), `protect_product_state` WHEN và `zz_rewrite`; case thân `protect_product_rows` khôi phục bằng `productRowsIamBody`; xóa case thân `require_root_marker` và case `protect_system_activation … UPDATE OF user_id`. 6. Test `session projection exposes no credential…`: sau `assert.equal(rows[0]!.user_id, id);` thêm `assert.equal(rows[0]!.kind, 'iam'); assert.equal('authority_level' in rows[0]!, false);`. 7. Test `forward protection migration preserves preexisting product fixture rows`: comment `// Every forward product migration after the initial one (002..012).`, `assert.equal((await upgraded.runMigrations()).length, 11);`; thêm sau assertion label: `assert.deepEqual(await upgraded.query('SELECT kind FROM app_user'), [{ kind: 'iam' }]);`. 8. Test fault injection: `"INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Fault fixture')"`. 9. Thêm test mới cuối file:

```ts
test('012 replaced the system-role guards and recreated resolve_session with an exact ACL', async () => {
  assert.deepEqual(
    await pools.data.query(
      `SELECT to_regprocedure('public.require_root_marker()')::text marker,to_regprocedure('public.protect_system_activation()')::text activation,to_regclass('public.account_rank')::text rank,to_regclass('public.iam_account')::text iam`,
    ),
    [{ marker: null, activation: null, rank: null, iam: 'iam_account' }],
  );
  const acl = await withClient(
    fixture.superuser,
    async (c) =>
      (
        await c.query<{ owner: string; grantee: string; privilege: string }>(
          `SELECT r.rolname AS owner,COALESCE(g.rolname,'PUBLIC') AS grantee,a.privilege_type AS privilege
         FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner,aclexplode(p.proacl) a
         LEFT JOIN pg_roles g ON g.oid=a.grantee
         WHERE p.oid='public.resolve_session(bytea)'::regprocedure ORDER BY 2`,
        )
      ).rows,
  );
  assert.deepEqual(
    acl.map((r) => [r.owner, r.grantee, r.privilege]),
    [
      ['product_session_owner', 'product_authority', 'EXECUTE'],
      ['product_session_owner', 'product_data', 'EXECUTE'],
      ['product_session_owner', 'product_identity', 'EXECUTE'],
      ['product_session_owner', 'product_session_owner', 'EXECUTE'],
    ],
  );
  assert.deepEqual(
    await withClient(
      fixture.superuser,
      async (c) =>
        (
          await c.query<{ n: number }>(
            "SELECT count(*)::int n FROM information_schema.columns WHERE table_schema='public' AND column_name='authority_level'",
          )
        ).rows,
    ),
    [{ n: 0 }],
  );
});
```

`test/product-system.integration-spec.ts` (tối thiểu cho Task 3; Task 4 viết lại file):

- Dòng 123: `"INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime')"`.
- Test `persistent bootstrap races once…`: `input` bỏ `boundaries`; xóa `await assert.rejects(bootstrapProductRoot(runner, release2(), { ...input, boundaries: [] }), /boundary/);`; sau assertion `user_role … 0` thêm:

```ts
assert.deepEqual(await migration.query('SELECT kind,state FROM app_user WHERE id=$1', [target]), [
  { kind: 'root', state: 'suspended' },
]);
```

- Test `bootstrap credential cannot assign Root by SQL once the marker is initialized` đổi tên `bootstrap credential cannot promote another Root once the marker is initialized`, thân sau kiểm marker:

```ts
const second = randomUUID();
await migration.query(
  `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'second@example.test','pending')`,
  [second],
);
const denied42501 = (e: { driverError?: { code?: string } }) => e.driverError?.code === '42501';
// The previous test suspended Root; the permanent marker alone refuses another promotion.
await assert.rejects(
  runner.run('bootstrap', (tx) =>
    tx.manager.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [second]),
  ),
  denied42501,
);
// Nor can it fall back to a role assignment: the bootstrap login has no INSERT on user_role.
await assert.rejects(
  runner.run('bootstrap', (tx) =>
    tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      second,
      Buffer.from('system.root'),
    ]),
  ),
  denied42501,
);
assert.deepEqual(await migration.query('SELECT kind FROM app_user WHERE id=$1', [second]), [
  { kind: 'iam' },
]);
```

- Test offline actor: bỏ `boundaries: [],`.
- Test `system grant explicit content change/removal requires prior exact hash`: template `limitedAccounts` đổi `expression` thành `{ op: 'eq' as const, field: 'state', value: { from: 'literal' as const, value: 'active' } }` (field `authorityLevel` không còn trong declarations; test này bị xóa ở Task 4).
- Test `code-owned roles are runtime assignments…`: xóa khối `await assert.rejects(admin('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [user, Buffer.from('system.root')]), denied);` — sau `012` tiền tố `system.` không còn ý nghĩa ở DB (mọi role code-owned là runtime assignment); việc Root nằm ngoài IAM được kiểm ở `test/product-root-guards.integration-spec.ts`.

`test/product-system-regression.integration-spec.ts`:

- Bỏ thuộc tính `boundaries` ở hai input bootstrap (OIDC và `bootstrapInput`).
- Thay test `bootstrap credential cannot commit a Root assignment without the marker naming it` bằng:

```ts
test('a Root promotion commits only with the marker naming it', async () => {
  await withProduct(async (_reconciler, migration, settings) => {
    const bootstrap = await new DataSource(
      productDataSourceOptions(settings.bootstrap),
    ).initialize();
    try {
      const runner = new ProductTransactionRunner({ bootstrap });
      const denied = (e: { code?: string; driverError?: { code?: string } }) =>
        (e.driverError?.code ?? e.code) === '42501';
      const target = randomUUID();
      const other = randomUUID();
      await migration.query(`INSERT INTO app_user(id,state) VALUES($1,'pending'),($2,'pending')`, [
        target,
        other,
      ]);
      const promote = `UPDATE app_user SET kind='root' WHERE id=$1`;
      // No marker at all: the deferred check refuses the commit.
      await assert.rejects(
        runner.run('bootstrap', (tx) => tx.manager.query(promote, [target])),
        denied,
      );
      // A marker naming somebody else, and forcing the check early, are refused too.
      await assert.rejects(
        runner.run('bootstrap', async (tx) => {
          await tx.manager.query(promote, [target]);
          await tx.manager.query(
            'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
            [randomUUID(), other],
          );
        }),
        denied,
      );
      await assert.rejects(
        runner.run('bootstrap', async (tx) => {
          await tx.manager.query('SET CONSTRAINTS ALL IMMEDIATE');
          await tx.manager.query(promote, [target]);
        }),
        denied,
      );
      assert.deepEqual(await migration.query(`SELECT id FROM app_user WHERE kind='root'`), []);
      assert.deepEqual(
        await migration.query('SELECT initialized_at FROM security_bootstrap_state'),
        [{ initialized_at: null }],
      );
    } finally {
      await bootstrap.destroy();
    }
  });
});
```

- Đổi tên test cuối thành `only the bootstrap credential issues activation for Root`; nội dung còn lại không đổi (giờ do `guard_root_kind`/`guard_root_activation` từ chối).

`test/product-authorization.integration-spec.ts` (Root fixture → IAM fixture, spec mục 9):

- `roles: [{ key: 'operator', label: 'Operator fixture', authorityLevel: 1 }, { key: 'auditor', label: 'Code role without grants', authorityLevel: 1 }]`; `defaultGrants: ['read', 'update'].map((action) => ({ permission: \`item.${action}\`, role: 'operator', template: { key: 'allItems', version: 1 }, parameters: {} }))`; `systemGrants: []`.
- Thay khối `runner.run('bootstrap', …)` (gán `system.root` + marker) và vòng `for (const role of ['system.root', 'auditor'])` bằng:

```ts
// The principal is an ordinary IAM user: the code-owned operator role carries its grants.
await runner.run('admin', (tx) =>
  tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
    userId,
    utf8('operator'),
  ]),
);
// The bootstrap credential has no assignment capability at all (ADR 0012).
const other = randomUUID();
await pools.identity.query("INSERT INTO app_user(id,state) VALUES($1,'active')", [other]);
for (const role of ['operator', 'auditor'])
  await assert.rejects(
    runner.run('bootstrap', (tx) =>
      tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
        other,
        utf8(role),
      ]),
    ),
    (e: { driverError?: { code?: string } }) => e.driverError?.code === '42501',
  );
```

- Dòng 531: `"INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime deny fixture')"`.

`test/product-audit.integration-spec.ts` (actor thành IAM, event IAM giữ exact):

- `release`: thêm vào `declarations` `boundaries: [...productDeclarations.boundaries, { key: 'accountAll', version: 1, entries: [{ permission: 'account.suspend', contextRequirements: [], requiredScope: { op: 'constant', value: true } }] }]`.
- Insert user: `` `INSERT INTO app_user(id,state,email_verified) VALUES($1,'active',true),($2,'active',true)` ``.
- Xóa khối `runner.run('bootstrap', …)`; trong khối `admin`: binding `[actor, utf8('account.suspend'), utf8('accountAll')]`, và thêm grant trực tiếp:

```ts
await tx.manager.query(
  "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
  [randomUUID(), utf8('account.suspend'), actor, utf8('allAccounts')],
);
```

- Comment khối fixture: `// Fixture authority (IAM actor): direct document grants, account.suspend grant and its boundary.` Mọi assertion event giữ nguyên.

`test/product-load.integration-spec.ts:95`: `'UPDATE app_user SET auth_epoch=auth_epoch+1 WHERE id=$1'`.

`test/product-cli.integration-spec.ts`:

- Thay kiểm `user_role` sau bootstrap (dòng 210–220) bằng `SELECT kind,state FROM app_user WHERE id=$1` → `[{ kind: 'root', state: 'pending' }]`.
- `/Root assignment revoked/` → `/Root suspended/`; truy vấn cuối:

```ts
const rows = await client.query<{ kind: string; state: string; marker: boolean; audit: number }>(
  `SELECT (SELECT kind FROM app_user WHERE id=$1) kind,(SELECT state FROM app_user WHERE id=$1) state,
        (SELECT initialized_at IS NOT NULL FROM security_bootstrap_state) marker,
        (SELECT count(*)::int FROM audit_outbox WHERE event_kind=$2 AND reason='Fixture handover') audit`,
  [userId, Buffer.from('root.revoke')],
);
assert.deepEqual(rows.rows[0], { kind: 'root', state: 'suspended', marker: true, audit: 1 });
```

Hash ghim (giá trị tính từ envelope Task 1 trên release dữ liệu của Step 7; nếu khác, so lại envelope chứ không chép giá trị mới mù quáng):

- `test/system-release.spec.ts` test `product manifest hash …`: `expected = 'ba878a4b746edefaf548dc8c26e864d9a8ca5f7e1a01cac9e9fd7db51234170b'`, hash declarations `'528137d7eaf0aeb8599f473611acb0a3e9101377bf57c7d1f19352bbdcb25701'`; comment `// Release 2 data (ADR 0012) with the pre-v2 product envelope; Task 4 removes the system grant fields.`
- `apps/api/test/structure.spec.ts` test `the composed release and storage bindings are unchanged`: release `'ba878a4b746edefaf548dc8c26e864d9a8ca5f7e1a01cac9e9fd7db51234170b'`, bindings `'77d13233fa04e02cc2e6444fff57b7dec4f2d1f23c737ec9a6746006de1bb6f8'`.

`apps/api/test/product.e2e-spec.ts`:

- Dòng 84–96:

```ts
const root = randomUUID() as IdentityId;
const user = randomUUID() as IdentityId;
await ds.migration.query(
  `INSERT INTO app_user(id,email_canonical,state) VALUES($1,'root@example.test','pending'),($2,'reader@example.test','pending')`,
  [root, user],
);
const bootstrap = await bootstrapProductRoot(runner, productRelease, {
  operationId: randomUUID(),
  userId: root,
  method: 'local',
});
```

- Khối `admin` (dòng 110–128): chỉ còn insert `user_role(user, reviewer)` và `policy_rule` update trực tiếp (xóa role `operator` và gán cho `peer`).
- Dòng 257–274:

```ts
const rootPage = (await (await request('/documents')).json()) as {
  items: unknown[];
  total: string;
};
// Root is no IAM principal and holds no grant.
assert.equal(rootPage.total, '0');
assert.equal((await request(`/administration/users/${user}/suspend`, 'POST')).status, 403);
assert.equal((await request('/auth/reauthenticate', 'POST', { password })).status, 200);
assert.equal((await request(`/administration/users/${user}/suspend`, 'POST')).status, 403);
assert.equal(
  (
    await ds.migration.query<{ state: string }[]>('SELECT state FROM app_user WHERE id=$1', [user])
  )[0]?.state,
  'active',
);
```

- Khối drift (dòng 281–296): `WHERE role_key=$1` với `Buffer.from('reviewer')`, khôi phục `label='Reviewer'`.

- [ ] **Step 10: Chạy test**

Run: `pnpm run test:integration -- test/product-root-guards.integration-spec.ts test/product-database.integration-spec.ts`
Expected: PASS.

Run: `pnpm run test:integration -- test/product-system.integration-spec.ts test/product-system-regression.integration-spec.ts test/product-authorization.integration-spec.ts test/product-audit.integration-spec.ts test/product-load.integration-spec.ts test/product-cli.integration-spec.ts test/product-genesis.integration-spec.ts test/product-identity.integration-spec.ts test/product-values.integration-spec.ts test/product-fence-io.integration-spec.ts test/product-outbox.integration-spec.ts`
Expected: PASS.

Run: `pnpm run test:unit -- test/system-release.spec.ts apps/api/test/structure.spec.ts` rồi `pnpm run test:e2e`
Expected: PASS.

- [ ] **Step 11: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write <mọi file của task> && pnpm run lint && pnpm run typecheck && pnpm run test:unit && pnpm run test:integration`
Expected: exit 0.

```bash
git add packages/typeorm-postgres/src/migrations/product/012-iam-root.ts packages/typeorm-postgres/src/product-database.ts packages/typeorm-postgres/src/product-manifest.ts packages/typeorm-postgres/src/product-authority.ts apps/api/src/administration/account.declarations.ts apps/api/src/authorization/product-manifest.ts tools/product.ts test/product-root-guards.integration-spec.ts test/product-database.integration-spec.ts test/product-system.integration-spec.ts test/product-system-regression.integration-spec.ts test/product-authorization.integration-spec.ts test/product-audit.integration-spec.ts test/product-load.integration-spec.ts test/product-cli.integration-spec.ts test/system-release.spec.ts apps/api/test/structure.spec.ts apps/api/test/product.e2e-spec.ts
git commit -m "feat: migration 012 moves Root out of IAM with DB guards, exact owner ACL and release 2 data"
```

---

### Task 4: Contract release product v2

**Files:**

- Modify: `packages/typeorm-postgres/src/product-manifest.ts:28-139,230-332,359-781`
- Modify: `packages/typeorm-postgres/src/index.ts:25-31`, `packages/typeorm-postgres/src/composition.ts:20-24`
- Modify: `apps/api/src/authorization/product-manifest.ts` (`productReleaseSource`)
- Modify tests: `test/system-release.spec.ts`, `apps/api/test/structure.spec.ts`, `test/package-boundaries.spec.ts`, `test/product-values.integration-spec.ts:115-122`, `test/product-fence-io.integration-spec.ts:126-141`, `test/product-authorization.integration-spec.ts:133-150`, `test/product-system-regression.integration-spec.ts:33-163`
- Rewrite: `test/product-system.integration-spec.ts`

**Interfaces:**

- Consumes: `validateRoleKeys`, `validateReleaseContent`, `releaseContentHash`, `ReleaseContentSource`, `ValidatedReleaseContent` (Task 1).
- Produces:

```ts
export interface ProductRole {
  readonly key: string;
  readonly label: string;
}
export interface ProductReleaseSource extends ReleaseContentSource {
  readonly roles: readonly ProductRole[];
  /** Exact earlier default grants to delete; default grants stay code-owned until removed here. */
  readonly removeDefaultGrants?: readonly DefaultGrant[];
}
export interface ProductReleaseManifest extends ValidatedReleaseContent {
  readonly roles: readonly ProductRole[];
  readonly removeDefaultGrants: readonly DefaultGrant[];
  readonly hash: string;
}
export function prepareProductRelease(
  source: ProductReleaseSource,
  core: AuthorizationCore,
): ProductReleaseManifest;
// Bỏ: SystemGrant, SystemGrantRemoval, systemGrantHash, reconcileSystemGrants, stableGrantId.
// Release 2 hash ghim: e11f43e8199bf70fd4a2c8e552477b682222402510fd3d0cc35b98256f15afaa
```

- [ ] **Step 1: Viết test fail**

Trong `test/system-release.spec.ts`: xóa test `system grants require exact declared permission/template and unique stable ownership`; trong test `a failing value codec …` xóa hai dòng `systemGrants: [], removeSystemGrants: []`; đổi hash ở test `product manifest hash …` thành `'e11f43e8199bf70fd4a2c8e552477b682222402510fd3d0cc35b98256f15afaa'` (declarations giữ `528137d7…`), comment `// Release 2 (ADR 0012): product roles are key + label, no system grant fields.`; thêm:

```ts
test('product release v2: roles are key and label, system.* is reserved, no system grant fields', async () => {
  const { productReleaseSource } =
    await import('../apps/api/dist/authorization/product-manifest.js');
  const prepared = prepareProductRelease(productReleaseSource, core);
  assert.deepEqual(prepared.roles, [{ key: 'reviewer', label: 'Reviewer' }]);
  for (const field of ['systemGrants', 'removeSystemGrants'])
    assert.equal(Object.hasOwn(prepared, field), false, field);
  for (const key of ['system.root', 'system.audit'])
    assert.throws(
      () =>
        prepareProductRelease(
          { ...productReleaseSource, roles: [{ key, label: 'Reserved' }] },
          core,
        ),
      (error) =>
        error instanceof ReleaseRejectedError &&
        error.reason === 'invalid_release' &&
        /reserved/.test(error.message),
      key,
    );
});
```

`apps/api/test/structure.spec.ts`: release hash `'e11f43e8199bf70fd4a2c8e552477b682222402510fd3d0cc35b98256f15afaa'`.
`test/package-boundaries.spec.ts`: thêm `'systemGrantHash'` vào `absent` của `composition`.

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:unit -- test/system-release.spec.ts apps/api/test/structure.spec.ts test/package-boundaries.spec.ts`
Expected: FAIL — `roles` còn `authorityLevel`, `systemGrants` còn trên manifest, `system.root` chưa bị từ chối, hash vẫn `ba878a4b…`, `systemGrantHash` vẫn được export.

- [ ] **Step 3: Implement trong `product-manifest.ts`**

Imports từ `./manifest-reconciler.js`: `ReleaseRejectedError, releaseContentHash, validateReleaseContent, validateRoleKeys, type DefaultGrant, type ReleaseContentSource, type RelationSeed, type RejectReason, type SyncResult, type ValidatedReleaseContent` (bỏ `prepareRelease`, `ReleaseSource`, `VerifiedReleaseManifest`). Thay dòng 28–139 (types + `prepareProductRelease`) bằng các interface ở **Interfaces** và:

```ts
/** Release → the authorization core that prepared it (provenance; never part of the hash). */
const productVerified = new WeakMap<object, AuthorizationCore>();
export function prepareProductRelease(
  source: ProductReleaseSource,
  core: AuthorizationCore,
): ProductReleaseManifest {
  if ((source.removeDefaultGrants?.length ?? 0) > 1000)
    reject('invalid_release', 'default grant removal limit');
  // `system.` is reserved: Root lives outside IAM (ADR 0012), no role may look like a system role.
  if (source.roles.some((role) => role.key.startsWith('system.')))
    reject('invalid_release', 'role key prefix system. is reserved');
  const roleKeys = validateRoleKeys(source.roles);
  const base = validateReleaseContent(source, core, roleKeys);
  // Same exact permission/template/parameter validation as the grants being removed.
  const removeDefaultGrants = validateReleaseContent(
    { ...source, defaultGrants: source.removeDefaultGrants ?? [] },
    core,
    roleKeys,
  ).defaultGrants;
  const removedIds = new Set(removeDefaultGrants.map(grantId));
  if (
    removedIds.size !== removeDefaultGrants.length ||
    base.defaultGrants.some((g) => removedIds.has(grantId(g)))
  )
    reject('invalid_release', 'default grant removal');
  const roles = source.roles.map((role) => ({ key: role.key, label: role.label }));
  const hash = sha256(
    canonicalJson({
      base: releaseContentHash(base, roles),
      // Omitted when empty so a release without removals keeps its hash.
      ...(removeDefaultGrants.length ? { removeDefaultGrants: [...removedIds].sort() } : {}),
    }),
  );
  const release: ProductReleaseManifest = Object.freeze({
    ...base,
    roles,
    hash,
    removeDefaultGrants: Object.freeze(removeDefaultGrants),
  });
  freezeRelease(release);
  productVerified.set(release, core);
  return release;
}
```

Trong `reconcile`: xóa `await reconcileSystemGrants(m, release);`. Xóa `systemGrantHash`, `reconcileSystemGrants`, `stableGrantId` (dòng 230–332). Đổi kiểu tham số `release` của `objectId`, `apply`, `verifyApplied` từ `VerifiedReleaseManifest` sang `ProductReleaseManifest`. Xóa hằng `ownerKey`/`hashPattern` nếu không còn dùng.

`index.ts`: export từ `./product-manifest.js` chỉ còn `type ProductReleaseSource, type ProductReleaseManifest, type ProductRole`. `composition.ts`: bỏ `systemGrantHash`.

`apps/api/src/authorization/product-manifest.ts`: `roles: [{ key: 'reviewer', label: 'Reviewer' }]`, xóa `systemGrants`/`removeSystemGrants`.

- [ ] **Step 4: Chuyển fixture release còn lại**

- `test/product-values.integration-spec.ts`: `roles: []`, xóa `systemGrants`/`removeSystemGrants`.
- `test/product-fence-io.integration-spec.ts`: `roles: [{ key: 'reviewer', label: 'Reviewer fixture' }]`, xóa hai trường.
- `test/product-authorization.integration-spec.ts`: bỏ `authorityLevel` ở hai role, xóa hai trường.
- `test/product-system-regression.integration-spec.ts`: xóa `grant`; `base`:

```ts
const base = {
  sequence: '1',
  predecessor: '0',
  declarations: productDeclarations,
  roles: [{ key: 'reviewer', label: 'Reviewer' }],
  defaultGrants: [
    {
      permission: 'document.read',
      role: 'reviewer',
      template: { key: 'ownedDocuments', version: 1 },
      parameters: {},
    },
  ],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};
```

Thay ba test system grant đầu file bằng:

```ts
test('a new release cannot adopt drift in a persisted code-owned grant omitted from it', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(migration, "UPDATE policy_rule SET effect='deny' WHERE managed_by='code'");
    await assert.rejects(
      reconciler.reconcile(prepareProductRelease(base, core)),
      /drift|not_ready|immutable_definition/,
    );
    const next = prepareProductRelease(
      { ...base, sequence: '2', predecessor: '1', defaultGrants: [] },
      core,
    );
    await assert.rejects(reconciler.reconcile(next), /drift|not_ready|immutable_definition/);
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});
test('a code-owned grant with a rewritten rule ID is drift, not a fresh grant', async () => {
  await withProduct(async (reconciler, migration) => {
    await offlineAlter(migration, "UPDATE policy_rule SET rule_id=$1 WHERE managed_by='code'", [
      randomUUID(),
    ]);
    const next = prepareProductRelease({ ...base, sequence: '2', predecessor: '1' }, core);
    await assert.rejects(
      reconciler.reconcile(next),
      /drift|not_ready|collision|immutable_definition/,
    );
    assert.equal(
      (
        await migration.query<{ sequence: string }[]>(
          'SELECT release_sequence::text sequence FROM authz_state',
        )
      )[0]!.sequence,
      '1',
    );
  });
});
```

- Viết lại `test/product-system.integration-spec.ts` (giữ `before`/`after`/`reconciler()` hiện có, import bỏ `systemGrantHash`):

```ts
const base = {
  sequence: '1',
  predecessor: '0',
  declarations: productDeclarations,
  roles: [],
  defaultGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};
const release2 = () =>
  prepareProductRelease(
    { ...base, sequence: '2', predecessor: '1', roles: [{ key: 'reviewer', label: 'Reviewer' }] },
    core,
  );
const denied = (e: { driverError?: { code?: string } }) => e.driverError?.code === '42501';
```

Tests theo thứ tự: (1) `catalog first, then a role; repeated and concurrent boot do not change revision` — thân như test cũ nhưng assertion cuối:

```ts
assert.deepEqual(
  await migration.query(
    `SELECT (SELECT count(*)::int FROM role_definition WHERE substring(role_key FROM 1 FOR 7)=convert_to('system.','UTF8')) roles,(SELECT count(*)::int FROM policy_rule WHERE system_owner IS NOT NULL) grants`,
  ),
  [{ roles: 0, grants: 0 }],
);
```

(2) `same release full drift fails; rollback avoids runtime seed takeover` — như cũ, label khôi phục `'Reviewer'`, insert runtime role `"INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime','Runtime')"`, `collision` dùng `roles: [{ key: 'runtime', label: 'Root' }]` và `sequence: '3', predecessor: '2'`. (3) và (4): hai test bootstrap/marker đúng như bản Task 3. (5) `code-owned roles are runtime assignments; their grants leave only by explicit release removal` — như cũ với `roles = [{ key: 'reviewer', label: 'Reviewer' }]`, `fifth` = `sequence: '3', predecessor: '2'`, `sixth` = `'4'/'3'`, release thứ bảy `'5'/'4'`; xóa khối `assert.rejects(admin('INSERT INTO user_role…system.root…'), denied)` (role đó không còn; Root ngoài IAM được kiểm ở `product-root-guards`). (6) test offline actor như Task 3. Xóa test `system grant explicit content change/removal requires prior exact hash`.

- [ ] **Step 5: Chạy test**

Run: `pnpm run test:unit -- test/system-release.spec.ts apps/api/test/structure.spec.ts test/package-boundaries.spec.ts`
Expected: PASS.

Run: `pnpm run test:integration -- test/product-system.integration-spec.ts test/product-system-regression.integration-spec.ts test/product-values.integration-spec.ts test/product-fence-io.integration-spec.ts test/product-authorization.integration-spec.ts test/product-genesis.integration-spec.ts test/product-root-guards.integration-spec.ts test/product-cli.integration-spec.ts`
Expected: PASS.

- [ ] **Step 6: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write <mọi file của task> && pnpm run lint && pnpm run typecheck && pnpm run test:unit && pnpm run test:e2e`
Expected: exit 0.

```bash
git add packages/typeorm-postgres/src/product-manifest.ts packages/typeorm-postgres/src/index.ts packages/typeorm-postgres/src/composition.ts apps/api/src/authorization/product-manifest.ts test/system-release.spec.ts apps/api/test/structure.spec.ts test/package-boundaries.spec.ts test/product-values.integration-spec.ts test/product-fence-io.integration-spec.ts test/product-authorization.integration-spec.ts test/product-system-regression.integration-spec.ts test/product-system.integration-spec.ts
git commit -m "feat: product release v2 without system grants or rank; system.* role keys reserved"
```

---

### Task 5: Nâng cấp từ release 1 thật qua migration `012`

**Files:**

- Modify: `packages/typeorm-postgres/src/product-database.ts:62-158` (tham số `migrations`)
- Create: `test/fixtures/release-one/product-manifest.ts`, `test/fixtures/release-one/account.declarations.ts`, `test/fixtures/release-one/document.declarations.ts`, `test/fixtures/release-one/release.ts`
- Create: `test/product-iam-migration.integration-spec.ts`

**Interfaces:**

- Consumes: `ProductIamRoot1792108800012` và thông điệp lỗi (Task 3); `createProductRelease` release 2 (Task 4).
- Produces:

```ts
// packages/typeorm-postgres/src/product-database.ts (entrypoint ./operations, chữ ký mở rộng tương thích)
export async function provisionProductDatabase(
  admin: PostgresConnectionSettings,
  passwords: Readonly<Record<ProductDatabasePurpose, string>>,
  migrations: readonly (typeof productMigrations)[number][] = productMigrations,
): Promise<Record<ProductDatabasePurpose, PostgresConnectionSettings>>;
// test/fixtures/release-one/release.ts
export const releaseOneSource: ProductReleaseSource; // kiểu của bản đóng băng
export function prepareReleaseOne(
  core: AuthorizationCore,
  source?: ProductReleaseSource,
): ProductReleaseManifest;
```

- [ ] **Step 1: Tham số `migrations` cho provisioning**

```ts
/**
 * Offline provisioning only; this credential must never be wired into the API. `migrations` is
 * the forward list to run (default: all). Upgrade rehearsals pass a prefix, e.g. up to 011.
 */
export async function provisionProductDatabase(
  admin: PostgresConnectionSettings,
  passwords: Readonly<Record<ProductDatabasePurpose, string>>,
  migrations: readonly (typeof productMigrations)[number][] = productMigrations,
): Promise<Record<ProductDatabasePurpose, PostgresConnectionSettings>> {
```

và DataSource của login migration:

```ts
const migration = await new DataSource({
  ...productDataSourceOptions(connections.migration),
  migrations: [...migrations],
}).initialize();
```

- [ ] **Step 2: Đóng băng release 1 của `50d6053`**

```bash
mkdir -p test/fixtures/release-one
git show 50d6053:packages/typeorm-postgres/src/product-manifest.ts > test/fixtures/release-one/product-manifest.ts
git show 50d6053:apps/api/src/administration/account.declarations.ts > test/fixtures/release-one/account.declarations.ts
git show 50d6053:apps/api/src/documents/document.declarations.ts > test/fixtures/release-one/document.declarations.ts
```

Sửa duy nhất những chỗ sau (ghi lý do ở dòng đầu mỗi file: `// Frozen copy of 50d6053 (release 1 write path) for upgrade tests; do not edit beyond imports.`):

- `product-manifest.ts`: `from './manifest-reconciler.js'` → `from '@base-authorization/typeorm-postgres/legacy'`; `from './product-transaction.js'` → `from '@base-authorization/typeorm-postgres/composition'`; `from './product-audit.js'` → `from '@base-authorization/typeorm-postgres/operations'`. Node strip-types và `erasableSyntaxOnly` không nhận parameter property, nên constructor của `ProductManifestReconciler` thành:

```ts
interface FrozenReconcilerOptions {
  /** The runtime's core; a release prepared by another core is refused. */
  core: AuthorizationCore;
  actor: IdentityId;
  capabilities: { validators: readonly string[]; obligationHandlers: readonly string[] };
}
export class ProductManifestReconciler {
  private readonly runner: ProductTransactionRunner;
  private readonly options: FrozenReconcilerOptions;
  constructor(runner: ProductTransactionRunner, options: FrozenReconcilerOptions) {
    this.runner = runner;
    this.options = options;
    if (!options.core.isCanonicalUuid(options.actor)) throw new TypeError('Invalid manifest actor');
  }
```

- `account.declarations.ts` và `document.declarations.ts`: `import type { ProductReleaseSource, ProductStorageBindings } from '@base-authorization/typeorm-postgres';` → `import type { ProductReleaseSource } from './product-manifest.ts';` và `import type { ProductStorageBindings } from '@base-authorization/typeorm-postgres';`.

Create `test/fixtures/release-one/release.ts` (bản sao dòng 36–65 của `apps/api/src/authorization/product-manifest.ts` tại `50d6053`):

```ts
// Release 1 exactly as 50d6053 published it (apps/api/src/authorization/product-manifest.ts).
import type { AuthorizationCore, SystemDeclarations } from '@base-authorization/core';
import {
  prepareProductRelease,
  type ProductReleaseManifest,
  type ProductReleaseSource,
} from './product-manifest.ts';
import { accountDeclarations, accountSystemGrants } from './account.declarations.ts';
import { documentDeclarations, documentDefaultGrants } from './document.declarations.ts';

const fragments = [documentDeclarations, accountDeclarations];
const releaseOneDeclarations: SystemDeclarations = {
  capabilities: { validators: ['fresh@1'], obligationHandlers: ['audit@1'] },
  resources: fragments.flatMap((f) => f.resources),
  policies: fragments.flatMap((f) => f.policies),
  templates: fragments.flatMap((f) => f.templates),
  boundaries: fragments.flatMap((f) => f.boundaries),
  relations: [],
};
export const releaseOneSource: ProductReleaseSource = {
  sequence: '1',
  predecessor: '0',
  declarations: releaseOneDeclarations,
  roles: [
    { key: 'system.root', label: 'Root', authorityLevel: 1000 },
    { key: 'reviewer', label: 'Reviewer', authorityLevel: 10 },
  ],
  defaultGrants: documentDefaultGrants,
  systemGrants: accountSystemGrants,
  removeSystemGrants: [],
  seeds: [],
  removeSeeds: [],
  boundaryBindings: [],
  removeBoundaryBindings: [],
};
export function prepareReleaseOne(
  core: AuthorizationCore,
  source: ProductReleaseSource = releaseOneSource,
): ProductReleaseManifest {
  return prepareProductRelease(source, core);
}
```

- [ ] **Step 3: Viết test nâng cấp**

Create `test/product-iam-migration.integration-spec.ts`:

```ts
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import type { ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductIdentityService,
  ProductManifestReconciler,
  ProductTransactionRunner,
  createProductPasswordHasher,
  verifyProductPrivileges,
} from '@base-authorization/typeorm-postgres/composition';
import {
  bootstrapProductRoot,
  productDataSourceOptions,
  productMigrations,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import { ProductIamRoot1792108800012 } from '../packages/typeorm-postgres/dist/migrations/product/012-iam-root.js';
import {
  createProductAuthorizationCore,
  createProductRelease,
} from '../apps/api/dist/authorization/product-manifest.js';
import * as one from './fixtures/release-one/product-manifest.ts';
import { prepareReleaseOne, releaseOneSource } from './fixtures/release-one/release.ts';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
const releaseTwo = createProductRelease(core);
const utf8 = (value: string) => Buffer.from(value);
const password = 'a long unique upgrade fixture password';
const capabilities = { validators: ['fresh@1'], obligationHandlers: ['audit@1'] };
const rootBoundary = [
  { permission: 'account.suspend', boundary: { key: 'rootAccounts', version: 1 } },
];
const userRoleGuards = ['protect_product_rows', 'require_root_marker', 'protect_system_activation'];
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
    p,
    randomBytes(24).toString('hex'),
  ]),
) as Record<ProductDatabasePurpose, string>;
let fixture: TestPostgres;
before(async () => {
  fixture = await startPostgres();
});
after(async () => {
  await fixture?.stop();
});

type Pools = Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
interface ReleaseOne {
  readonly pools: Pools;
  readonly migration: DataSource;
  readonly runner: ProductTransactionRunner;
  readonly release: one.ProductReleaseManifest;
  /** Real provisioning with every migration: 012 runs as product_migration (spec 4.1). */
  readonly upgrade: () => Promise<unknown>;
  readonly close: () => Promise<void>;
}
/** A database migrated to 011 by real provisioning and synced with release 1 by 50d6053 code. */
async function releaseOneDatabase(name: string, source = releaseOneSource): Promise<ReleaseOne> {
  await withClient(fixture.superuser, (c) => c.query(`CREATE DATABASE ${name}`));
  const admin = { ...fixture.superuser, database: name };
  const settings = await provisionProductDatabase(admin, passwords, productMigrations.slice(0, 11));
  const pools = {} as Pools;
  for (const p of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[p] = await new DataSource(productDataSourceOptions(settings[p])).initialize();
  const migration = await new DataSource(productDataSourceOptions(settings.migration)).initialize();
  const runner = new ProductTransactionRunner(pools);
  const release = one.prepareProductRelease(source, core);
  await new one.ProductManifestReconciler(runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities,
  }).reconcile(release);
  return {
    pools,
    migration,
    runner,
    release,
    upgrade: () => provisionProductDatabase(admin, passwords),
    close: async () => {
      for (const pool of Object.values(pools)) await pool.destroy();
      await migration.destroy();
    },
  };
}
const pending = async (db: ReleaseOne, email: string): Promise<IdentityId> => {
  const id = randomUUID() as IdentityId;
  await db.migration.query(
    `INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`,
    [id, email],
  );
  return id;
};
/** Table-owner tampering for states no command can reach (guards off for one statement). */
async function asOwner(db: ReleaseOne, sql: string, params: unknown[]): Promise<void> {
  await db.migration.transaction(async (m) => {
    for (const t of userRoleGuards) await m.query(`ALTER TABLE user_role DISABLE TRIGGER ${t}`);
    await m.query(sql, params);
    for (const t of userRoleGuards) await m.query(`ALTER TABLE user_role ENABLE TRIGGER ${t}`);
  });
}
/** 012 refused: everything rolled back, the database is still at release 1 without `kind`. */
async function refusedUpgrade(db: ReleaseOne, message: RegExp, label = String(message)) {
  await assert.rejects(db.upgrade(), message, label);
  assert.deepEqual(
    await db.migration.query(
      `SELECT (SELECT count(*)::int FROM information_schema.columns WHERE table_schema='public' AND table_name='app_user' AND column_name='kind') kind,
        (SELECT count(*)::int FROM migrations WHERE name='ProductIamRoot1792108800012') applied,
        (SELECT release_sequence::text FROM authz_state) sequence`,
    ),
    [{ kind: 0, applied: 0, sequence: '1' }],
    label,
  );
}
const syncReleaseTwo = (db: ReleaseOne) =>
  new ProductManifestReconciler(db.runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities,
  }).reconcile(releaseTwo);

test('the frozen release 1 is byte-identical to the published one; 012 cannot be reverted', async () => {
  assert.equal(
    prepareReleaseOne(core).hash,
    'c1fbb3451d9292477ae24ed1d342f581612b68d9519ffccce6f08a9a3c874fa9',
  );
  await assert.rejects(
    new ProductIamRoot1792108800012().down(),
    /irreversible; restore from backup/,
  );
});

test('unmarked release 1: drift and a stray holder roll back; then 012 upgrades and release 2 syncs', async () => {
  const db = await releaseOneDatabase('upgrade_unmarked');
  try {
    // Binary of release 2 on the 011 schema: the startup probe refuses it.
    await assert.rejects(verifyProductPrivileges(db.pools), /privilege drift|protection drift/);
    const relabel = (label: string) =>
      db.migration.transaction(async (m) => {
        await m.query('ALTER TABLE role_definition DISABLE TRIGGER protect_product_rows');
        await m.query('UPDATE role_definition SET label=$1 WHERE role_key=$2', [
          label,
          utf8('reviewer'),
        ]);
        await m.query('ALTER TABLE role_definition ENABLE TRIGGER protect_product_rows');
      });
    await relabel('drift');
    await refusedUpgrade(db, /code-owned facts drifted; repair before migration/);
    await relabel('Reviewer');
    const stray = await pending(db, 'stray@example.test');
    await asOwner(db, 'INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      stray,
      utf8('system.root'),
    ]);
    await refusedUpgrade(db, /does not match the bootstrap marker/);
    await asOwner(db, 'DELETE FROM user_role WHERE user_id=$1', [stray]);
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query(
        `SELECT to_regprocedure('public.require_root_marker()')::text marker,to_regprocedure('public.protect_system_activation()')::text activation,
          (SELECT count(*)::int FROM role_definition WHERE role_key=$1) roles,
          (SELECT count(*)::int FROM permission_boundary WHERE boundary_key=$2) boundaries,
          (SELECT release_sequence::text FROM authz_state) sequence`,
        [utf8('system.root'), utf8('rootAccounts')],
      ),
      [{ marker: null, activation: null, roles: 0, boundaries: 1, sequence: '1' }],
    );
    await verifyProductPrivileges(db.pools);
    assert.equal((await syncReleaseTwo(db)).changed, true);
    const next = await pending(db, 'first-root@example.test');
    assert.ok(
      (
        await bootstrapProductRoot(db.runner, releaseTwo, {
          operationId: randomUUID(),
          userId: next,
          method: 'local',
        })
      ).initialized,
    );
    assert.deepEqual(await db.migration.query('SELECT kind FROM app_user WHERE id=$1', [next]), [
      { kind: 'root' },
    ]);
  } finally {
    await db.close();
  }
});

test('a Root holder keeps state and credential and loses every IAM fact; other holder shapes fail', async () => {
  const db = await releaseOneDatabase('upgrade_holder');
  try {
    const target = await pending(db, 'holder@example.test');
    const bootstrap = await one.bootstrapProductRoot(db.runner, db.release, {
      operationId: randomUUID(),
      userId: target,
      method: 'local',
      boundaries: rootBoundary,
    });
    assert.ok(bootstrap.activationSecret);
    const identity = new ProductIdentityService(
      db.runner,
      await createProductPasswordHasher(new Set()),
    );
    await identity.activate(bootstrap.activationSecret, password, 'holder');
    const document = randomUUID();
    await db.runner.run('admin', async (tx) => {
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [document, utf8('document'), utf8(document)],
      );
      await tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
        [randomUUID(), utf8('document.read'), target, utf8('ownedDocuments')],
      );
      await tx.manager.query(
        "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,'allow','manual',statement_timestamp(),'fixture',$5)",
        [randomUUID(), document, utf8('document'), utf8('document.read'), target],
      );
      await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
        target,
        utf8('reviewer'),
      ]);
    });
    const other = await pending(db, 'other@example.test');
    const holder = (sql: string, user: string) => asOwner(db, sql, [user, utf8('system.root')]);
    await holder('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', other);
    await refusedUpgrade(db, /more than one Root holder/);
    await holder('DELETE FROM user_role WHERE user_id=$1 AND role_key=$2', target);
    await refusedUpgrade(db, /does not match the bootstrap marker/);
    await holder('DELETE FROM user_role WHERE user_id=$1 AND role_key=$2', other);
    await holder('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', target);
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query(
        `SELECT kind,state,(SELECT count(*)::int FROM user_role WHERE user_id=$1)+(SELECT count(*)::int FROM user_boundary WHERE user_id=$1)
          +(SELECT count(*)::int FROM policy_rule WHERE user_id=$1)+(SELECT count(*)::int FROM record_exception WHERE user_id=$1) facts
         FROM app_user WHERE id=$1`,
        [target],
      ),
      [{ kind: 'root', state: 'active', facts: 0 }],
    );
    assert.ok((await identity.login('holder@example.test', password, 'holder')).secret);
    await verifyProductPrivileges(db.pools);
    assert.equal((await syncReleaseTwo(db)).changed, true);
    await assert.rejects(
      bootstrapProductRoot(db.runner, releaseTwo, {
        operationId: randomUUID(),
        userId: await pending(db, 'late@example.test'),
        method: 'local',
      }),
      /already initialized/,
    );
  } finally {
    await db.close();
  }
});

test('a revoked Root (real bootstrap → revoke-root) stays IAM; any allow source keeps its binding live', async () => {
  const db = await releaseOneDatabase('upgrade_revoked');
  try {
    const former = await pending(db, 'former@example.test');
    await one.bootstrapProductRoot(db.runner, db.release, {
      operationId: randomUUID(),
      userId: former,
      method: 'local',
      boundaries: rootBoundary,
    });
    assert.deepEqual(
      await one.revokeProductRoot(
        db.runner,
        { operationId: randomUUID(), userId: former, approval: 'CHG-upgrade', reason: 'Fixture' },
        core,
      ),
      { revoked: true },
    );
    const account = randomUUID();
    await db.runner.run('admin', async (tx) => {
      await tx.manager.query(
        "INSERT INTO role_definition(role_key,managed_by,authority_level,label) VALUES($1,'runtime',1,'Operator')",
        [utf8('operator')],
      );
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [account, utf8('account'), utf8(former)],
      );
    });
    type Fact = readonly [string, readonly unknown[]];
    const rule = (subject: 'user_id' | 'role_key', effect: 'allow' | 'deny'): Fact => [
      `INSERT INTO policy_rule(rule_id,permission_key,${subject},effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'${effect}',$4,1,'{}','runtime')`,
      [
        randomUUID(),
        utf8('account.suspend'),
        subject === 'user_id' ? former : utf8('operator'),
        utf8('allAccounts'),
      ],
    ];
    const exception = (subject: 'user_id' | 'role_key'): Fact => [
      `INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,${subject},effect,purpose,starts_at,reason,issued_by) VALUES($1,$2,$3,$4,$5,'allow','manual',statement_timestamp(),'fixture',$6)`,
      [
        randomUUID(),
        account,
        utf8('account'),
        utf8('account.suspend'),
        subject === 'user_id' ? former : utf8('operator'),
        former,
      ],
    ];
    const assigned: Fact = [
      'INSERT INTO user_role(user_id,role_key) VALUES($1,$2)',
      [former, utf8('operator')],
    ];
    const write = (facts: readonly Fact[]) =>
      db.runner.run('admin', async (tx) => {
        for (const [sql, params] of facts) await tx.manager.query(sql, [...params]);
      });
    const clear = () =>
      db.runner.run('admin', async (tx) => {
        await tx.manager.query('DELETE FROM record_exception WHERE permission_key=$1', [
          utf8('account.suspend'),
        ]);
        await tx.manager.query(
          "DELETE FROM policy_rule WHERE permission_key=$1 AND managed_by='runtime'",
          [utf8('account.suspend')],
        );
        await tx.manager.query('DELETE FROM user_role WHERE user_id=$1', [former]);
      });
    for (const [label, facts] of [
      ['direct allow rule', [rule('user_id', 'allow')]],
      ['allow rule through a role', [assigned, rule('role_key', 'allow')]],
      ['direct allow exception', [exception('user_id')]],
      ['allow exception through a role', [assigned, exception('role_key')]],
      ['allow and deny together', [rule('user_id', 'allow'), rule('user_id', 'deny')]],
    ] as const) {
      await write(facts);
      await refusedUpgrade(db, /former Root boundary binding is not inert/, label);
      await clear();
    }
    // Only a deny remains: the binding is inert, 012 removes it and keeps the deny.
    await write([rule('user_id', 'deny')]);
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query(
        `SELECT kind,(SELECT count(*)::int FROM user_boundary WHERE user_id=$1) bindings,(SELECT count(*)::int FROM policy_rule WHERE user_id=$1 AND effect='deny') denies FROM app_user WHERE id=$1`,
        [former],
      ),
      [{ kind: 'iam', bindings: 0, denies: 1 }],
    );
    assert.equal((await syncReleaseTwo(db)).changed, true);
    await assert.rejects(
      bootstrapProductRoot(db.runner, releaseTwo, {
        operationId: randomUUID(),
        userId: await pending(db, 'next@example.test'),
        method: 'local',
      }),
      /already initialized/,
    );
  } finally {
    await db.close();
  }
});

test('a revoked Root without facts converts; an IAM user still bound to rootAccounts@1 blocks release 2', async () => {
  const db = await releaseOneDatabase('upgrade_bound_member');
  try {
    const former = await pending(db, 'former2@example.test');
    await one.bootstrapProductRoot(db.runner, db.release, {
      operationId: randomUUID(),
      userId: former,
      method: 'local',
      boundaries: rootBoundary,
    });
    await one.revokeProductRoot(
      db.runner,
      { operationId: randomUUID(), userId: former, approval: 'CHG-upgrade', reason: 'Fixture' },
      core,
    );
    const member = randomUUID();
    await db.migration.query(`INSERT INTO app_user(id,state) VALUES($1,'active')`, [member]);
    await db.runner.run('admin', (tx) =>
      tx.manager.query(
        'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
        [member, utf8('account.suspend'), utf8('rootAccounts')],
      ),
    );
    await db.upgrade();
    assert.deepEqual(
      await db.migration.query('SELECT count(*)::int n FROM user_boundary WHERE user_id=$1', [
        former,
      ]),
      [{ n: 0 }],
    );
    await assert.rejects(syncReleaseTwo(db), /definition_in_use/);
  } finally {
    await db.close();
  }
});

test('an unknown system.* role is surfaced, never converted silently', async () => {
  const db = await releaseOneDatabase('upgrade_system_role', {
    ...releaseOneSource,
    roles: [...releaseOneSource.roles, { key: 'system.audit', label: 'Audit', authorityLevel: 1 }],
  });
  try {
    await refusedUpgrade(db, /unknown system\.\* role/);
  } finally {
    await db.close();
  }
});

test('a fresh database migrates to 012 and takes release 2 through genesis', async () => {
  await withClient(fixture.superuser, (c) => c.query('CREATE DATABASE upgrade_fresh'));
  const settings = await provisionProductDatabase(
    { ...fixture.superuser, database: 'upgrade_fresh' },
    passwords,
  );
  const sync = await new DataSource(productDataSourceOptions(settings.sync)).initialize();
  try {
    const result = await new ProductManifestReconciler(new ProductTransactionRunner({ sync }), {
      core,
      actor: randomUUID() as IdentityId,
      capabilities,
    }).reconcile(releaseTwo);
    assert.equal(result.changed, true);
  } finally {
    await sync.destroy();
  }
});
```

- [ ] **Step 4: Chạy test**

Run: `pnpm run test:integration -- test/product-iam-migration.integration-spec.ts`
Expected: PASS. Nếu FAIL, sửa `012` hoặc fixture đóng băng theo spec (không đổi assertion); test hash đầu file bảo đảm fixture là release 1 thật.

- [ ] **Step 5: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write packages/typeorm-postgres/src/product-database.ts test/fixtures/release-one test/product-iam-migration.integration-spec.ts && pnpm run lint && pnpm run typecheck && pnpm run test:unit && pnpm run test:integration -- test/product-database.integration-spec.ts`
Expected: exit 0.

```bash
git add packages/typeorm-postgres/src/product-database.ts test/fixtures/release-one test/product-iam-migration.integration-spec.ts
git commit -m "test: upgrade from the real release 1 through migration 012 for every backfill case"
```

---

### Task 6: Protocol khóa — concurrency hai connection

**Files:**

- Create: `test/product-root-concurrency.integration-spec.ts`
- Modify (chỉ khi test lộ lỗi): `packages/typeorm-postgres/src/migrations/product/012-iam-root.ts`

**Interfaces:**

- Consumes: guard `guard_root_kind`, `guard_root_not_iam_subject`, `guard_root_activation` và thông điệp `requires READ COMMITTED` (Task 3).
- Produces: không.

- [ ] **Step 1: Viết test**

```ts
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type pg from 'pg';
import type { IdentityId } from '@base-authorization/core';
import type { ProductDatabasePurpose } from '@base-authorization/typeorm-postgres';
import {
  ProductManifestReconciler,
  ProductTransactionRunner,
  prepareProductRelease,
} from '@base-authorization/typeorm-postgres/composition';
import {
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import {
  createProductAuthorizationCore,
  productDeclarations,
  productReleaseSource,
} from '../apps/api/dist/authorization/product-manifest.js';
import { openClient, startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
const utf8 = (value: string) => Buffer.from(value);
const release = prepareProductRelease(
  {
    ...productReleaseSource,
    declarations: {
      ...productDeclarations,
      boundaries: [
        ...productDeclarations.boundaries,
        {
          key: 'documentLimit',
          version: 1,
          entries: [
            {
              permission: 'document.read',
              contextRequirements: [],
              requiredScope: { op: 'constant', value: true },
            },
          ],
        },
      ],
    },
  },
  core,
);
const object = randomUUID();
/** One write per IAM fact kind and the activation token, by its real runtime login ($1 = subject). */
const attachments = [
  {
    name: 'user_role',
    login: 'authority',
    sql: 'INSERT INTO user_role(user_id,role_key) VALUES($1,$2)',
    params: () => [utf8('reviewer')],
  },
  {
    name: 'user_boundary',
    login: 'authority',
    sql: 'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
    params: () => [utf8('document.read'), utf8('documentLimit')],
  },
  {
    name: 'policy_rule',
    login: 'authority',
    sql: "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($2,$3,$1,'allow',$4,1,'{}','runtime')",
    params: () => [randomUUID(), utf8('document.read'), utf8('ownedDocuments')],
  },
  {
    name: 'record_exception',
    login: 'authority',
    sql: "INSERT INTO record_exception(exception_id,object_id,type_key,permission_key,user_id,effect,purpose,starts_at,reason,issued_by) VALUES($2,$3,$4,$5,$1,'allow','manual',statement_timestamp(),'fixture',$1)",
    params: () => [randomUUID(), object, utf8('document'), utf8('document.read')],
  },
  {
    name: 'activation token',
    login: 'identity',
    sql: "INSERT INTO one_time_token(token_hash,user_id,purpose,expires_at) VALUES($2,$1,'activation',statement_timestamp()+interval '15 minutes')",
    params: () => [randomBytes(32)],
  },
] as const;
let fixture: TestPostgres;
let connections: Awaited<ReturnType<typeof provisionProductDatabase>>;
let migration: DataSource;
let admin: pg.Client;

before(async () => {
  fixture = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
      p,
      randomBytes(24).toString('hex'),
    ]),
  ) as Record<ProductDatabasePurpose, string>;
  connections = await provisionProductDatabase(fixture.superuser, passwords);
  migration = await new DataSource(productDataSourceOptions(connections.migration)).initialize();
  admin = await openClient(fixture.superuser);
  const sync = await new DataSource(productDataSourceOptions(connections.sync)).initialize();
  const authority = await new DataSource(
    productDataSourceOptions(connections.authority),
  ).initialize();
  try {
    const runner = new ProductTransactionRunner({ sync, authority });
    await new ProductManifestReconciler(runner, {
      core,
      actor: randomUUID() as IdentityId,
      capabilities: release.declarations.capabilities,
    }).reconcile(release);
    await runner.run('admin', (tx) =>
      tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [object, utf8('document'), utf8(object)],
      ),
    );
  } finally {
    await sync.destroy();
    await authority.destroy();
  }
});
after(async () => {
  await admin?.end();
  await migration?.destroy();
  await fixture?.stop();
});

const pendingUser = async () => {
  const id = randomUUID();
  await migration.query(`INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`, [
    id,
    `${id}@example.test`,
  ]);
  return id;
};
const pidOf = async (client: pg.Client) =>
  (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
/** Deterministic ordering: returns once the backend waits on a lock held by another one. */
async function waitUntilBlocked(pid: number): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt++) {
    const { rows } = await admin.query<{ blocked: boolean }>(
      'SELECT cardinality(pg_blocking_pids($1))>0 AS blocked',
      [pid],
    );
    if (rows[0]?.blocked) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`backend ${pid} never waited for a lock`);
}
const outcome = (work: Promise<unknown>) =>
  work.then(
    () => 'committed',
    (error: { code?: string }) => error.code ?? 'error',
  );
const factCount = async (user: string) =>
  (
    await migration.query<{ n: number }[]>(
      `SELECT (SELECT count(*)::int FROM user_role WHERE user_id=$1)+(SELECT count(*)::int FROM user_boundary WHERE user_id=$1)
        +(SELECT count(*)::int FROM policy_rule WHERE user_id=$1)+(SELECT count(*)::int FROM record_exception WHERE user_id=$1)
        +(SELECT count(*)::int FROM one_time_token WHERE user_id=$1) AS n`,
      [user],
    )
  )[0]!.n;

test('a promotion waiting behind an uncommitted fact or token is refused once the writer commits', async () => {
  for (const attachment of attachments) {
    const target = await pendingUser();
    const writer = await openClient(connections[attachment.login]);
    const promoter = await openClient(connections.bootstrap);
    try {
      await writer.query('BEGIN');
      await writer.query(attachment.sql, [target, ...attachment.params()]);
      const pid = await pidOf(promoter);
      await promoter.query('BEGIN');
      const lock = promoter.query('SELECT 1 FROM app_user WHERE id=$1 FOR NO KEY UPDATE', [target]);
      await waitUntilBlocked(pid);
      await writer.query('COMMIT');
      await lock;
      assert.equal(
        await outcome(promoter.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target])),
        '42501',
        attachment.name,
      );
      await promoter.query('ROLLBACK');
    } finally {
      await writer.end();
      await promoter.end();
    }
  }
});

test('a promotion outside READ COMMITTED is refused with real credentials outside the runner', async () => {
  for (const level of ['REPEATABLE READ', 'SERIALIZABLE']) {
    const target = await pendingUser();
    const promoter = await openClient(connections.bootstrap);
    try {
      await promoter.query(`BEGIN ISOLATION LEVEL ${level}`);
      await promoter.query('SELECT 1 FROM app_user WHERE id=$1 FOR NO KEY UPDATE', [target]);
      await assert.rejects(
        promoter.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target]),
        /requires READ COMMITTED/,
        level,
      );
      await promoter.query('ROLLBACK');
    } finally {
      await promoter.end();
    }
  }
});

test('ordinary IAM facts and invitations succeed with real credentials (the guard owner can lock)', async () => {
  const target = await pendingUser();
  for (const attachment of attachments)
    await withClient(connections[attachment.login], (c) =>
      c.query(attachment.sql, [target, ...attachment.params()]),
    );
  assert.equal(await factCount(target), attachments.length);
});

test('facts and tokens written while a promotion holds the target wait, then are refused', async () => {
  const target = await pendingUser();
  const promoter = await openClient(connections.bootstrap);
  const writers = await Promise.all(attachments.map((a) => openClient(connections[a.login])));
  try {
    await promoter.query('BEGIN');
    await promoter.query('SELECT 1 FROM app_user WHERE id=$1 FOR NO KEY UPDATE', [target]);
    await promoter.query(`UPDATE app_user SET kind='root' WHERE id=$1`, [target]);
    const waiting: { name: string; result: Promise<string> }[] = [];
    for (const [index, writer] of writers.entries()) {
      const attachment = attachments[index]!;
      const pid = await pidOf(writer);
      const result = outcome(writer.query(attachment.sql, [target, ...attachment.params()]));
      await waitUntilBlocked(pid);
      waiting.push({ name: attachment.name, result });
    }
    await promoter.query(
      'UPDATE security_bootstrap_state SET operation_id=$1,target_user_id=$2,initialized_at=statement_timestamp() WHERE singleton',
      [randomUUID(), target],
    );
    await promoter.query('COMMIT');
    for (const { name, result } of waiting) assert.equal(await result, '42501', name);
    assert.deepEqual(await migration.query('SELECT kind FROM app_user WHERE id=$1', [target]), [
      { kind: 'root' },
    ]);
    assert.equal(await factCount(target), 0);
  } finally {
    await promoter.end();
    for (const writer of writers) await writer.end();
  }
});
```

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:integration -- test/product-root-concurrency.integration-spec.ts`
Expected: PASS (guard đã có từ Task 3). Kiểm lại đúng nguyên nhân: tạm xóa ` FOR SHARE` trong `guardRootNotIamSubjectBody` → test cuối FAIL với `never waited for a lock`; khôi phục ngay.

- [ ] **Step 3: Kiểm tra và commit**

Run: `pnpm exec prettier --write test/product-root-concurrency.integration-spec.ts && pnpm run lint && pnpm run typecheck`
Expected: exit 0.

```bash
git add test/product-root-concurrency.integration-spec.ts
git commit -m "test: Root promotion and IAM fact writes serialize on the account row"
```

---

### Task 7: Bypass Root, fresh-auth SQL và audit Root trong `access`

**Files:**

- Modify: `packages/typeorm-postgres/src/product-authority.ts:1-272`
- Modify: `packages/typeorm-postgres/src/product-audit.ts:9-149`
- Modify: `packages/typeorm-postgres/src/composition.ts:13`
- Create: `test/product-root.integration-spec.ts`
- Modify: `test/package-boundaries.spec.ts` (`composition.present`), `apps/api/test/product.e2e-spec.ts:257-266`

**Interfaces:**

- Consumes: `AuthorizationCore.planUnrestricted` (Task 2); `resolve_session(...).kind` (Task 3).
- Produces:

```ts
// packages/typeorm-postgres/src/product-authority.ts (./composition)
export const PRODUCT_FRESH_AUTH_SQL: string;
// "(reauthenticated_at IS NOT NULL AND reauthenticated_at<=statement_timestamp() AND statement_timestamp()-reauthenticated_at<interval '300 seconds')"

// packages/typeorm-postgres/src/product-audit.ts
type RequestedKey = { readonly resource: string; readonly keyKind: KeyKind; readonly key: string };
type RootOutcome = { readonly principalKind: 'root'; readonly outcome: 'ok' | 'absent' };
// Thêm vào ProductAuditEvent:
//  | ({ kind: `access.${string}`; actor: string; permission: string; target?: RequestedKey } & RootOutcome)
//  | { kind: 'data.update'; actor; permission; principalKind: 'root'; outcome: 'ok'; target: RequestedKey & { objectId: string } }
//  | { kind: 'data.update'; actor; permission; principalKind: 'root'; outcome: 'absent'; target: RequestedKey }
//  | ({ kind: 'account.suspend'; actor; permission; target: { userId: string } } & RootOutcome)
// Metadata Root: principalKind, outcome, resource/keyKind/key (key chỉ uuid/integer), targetUserId, resultingRevision theo ADR 0009.
```

- [ ] **Step 1: Viết test fail**

Create `test/product-root.integration-spec.ts`:

```ts
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { DataSource } from 'typeorm';
import type { IdentityId } from '@base-authorization/core';
import {
  ProductAccessDenied,
  ProductInvalidRequest,
  type ProductDatabasePurpose,
} from '@base-authorization/typeorm-postgres';
import {
  PRODUCT_FRESH_AUTH_SQL,
  ProductAuthorization,
  ProductBindingRegistry,
  ProductIdentityService,
  ProductManifestReconciler,
  ProductTransactionRunner,
  createProductPasswordHasher,
  prepareProductRelease,
  productObligations,
  sessionDigest,
  type ProductObligationRegistry,
} from '@base-authorization/typeorm-postgres/composition';
import {
  appendProductAudit,
  bootstrapProductRoot,
  productDataSourceOptions,
  provisionProductDatabase,
} from '@base-authorization/typeorm-postgres/operations';
import {
  createProductAuthorizationCore,
  productBindings,
  productDeclarations,
  productReleaseSource,
} from '../apps/api/dist/authorization/product-manifest.js';
import { ProductDocument1792108800002 } from '../apps/api/dist/documents/migrations/product-document.js';
import { startPostgres, withClient, type TestPostgres } from './setup-postgres.ts';

const core = createProductAuthorizationCore();
// Release 2 plus one account boundary, so the IAM suspend path (grant + required boundary) exists.
const release = prepareProductRelease(
  {
    ...productReleaseSource,
    declarations: {
      ...productDeclarations,
      boundaries: [
        ...productDeclarations.boundaries,
        {
          key: 'accountAll',
          version: 1,
          entries: [
            {
              permission: 'account.suspend',
              contextRequirements: [],
              requiredScope: { op: 'constant', value: true },
            },
          ],
        },
      ],
    },
  },
  core,
);
const validators = {
  'fresh@1': (_p: unknown, input: { context: { freshAuthentication?: unknown } }) =>
    input.context.freshAuthentication === true,
};
const utf8 = (value: string) => Buffer.from(value);
const rootEmail = 'root@example.test';
const rootPassword = 'a long unique root bypass password';
const draft = randomUUID();
const published = randomUUID();
const reader = randomUUID() as IdentityId;
const readerSecret = randomBytes(32).toString('base64url');
let postgres: TestPostgres;
let pools: Record<'data' | 'identity' | 'authority' | 'sync' | 'bootstrap', DataSource>;
let migration: DataSource;
let runner: ProductTransactionRunner;
let identity: ProductIdentityService;
let bindings: ProductBindingRegistry;
let root: { id: IdentityId; stale: string };
let attempt = 0;

const service = (obligations: ProductObligationRegistry = productObligations) =>
  new ProductAuthorization(runner, bindings, { validators, obligations }, [
    { resource: 'document', action: 'update', fields: ['title'] },
  ]);
/** A Root session reauthenticated just now (local password). */
async function freshRoot(): Promise<string> {
  const clientKey = `root-${++attempt}`;
  const login = await identity.login(rootEmail, rootPassword, clientKey);
  return (await identity.reauthenticate(login.secret, rootPassword, clientKey)).secret;
}
type Event = readonly [string, string, string | null, string | null, Record<string, unknown>];
const revision = () =>
  withClient(
    postgres.superuser,
    async (c) =>
      (await c.query<{ r: string }>('SELECT revision::text r FROM authz_state')).rows[0]!.r,
  );
const events = () =>
  withClient(
    postgres.superuser,
    async (c) =>
      (
        await c.query<{
          id: string;
          kind: string;
          actor: string;
          permission: string | null;
          object: string | null;
          metadata: Record<string, unknown>;
        }>(
          `SELECT event_id id,convert_from(event_kind,'UTF8') kind,actor_id::text actor,convert_from(permission_key,'UTF8') permission,object_id::text object,safe_metadata metadata FROM audit_outbox`,
        )
      ).rows,
  );
/** Events appended by `work` only, as [kind, actor, permission, object_id, metadata]. */
async function appended(work: () => Promise<unknown>) {
  const seen = new Set((await events()).map((e) => e.id));
  const before = await revision();
  await work();
  const added: Event[] = (await events())
    .filter((e) => !seen.has(e.id))
    .map((e) => [e.kind, e.actor, e.permission, e.object, e.metadata] as const)
    .sort((a, b) => a[0].localeCompare(b[0]));
  return { before, after: await revision(), added };
}
const title = async (id: string) =>
  (await migration.query<{ title: string }[]>('SELECT title FROM document WHERE id=$1', [id]))[0]!
    .title;

before(async () => {
  postgres = await startPostgres();
  const passwords = Object.fromEntries(
    ['data', 'identity', 'authority', 'sync', 'bootstrap', 'migration', 'outbox'].map((p) => [
      p,
      randomBytes(20).toString('hex'),
    ]),
  ) as Record<ProductDatabasePurpose, string>;
  const connections = await provisionProductDatabase(postgres.superuser, passwords);
  pools = {} as typeof pools;
  for (const p of ['data', 'identity', 'authority', 'sync', 'bootstrap'] as const)
    pools[p] = await new DataSource(productDataSourceOptions(connections[p])).initialize();
  migration = await new DataSource(productDataSourceOptions(connections.migration)).initialize();
  runner = new ProductTransactionRunner(pools);
  identity = new ProductIdentityService(runner, await createProductPasswordHasher(new Set()));
  const qr = migration.createQueryRunner();
  await new ProductDocument1792108800002().up(qr);
  await qr.release();
  await new ProductManifestReconciler(runner, {
    core,
    actor: randomUUID() as IdentityId,
    capabilities: release.declarations.capabilities,
  }).reconcile(release);
  bindings = new ProductBindingRegistry(core, release.declarations, productBindings);
  // IAM reader: reviewer role (owned documents only), a session without reauthentication.
  await migration.query(`INSERT INTO app_user(id,state,email_verified) VALUES($1,'active',true)`, [
    reader,
  ]);
  await migration.query(
    "INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,'fixture-only',1)",
    [reader],
  );
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(readerSecret), reader],
  );
  await runner.run('admin', async (tx) => {
    await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
      reader,
      utf8('reviewer'),
    ]);
    for (const id of [draft, published])
      await tx.manager.query(
        "INSERT INTO object_ref(object_id,type_key,key_kind,key_bytes) VALUES($1,$2,'uuid',$3)",
        [id, utf8('document'), utf8(id)],
      );
  });
  // Root: pending enrollment → offline bootstrap → activation → login (no reauthentication).
  const id = randomUUID() as IdentityId;
  await migration.query(`INSERT INTO app_user(id,email_canonical,state) VALUES($1,$2,'pending')`, [
    id,
    rootEmail,
  ]);
  const { activationSecret } = await bootstrapProductRoot(runner, release, {
    operationId: randomUUID(),
    userId: id,
    method: 'local',
  });
  assert.ok(activationSecret);
  await identity.activate(activationSecret, rootPassword, 'root-activation');
  root = { id, stale: (await identity.login(rootEmail, rootPassword, 'root-stale')).secret };
  // One document owned by the reader (draft), one owned by Root (published); no grant names Root.
  await migration.query(
    `INSERT INTO document(id,object_id,owner_id,title,state) VALUES($1,$1,$3,'Draft','draft'),($2,$2,$4,'Published','published')`,
    [draft, published, reader, id],
  );
});
after(async () => {
  await migration?.destroy();
  for (const pool of Object.values(pools ?? {})) await pool.destroy();
  await postgres?.stop();
});

test('fresh reauthentication is decided in SQL at microsecond precision on the DB clock', async () => {
  const fresh = async (age: string | null) =>
    (
      await pools.data.query<{ fresh: boolean }[]>(
        `SELECT ${PRODUCT_FRESH_AUTH_SQL} AS fresh FROM (SELECT statement_timestamp()-$1::interval AS reauthenticated_at) s`,
        [age],
      )
    )[0]!.fresh;
  assert.equal(await fresh(null), false);
  assert.equal(await fresh('-1 second'), false);
  assert.equal(await fresh('300 seconds'), false);
  assert.equal(await fresh('299.999999 seconds'), true);
  assert.equal(await fresh('0 seconds'), true);
});

test('Root reads every document without a grant, through the same projection, with an audit per access', async () => {
  const s = service();
  const missing = randomUUID();
  const { added } = await appended(async () => {
    const page = await s.list(root.stale, 'document', 'read');
    assert.equal(page.total, '2');
    assert.deepEqual(page.items.map((item) => item.title).sort(), ['Draft', 'Published']);
    assert.ok(page.items.every((item) => !('ownerId' in item)));
    assert.equal(await s.count(root.stale, 'document', 'read'), '2');
    assert.equal((await s.detail(root.stale, 'document', 'read', draft))?.title, 'Draft');
    assert.equal(await s.detail(root.stale, 'document', 'read', missing), null);
  });
  const ok = { principalKind: 'root', outcome: 'ok' };
  assert.deepEqual(added, [
    ['access.document.read', root.id, 'document.read', null, ok],
    ['access.document.read', root.id, 'document.read', null, ok],
    [
      'access.document.read',
      root.id,
      'document.read',
      null,
      { ...ok, resource: 'document', keyKind: 'uuid', key: draft },
    ],
    [
      'access.document.read',
      root.id,
      'document.read',
      null,
      {
        principalKind: 'root',
        outcome: 'absent',
        resource: 'document',
        keyKind: 'uuid',
        key: missing,
      },
    ],
  ]);
  // An empty obligation registry changes nothing for Root: its audit is written directly.
  assert.equal(
    (await appended(() => service({}).count(root.stale, 'document', 'read'))).added.length,
    1,
  );
});

test('Root writes need a fresh reauthentication; then policy scope is bypassed but fields are not', async () => {
  const s = service();
  const denied = await appended(() =>
    assert.rejects(
      s.update(root.stale, 'document', 'update', published, { title: 'Stale' }),
      ProductAccessDenied,
    ),
  );
  assert.deepEqual(denied.added, []);
  assert.equal(await title(published), 'Published');
  const fresh = await freshRoot();
  // Not a draft: the `editable` scope would deny an IAM user; Root bypasses it.
  const written = await appended(async () =>
    assert.equal(
      await s.update(fresh, 'document', 'update', published, { title: 'By Root' }),
      true,
    ),
  );
  assert.deepEqual(written.added, [
    [
      'data.update',
      root.id,
      'document.update',
      published,
      {
        principalKind: 'root',
        outcome: 'ok',
        resource: 'document',
        keyKind: 'uuid',
        key: published,
        resultingRevision: written.before,
      },
    ],
  ]);
  assert.equal(await title(published), 'By Root');
  const missing = randomUUID();
  const absent = await appended(async () =>
    assert.equal(await s.update(fresh, 'document', 'update', missing, { title: 'Nowhere' }), false),
  );
  assert.deepEqual(absent.added, [
    [
      'data.update',
      root.id,
      'document.update',
      null,
      {
        principalKind: 'root',
        outcome: 'absent',
        resource: 'document',
        keyKind: 'uuid',
        key: missing,
        resultingRevision: absent.before,
      },
    ],
  ]);
  // The writable-field allowlist still binds Root.
  await assert.rejects(
    s.update(fresh, 'document', 'update', published, { ownerId: root.id }),
    ProductAccessDenied,
  );
});

test('an OIDC reauthentication is fresh as well; an OIDC session without one is not', async () => {
  const issuer = 'https://issuer.root.invalid';
  await pools.sync.query('INSERT INTO oidc_provider(issuer,version,enabled) VALUES($1,1,true)', [
    issuer,
  ]);
  await pools.identity.query(
    "INSERT INTO external_identity(issuer,subject,user_id) VALUES($1,'root-subject',$2)",
    [issuer, root.id],
  );
  const session = async (reauthenticated: boolean) => {
    const secret = randomBytes(32).toString('base64url');
    await pools.identity.query(
      `INSERT INTO application_session(token_hash,user_id,auth_epoch,method,assurance,authenticated_at,reauthenticated_at,expires_at,external_issuer,external_subject,binding_version,provider_version)
       VALUES($1,$2,(SELECT auth_epoch FROM app_user WHERE id=$2),'oidc','oidc',statement_timestamp(),${reauthenticated ? 'statement_timestamp()' : 'NULL'},statement_timestamp()+interval '1 hour',$3,'root-subject',1,1)`,
      [sessionDigest(secret), root.id, issuer],
    );
    return secret;
  };
  await assert.rejects(
    service().update(await session(false), 'document', 'update', draft, { title: 'OIDC stale' }),
    ProductAccessDenied,
  );
  assert.equal(
    await service().update(await session(true), 'document', 'update', draft, {
      title: 'OIDC fresh',
    }),
    true,
  );
});

test('a failed Root audit rolls the access back and returns nothing', async () => {
  const fresh = await freshRoot();
  const before = await title(draft);
  await withClient(postgres.superuser, (c) =>
    c.query('REVOKE INSERT ON audit_outbox FROM product_data'),
  );
  try {
    await assert.rejects(service().list(root.stale, 'document', 'read'), /permission denied/);
    await assert.rejects(
      service().update(fresh, 'document', 'update', draft, { title: 'Must not stick' }),
      /permission denied/,
    );
    // IAM reads carry no audit obligation here, so they are unaffected.
    assert.equal((await service().list(readerSecret, 'document', 'read')).total, '1');
  } finally {
    await withClient(postgres.superuser, (c) =>
      c.query('GRANT INSERT ON audit_outbox TO product_data'),
    );
  }
  assert.equal(await title(draft), before);
});

test('malformed keys, unknown actions and resources fail closed for Root without an event', async () => {
  const fresh = await freshRoot();
  const { added } = await appended(async () => {
    await assert.rejects(
      service().detail(root.stale, 'document', 'read', 'not-a-key'),
      ProductInvalidRequest,
    );
    await assert.rejects(
      service().update(fresh, 'document', 'update', 'not-a-key', { title: 'x' }),
      ProductInvalidRequest,
    );
    await assert.rejects(service().list(root.stale, 'document', 'delete'), ProductAccessDenied);
    await assert.rejects(service().list(root.stale, 'invoice', 'read'), ProductAccessDenied);
  });
  assert.deepEqual(added, []);
});

test('a string record key never reaches Root audit metadata', async () => {
  const { added } = await appended(() =>
    runner.run('read', (tx) =>
      appendProductAudit(tx, {
        kind: 'access.person.read',
        actor: root.id,
        permission: 'person.read',
        principalKind: 'root',
        outcome: 'absent',
        target: { resource: 'person', keyKind: 'string', key: 'person@example.test' },
      }),
    ),
  );
  assert.deepEqual(added, [
    [
      'access.person.read',
      root.id,
      'person.read',
      null,
      { principalKind: 'root', outcome: 'absent', resource: 'person', keyKind: 'string' },
    ],
  ]);
});

test('IAM reads stay scoped and unaudited; a role named like Root grants nothing', async () => {
  await runner.run('admin', async (tx) => {
    for (const key of ['system.root', 'root']) {
      await tx.manager.query(
        "INSERT INTO role_definition(role_key,managed_by,label) VALUES($1,'runtime',$2)",
        [utf8(key), `Named ${key}`],
      );
      await tx.manager.query('INSERT INTO user_role(user_id,role_key) VALUES($1,$2)', [
        reader,
        utf8(key),
      ]);
    }
  });
  const { added } = await appended(async () => {
    const page = await service().list(readerSecret, 'document', 'read');
    assert.equal(page.total, '1');
    assert.equal(await service().detail(readerSecret, 'document', 'read', published), null);
  });
  assert.deepEqual(added, []);
});
```

Trong `test/package-boundaries.spec.ts` thêm `'PRODUCT_FRESH_AUTH_SQL'` vào `composition.present`.

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:integration -- test/product-root.integration-spec.ts`
Expected: FAIL — import `PRODUCT_FRESH_AUTH_SQL` là `undefined` (test fresh), Root list trả `total: '0'`.

- [ ] **Step 3: Union audit trong `product-audit.ts`**

Thêm sau `type UserTarget`:

```ts
/** Requested record key of an access; metadata keeps `key` only for uuid/integer kinds. */
type RequestedKey = {
  readonly resource: string;
  readonly keyKind: KeyKind;
  readonly key: string;
};
/** Root marker, written only from the verified session kind through typed input (spec 6.5). */
type RootOutcome = { readonly principalKind: 'root'; readonly outcome: 'ok' | 'absent' };
```

Thay các nhánh `access`, `data.update`, `account.suspend` của union bằng:

```ts
  | { readonly kind: `access.${string}`; readonly actor: string; readonly permission: string }
  | ({
      readonly kind: `access.${string}`;
      readonly actor: string;
      readonly permission: string;
      /** Detail only: the requested key, ok or absent; never a made-up target. */
      readonly target?: RequestedKey;
    } & RootOutcome)
  | {
      readonly kind: 'data.update';
      readonly actor: string;
      readonly permission: string;
      readonly target: RequestedKey & { readonly objectId: string };
    }
  | {
      readonly kind: 'data.update';
      readonly actor: string;
      readonly permission: string;
      readonly principalKind: 'root';
      readonly outcome: 'ok';
      readonly target: RequestedKey & { readonly objectId: string };
    }
  | {
      readonly kind: 'data.update';
      readonly actor: string;
      readonly permission: string;
      readonly principalKind: 'root';
      readonly outcome: 'absent';
      readonly target: RequestedKey;
    }
  | {
      readonly kind: 'account.suspend';
      readonly actor: string;
      readonly permission: string;
      readonly target: UserTarget;
    }
  | ({
      readonly kind: 'account.suspend';
      readonly actor: string;
      readonly permission: string;
      readonly target: UserTarget;
    } & RootOutcome)
```

Trong `appendProductAudit`, dòng `if ('target' in event && 'userId' in event.target)` thành `if ('target' in event && event.target && 'userId' in event.target)` (target của access Root là tùy chọn); sau dòng `if (!event.kind.startsWith('access.')) …` thêm:

```ts
if ('principalKind' in event) {
  metadata.principalKind = event.principalKind;
  metadata.outcome = event.outcome;
}
if ('target' in event && event.target && 'keyKind' in event.target) {
  metadata.resource = event.target.resource;
  metadata.keyKind = event.target.keyKind;
  if (event.target.keyKind !== 'string') metadata.key = event.target.key;
  if ('objectId' in event.target) objectId = event.target.objectId;
}
```

và xóa `case 'data.update'` trong `switch` (logic đã chuyển lên khối trên; event IAM ra metadata y hệt).

- [ ] **Step 4: Nhánh Root trong `product-authority.ts`**

Imports thêm `type UserTrustedInput` (core) và `type ProductAuditEvent` (`./product-audit.js`). Thay `SessionProjection` và thêm hằng:

```ts
interface SessionProjection {
  user_id: UserId;
  /** From resolve_session in this fenced transaction; never from a request or a role name. */
  kind: 'root' | 'iam';
  assurance: string;
  authenticated_at: Date;
  reauthenticated_at: Date | null;
  expires_at: Date;
  state: 'active' | 'suspended' | 'pending';
  /** PRODUCT_FRESH_AUTH_SQL, by the DB clock of the same statement. */
  fresh: boolean;
  /** DB clock of the same statement and the plan deadline (never past session expiry). */
  now: string;
  deadline: string;
}
type PrincipalKind = SessionProjection['kind'];
/**
 * Fresh reauthentication: in the past and less than 300 seconds before the statement time.
 * Evaluated in SQL so the DB clock and microseconds decide (spec 6.4).
 */
export const PRODUCT_FRESH_AUTH_SQL =
  "(reauthenticated_at IS NOT NULL AND reauthenticated_at<=statement_timestamp() AND statement_timestamp()-reauthenticated_at<interval '300 seconds')";
```

`session()`:

```ts
  private async session(tx: ProductTransaction, secret: string): Promise<SessionProjection> {
    const [session] = await tx.manager.query<SessionProjection[]>(
      `SELECT s.*,${PRODUCT_FRESH_AUTH_SQL} fresh,to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') now,to_char(LEAST(s.expires_at,statement_timestamp()+interval '2 seconds') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') deadline FROM public.resolve_session($1) s`,
      [sessionDigest(secret)],
    );
    if (
      !session ||
      !this.bindings.core.isCanonicalUuid(session.user_id) ||
      (session.kind !== 'root' && session.kind !== 'iam')
    )
      throw new ProductAuthenticationError();
    return session;
  }
```

`access` và các operation:

```ts
  /**
   * The only Root branch (ADR 0012): `kind` comes from the verified session. Root still needs a
   * valid session, a fresh reauthentication for write/admin, a declared action, the projection
   * and writable allowlists, and leaves one audit event per committed access.
   */
  private async access<T>(
    secret: string,
    resource: string,
    action: string,
    mode: 'read' | 'write' | 'admin',
    work: (plan: UserAuthorizedPlan, tx: ProductTransaction, kind: PrincipalKind) => Promise<T>,
    rootEvent: (plan: UserAuthorizedPlan, result: T) => ProductAuditEvent,
  ): Promise<T> {
    return this.transactions.run(mode, async (tx) => {
      // Authority purpose deliberately has no session/credential read capability: use the narrow projection function.
      const session = await this.session(tx, secret);
      if (session.kind === 'root' && mode !== 'read' && !session.fresh)
        throw new ProductAccessDenied();
      const snapshot = await readProductAuthority(
        tx,
        session.user_id,
        `${resource}.${action}`,
        this.bindings.declarations,
        this.registry,
      );
      const input: UserTrustedInput = {
        principal: { id: session.user_id, assurance: session.assurance === 'mfa' ? 2 : 1 },
        resource,
        action,
        now: session.now,
        validUntil: session.deadline,
        context: { freshAuthentication: session.fresh },
      };
      const decision =
        session.kind === 'root'
          ? this.bindings.core.planUnrestricted(input, snapshot)
          : this.bindings.core.planUser(input, snapshot);
      if (decision.effect !== 'allow') throw new ProductAccessDenied();
      const result = await work(decision.plan, tx, session.kind);
      if (session.kind === 'root') await appendProductAudit(tx, rootEvent(decision.plan, result));
      await fulfillProductObligations(tx, decision.plan, this.obligations);
      return result;
    });
  }
  /** Requested key of a Root audit target (spec 6.5); parsed like the operation parsed it. */
  private requested(resource: string, key: string) {
    const keyKind = this.bindings.declarations.resources[resource]!.keyKind;
    return { resource, keyKind, key: requestKey(this.bindings.core, keyKind, key).value };
  }
  private static readonly ok = { principalKind: 'root', outcome: 'ok' } as const;
  list(secret: string, resource: string, action: string, query: ListQuery = {}) {
    return this.access(
      secret,
      resource,
      action,
      'read',
      (plan, tx) => this.gateway.list(plan, query, tx),
      (plan) => ({
        kind: `access.${plan.resource}.${plan.action}`,
        actor: plan.userId,
        permission: plan.permission,
        ...ProductAuthorization.ok,
      }),
    );
  }
  detail(secret: string, resource: string, action: string, key: string) {
    return this.access(
      secret,
      resource,
      action,
      'read',
      (plan, tx) =>
        this.gateway.detail(
          plan,
          requestKey(
            this.bindings.core,
            this.bindings.declarations.resources[resource]!.keyKind,
            key,
          ),
          tx,
        ),
      (plan, row) => ({
        kind: `access.${plan.resource}.${plan.action}`,
        actor: plan.userId,
        permission: plan.permission,
        principalKind: 'root',
        outcome: row ? 'ok' : 'absent',
        target: this.requested(resource, key),
      }),
    );
  }
  count(secret: string, resource: string, action: string) {
    return this.access(
      secret,
      resource,
      action,
      'read',
      (plan, tx) => this.gateway.count(plan, {}, tx),
      (plan) => ({
        kind: `access.${plan.resource}.${plan.action}`,
        actor: plan.userId,
        permission: plan.permission,
        ...ProductAuthorization.ok,
      }),
    );
  }
```

`update`: chữ ký giữ nguyên; thân:

```ts
const objectId = await this.access(
  secret,
  resource,
  action,
  'write',
  async (plan, tx, kind) => {
    // … nguyên văn phần dựng binding/bound/params/assignments/typedKey/rows hiện có …
    if (rows.length && kind === 'iam')
      await appendProductAudit(tx, {
        kind: 'data.update',
        actor: plan.userId,
        permission: plan.permission,
        target: { resource, keyKind, key: typedKey.value, objectId: rows[0]!.object_id },
      });
    return rows[0]?.object_id;
  },
  (plan, updated): ProductAuditEvent =>
    updated === undefined
      ? {
          kind: 'data.update',
          actor: plan.userId,
          permission: plan.permission,
          principalKind: 'root',
          outcome: 'absent',
          target: this.requested(resource, key),
        }
      : {
          kind: 'data.update',
          actor: plan.userId,
          permission: plan.permission,
          principalKind: 'root',
          outcome: 'ok',
          target: { ...this.requested(resource, key), objectId: updated },
        },
);
return objectId !== undefined;
```

`suspendUser` (thứ tự cũ giữ đến Task 8; event IAM chỉ cho `kind === 'iam'`):

```ts
  async suspendUser(secret: string, target: string): Promise<boolean> {
    if (!this.bindings.core.isCanonicalUuid(target)) throw new ProductAccessDenied();
    return this.access(
      secret,
      'account',
      'suspend',
      'admin',
      async (plan, tx, kind) => {
        if (plan.userId === target) throw new ProductAccessDenied();
        const row = await this.gateway.detail(plan, this.bindings.core.parseKey('uuid', target), tx);
        if (!row) return false;
        await tx.manager.query(
          `UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1`,
          [target],
        );
        if (kind === 'iam')
          await appendProductAudit(tx, {
            kind: 'account.suspend',
            actor: plan.userId,
            permission: plan.permission,
            target: { userId: target },
          });
        return true;
      },
      (plan, suspended) => ({
        kind: 'account.suspend',
        actor: plan.userId,
        permission: plan.permission,
        principalKind: 'root',
        outcome: suspended ? 'ok' : 'absent',
        target: { userId: target },
      }),
    );
  }
```

`composition.ts`: `export { ProductAuthorization, PRODUCT_FRESH_AUTH_SQL, readProductAuthority } from './product-authority.js';`.

- [ ] **Step 5: E2E theo hành vi mới**

Trong `apps/api/test/product.e2e-spec.ts`, thay đoạn Root ở Task 3 bằng:

```ts
const rootPage = (await (await request('/documents')).json()) as {
  items: Record<string, unknown>[];
  total: string;
};
// Root is outside IAM: every document, still through the projection; writes need fresh reauth.
assert.equal(rootPage.total, '2');
assert.ok(rootPage.items.every((item) => !('ownerId' in item)));
assert.equal((await request(`/documents/${hidden}`)).status, 200);
assert.equal((await request(`/documents/${hidden}`, 'PATCH', { title: 'Root edit' })).status, 403);
assert.equal((await request(`/administration/users/${user}/suspend`, 'POST')).status, 403);
assert.equal((await request('/auth/reauthenticate', 'POST', { password })).status, 200);
assert.equal((await request(`/documents/${hidden}`, 'PATCH', { title: 'Root edit' })).status, 200);
assert.equal((await request(`/administration/users/${user}/suspend`, 'POST')).status, 200);
assert.equal(
  (
    await ds.migration.query<{ state: string }[]>('SELECT state FROM app_user WHERE id=$1', [user])
  )[0]?.state,
  'suspended',
);
```

- [ ] **Step 6: Chạy test**

Run: `pnpm run test:integration -- test/product-root.integration-spec.ts test/product-audit.integration-spec.ts test/product-authorization.integration-spec.ts test/product-values.integration-spec.ts`
Expected: PASS (event IAM trong `product-audit` vẫn khớp exact).

Run: `pnpm run test:unit -- test/package-boundaries.spec.ts` và `pnpm run test:e2e`
Expected: PASS.

- [ ] **Step 7: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write <mọi file của task> && pnpm run lint && pnpm run typecheck && pnpm run test:unit`
Expected: exit 0 (ESLint không báo `planUnrestricted` trong `product-authority.ts`).

```bash
git add packages/typeorm-postgres/src/product-authority.ts packages/typeorm-postgres/src/product-audit.ts packages/typeorm-postgres/src/composition.ts test/product-root.integration-spec.ts test/package-boundaries.spec.ts apps/api/test/product.e2e-spec.ts
git commit -m "feat: Root bypass in access with SQL fresh-auth for writes and an audit per Root access"
```

---

### Task 8: Resource `account` và `suspendUser`

**Files:**

- Modify: `packages/typeorm-postgres/src/product-authority.ts` (`suspendUser`)
- Modify: `apps/api/src/openapi/product-openapi.ts:191-200`
- Modify: `test/product-root.integration-spec.ts` (thêm test), `apps/api/test/structure.spec.ts:198`, `apps/api/test/product.e2e-spec.ts`

**Interfaces:**

- Consumes: `access(…, work(plan, tx, kind), rootEvent)` (Task 7); binding `iam_account` (Task 3).
- Produces: `suspendUser(secret: string, target: string): Promise<boolean>` — `false` (404) khi target vắng mặt hoặc là Root (kể cả Root tự nhắm mình); `ProductAccessDenied` (403) khi IAM tự suspend hoặc id không canonical.

- [ ] **Step 1: Viết test fail**

Thêm vào cuối `test/product-root.integration-spec.ts`:

```ts
/** An active IAM account with a local session, reauthenticated now when `fresh`. */
async function iamUser(fresh = false) {
  const id = randomUUID() as IdentityId;
  const secret = randomBytes(32).toString('base64url');
  await migration.query(`INSERT INTO app_user(id,state,email_verified) VALUES($1,'active',true)`, [
    id,
  ]);
  await migration.query(
    "INSERT INTO local_credential(user_id,password_hash,version) VALUES($1,'fixture-only',1)",
    [id],
  );
  await pools.identity.query(
    `INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,reauthenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),${fresh ? 'statement_timestamp()' : 'NULL'},statement_timestamp()+interval '1 hour')`,
    [sessionDigest(secret), id],
  );
  return { id, secret };
}
const account = (id: string) =>
  migration.query<{ state: string; epoch: string }[]>(
    'SELECT state,auth_epoch::text epoch FROM app_user WHERE id=$1',
    [id],
  );

test('Root suspends an IAM account; itself, absent and malformed ids reveal nothing', async () => {
  const member = await iamUser();
  const s = service();
  assert.deepEqual(
    (
      await appended(() =>
        assert.rejects(s.suspendUser(root.stale, member.id), ProductAccessDenied),
      )
    ).added,
    [],
  );
  const fresh = await freshRoot();
  const done = await appended(async () =>
    assert.equal(await s.suspendUser(fresh, member.id), true),
  );
  assert.deepEqual(done.added, [
    [
      'account.suspend',
      root.id,
      'account.suspend',
      null,
      {
        principalKind: 'root',
        outcome: 'ok',
        targetUserId: member.id,
        resultingRevision: done.after,
      },
    ],
  ]);
  assert.deepEqual(await account(member.id), [{ state: 'suspended', epoch: '2' }]);
  for (const target of [root.id, randomUUID()]) {
    const absent = await appended(async () =>
      assert.equal(await s.suspendUser(fresh, target), false),
    );
    assert.deepEqual(absent.added, [
      [
        'account.suspend',
        root.id,
        'account.suspend',
        null,
        {
          principalKind: 'root',
          outcome: 'absent',
          targetUserId: target,
          resultingRevision: absent.after,
        },
      ],
    ]);
  }
  assert.equal((await account(root.id))[0]?.state, 'active');
  // A non-canonical id is refused before any lookup: 403 and no event.
  assert.deepEqual(
    (
      await appended(() =>
        assert.rejects(s.suspendUser(fresh, member.id.toUpperCase()), ProductAccessDenied),
      )
    ).added,
    [],
  );
});

test('IAM suspend needs a grant and a boundary; self is 403; Root is invisible to IAM', async () => {
  const admin = await iamUser(true);
  const staleAdmin = randomBytes(32).toString('base64url');
  await pools.identity.query(
    "INSERT INTO application_session(token_hash,user_id,auth_epoch,credential_version,method,assurance,authenticated_at,expires_at) VALUES($1,$2,1,1,'local','password',statement_timestamp(),statement_timestamp()+interval '1 hour')",
    [sessionDigest(staleAdmin), admin.id],
  );
  const unbounded = await iamUser(true);
  const target = await iamUser();
  await runner.run('admin', async (tx) => {
    for (const user of [admin.id, unbounded.id])
      await tx.manager.query(
        "INSERT INTO policy_rule(rule_id,permission_key,user_id,effect,template_key,template_version,parameters,managed_by) VALUES($1,$2,$3,'allow',$4,1,'{}','runtime')",
        [randomUUID(), utf8('account.suspend'), user, utf8('allAccounts')],
      );
    await tx.manager.query(
      'INSERT INTO user_boundary(user_id,permission_key,boundary_key,boundary_version) VALUES($1,$2,$3,1)',
      [admin.id, utf8('account.suspend'), utf8('accountAll')],
    );
  });
  const s = service();
  await assert.rejects(s.suspendUser(unbounded.secret, target.id), ProductAccessDenied);
  await assert.rejects(s.suspendUser(admin.secret, admin.id), ProductAccessDenied);
  assert.equal(await s.suspendUser(admin.secret, root.id), false);
  assert.equal((await account(root.id))[0]?.state, 'active');
  // freshAuthentication@1 still decides for IAM, from the same SQL boolean.
  await assert.rejects(s.suspendUser(staleAdmin, target.id), ProductAccessDenied);
  const done = await appended(async () =>
    assert.equal(await s.suspendUser(admin.secret, target.id), true),
  );
  assert.deepEqual(done.added, [
    ['access.suspend', admin.id, 'account.suspend', null, {}],
    [
      'account.suspend',
      admin.id,
      'account.suspend',
      null,
      { targetUserId: target.id, resultingRevision: done.after },
    ],
  ]);
});
```

`apps/api/test/structure.spec.ts`: `const openApiSha256 = 'f0f1c5c53e2057ded71ce665a98b4df713ae790299159dc5ca8b7fbd3879148f';` (tính từ tài liệu hiện tại với summary mới ở Step 3).

Trong `apps/api/test/product.e2e-spec.ts`, ngay sau dòng `/auth/reauthenticate … 200` của Task 7 thêm:

```ts
// Root itself and an absent id look the same: 404 (the account resource holds IAM accounts only).
assert.equal((await request(`/administration/users/${root}/suspend`, 'POST')).status, 404);
assert.equal((await request(`/administration/users/${randomUUID()}/suspend`, 'POST')).status, 404);
```

và đổi tên test thành `'actual API boot, activation/login, scoped read/write, Root bypass with fresh writes and revoke/reset fail closed'`.

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:integration -- test/product-root.integration-spec.ts`
Expected: FAIL ở test Root — `s.suspendUser(fresh, root.id)` ném `ProductAccessDenied` thay vì trả `false` (thứ tự cũ chặn self trước lookup).

- [ ] **Step 3: Implement**

`suspendUser` (callback `work`):

```ts
      async (plan, tx, kind) => {
        // One lookup through iam_account first: an absent id and any Root (Root included when it
        // targets itself) are the same "not found" (spec 7.2). Only then the IAM self check.
        const row = await this.gateway.detail(plan, this.bindings.core.parseKey('uuid', target), tx);
        if (!row) return false;
        if (plan.userId === target) throw new ProductAccessDenied();
        await tx.manager.query(
          `UPDATE app_user SET state='suspended',auth_epoch=auth_epoch+1 WHERE id=$1`,
          [target],
        );
        if (kind === 'iam')
          await appendProductAudit(tx, {
            kind: 'account.suspend',
            actor: plan.userId,
            permission: plan.permission,
            target: { userId: target },
          });
        return true;
      },
```

`apps/api/src/openapi/product-openapi.ts`: summary `'Suspend an IAM user: Root, or a grant within a required boundary'`.

- [ ] **Step 4: Chạy test**

Run: `pnpm run test:integration -- test/product-root.integration-spec.ts test/product-audit.integration-spec.ts`
Expected: PASS.

Run: `pnpm run test:unit -- apps/api/test/structure.spec.ts` và `pnpm run test:e2e`
Expected: PASS.

- [ ] **Step 5: Kiểm tra rộng và commit**

Run: `pnpm exec prettier --write <mọi file của task> && pnpm run lint && pnpm run typecheck && pnpm run test:unit`
Expected: exit 0.

```bash
git add packages/typeorm-postgres/src/product-authority.ts apps/api/src/openapi/product-openapi.ts test/product-root.integration-spec.ts apps/api/test/structure.spec.ts apps/api/test/product.e2e-spec.ts
git commit -m "feat: suspend looks up iam_account first; Root and absent targets are one 404"
```

---

### Task 9: CLI Root end-to-end

**Files:**

- Modify: `test/product-cli.integration-spec.ts:1-268`

**Interfaces:**

- Consumes: CLI `enroll`, `bootstrap`, `reissue-root`, `revoke-root` (Task 3); `ProductIdentityService` (composition).
- Produces: không.

- [ ] **Step 1: Viết test**

Imports thêm:

```ts
import { DataSource } from 'typeorm';
import { ProductAuthenticationError } from '@base-authorization/typeorm-postgres';
import {
  PRODUCT_OFFLINE_ACTOR,
  ProductIdentityService,
  ProductTransactionRunner,
  createProductPasswordHasher,
} from '@base-authorization/typeorm-postgres/composition';
import { productDataSourceOptions } from '@base-authorization/typeorm-postgres/operations';
```

Ngay sau khối `notRoot` (sau `await assert.rejects(readFile(join(dir, 'not-root-proof'), 'utf8'));`) thêm:

```ts
// enroll → bootstrap → activation (only the reissued proof works) → login.
const identitySource = await new DataSource(
  productDataSourceOptions({
    host: c.host,
    port: c.port,
    username: 'product_identity',
    password: env['PRODUCT_IDENTITY_PASSWORD'] ?? '',
    database: 'cli_fixture',
  }),
).initialize();
try {
  const identityRunner = new ProductTransactionRunner({ identity: identitySource });
  const identity = new ProductIdentityService(
    identityRunner,
    await createProductPasswordHasher(new Set()),
  );
  const rootPassword = 'a long unique cli root password';
  await assert.rejects(identity.activate(proof, rootPassword, 'cli-root'), ProductAuthenticationError);
  await identity.activate((await readFile(reissuePath, 'utf8')).trim(), rootPassword, 'cli-root');
  const session = await identity.login('root-cli@example.test', rootPassword, 'cli-root');
```

Sau khối kiểm `kind/state/marker/audit` của `revoke-root` (vẫn trong `try`) thêm:

```ts
  // The suspended Root cannot log in, and the session it held before the revocation is dead.
  await assert.rejects(
    identity.login('root-cli@example.test', rootPassword, 'cli-root'),
    ProductAuthenticationError,
  );
  await assert.rejects(
    identityRunner.run('identity', (tx) => identity.authenticate(tx, session.secret)),
    ProductAuthenticationError,
  );
  // The marker is permanent: no bootstrap after a revocation.
  const next = randomUUID();
  run('enroll', '--user', next, '--method', 'local', '--email', 'next-root@example.test');
  const again = spawnSync(
    process.execPath,
    [
      'tools/product.ts',
      'bootstrap',
      '--user',
      next,
      '--operation',
      randomUUID(),
      '--method',
      'local',
      '--activation-file',
      join(dir, 'again-proof'),
    ],
    { env, encoding: 'utf8', timeout: 30000 },
  );
  assert.notEqual(again.status, 0);
  assert.match(again.stderr, /\(ReleaseRejectedError collision\)/);
  await assert.rejects(readFile(join(dir, 'again-proof'), 'utf8'));
  // root.* audit: the offline actor acts, the Root account is the target.
  await withClient({ ...c, database: 'cli_fixture' }, async (client) => {
    const rows = await client.query<{ kind: string; actor: string; target: string }>(
      `SELECT convert_from(event_kind,'UTF8') kind,actor_id::text actor,safe_metadata->>'targetUserId' target
       FROM audit_outbox WHERE convert_from(event_kind,'UTF8') LIKE 'root.%' ORDER BY occurred_at,event_id`,
    );
    assert.deepEqual(
      rows.rows.map((r) => [r.kind, r.actor, r.target]),
      [
        ['root.bootstrap', PRODUCT_OFFLINE_ACTOR, userId],
        ['root.reissue', PRODUCT_OFFLINE_ACTOR, userId],
        ['root.revoke', PRODUCT_OFFLINE_ACTOR, userId],
      ],
    );
  });
} finally {
  await identitySource.destroy();
}
```

(Khối `revoke`/`refused`/hai lần `revoke(...)`/kiểm DB hiện có dời vào trong `try` này, giữa đoạn login và đoạn mới; nội dung giữ như bản Task 3.)

- [ ] **Step 2: Chạy test**

Run: `pnpm run test:integration -- test/product-cli.integration-spec.ts`
Expected: PASS. Kiểm lại đúng nguyên nhân bằng thao tác tạm: trong `revokeProductRoot` bỏ `,auth_epoch=auth_epoch+1` → assertion session cũ FAIL (resolve_session vẫn lọc `state='active'` nên session cũng chết — nếu test vẫn PASS, đó là do `state`; ghi nhận trong ledger, không nới assertion). Khôi phục ngay.

- [ ] **Step 3: Kiểm tra và commit**

Run: `pnpm exec prettier --write test/product-cli.integration-spec.ts && pnpm run lint && pnpm run typecheck`
Expected: exit 0.

```bash
git add test/product-cli.integration-spec.ts
git commit -m "test: offline Root lifecycle through the real CLI, login and audit"
```

---

### Task 10: Docs, ADR 0012, `AGENTS.md`, mutation check và full gate

**Files:**

- Create: `docs/decisions/0012-iam-root-separation.md`
- Modify: `AGENTS.md`, `packages/core/AGENTS.md`, `packages/typeorm-postgres/AGENTS.md`, `apps/api/AGENTS.md`
- Modify: `docs/permission-boundaries.md`, `docs/authz-single-product-architecture.md`, `docs/single-product-operations.md`, `docs/single-product-reuse-map.md`, `docs/single-product-verification.md`
- Modify: `docs/prompt.md` (một dòng đầu)
- Modify: plan này (checkbox + ledger)

**Interfaces:**

- Consumes: toàn bộ Task 1–9.
- Produces: tài liệu; không đổi code.

- [ ] **Step 1: ADR 0012**

Create `docs/decisions/0012-iam-root-separation.md`:

```md
# ADR 0012 — IAM thuần và Root tách khỏi IAM

Ngày: 2026-10-15. Trạng thái: chấp nhận; thiết kế ở `docs/superpowers/specs/2026-10-14-iam-root-separation-design.md`, triển khai và bằng chứng ở `docs/superpowers/plans/2026-10-15-iam-root-separation.md` (ledger) và `docs/single-product-verification.md`.

Supersede: ADR 0007 (phần "Root không bypass"); ADR 0008 (Root là role `system.root`; rank và `account_rank` của migration 006; bảo vệ peer bằng rank); ADR 0009 (chỉ phần nhắc "Root không bypass"; semantics audit của 0009 giữ nguyên). Các ADR đó giữ nguyên làm lịch sử.

## Bối cảnh

Đây là auth cho một sản phẩm duy nhất của một tổ chức cố định, không phải SaaS. Root là super admin của chính tổ chức đó, tương đương AWS root user so với IAM user. Rank (`authority_level`, `account_rank`) chồng một thứ bậc ngầm lên grant/deny/boundary và làm Root phụ thuộc grants code-owned.

## Quyết định

- **Root ngoài IAM.** `app_user.kind ∈ {root, iam}`, tối đa một Root (partial unique index). Root không có role, grant, boundary, record exception hay direct rule (`guard_root_not_iam_subject`). Root bypass mọi kiểm tra phân quyền qua `planUnrestricted` trên mọi resource/action đã khai báo, kể cả action thêm sau này. `kind` chỉ lấy từ `resolve_session` trong fenced transaction; tên role không tạo bypass.
- **Root vẫn phải qua:** session hợp lệ, `auth_epoch`, không suspended, CSRF/Origin; fresh-auth 300 giây (tính trong SQL bằng `statement_timestamp()`, chính xác µs) cho ghi `write`/`admin`; action đã khai báo; projection và writable allowlist; một event audit cho mỗi `access` commit (`principalKind: 'root'`, `outcome`), ghi trực tiếp, không qua obligation registry. Denied không audit. Event Root dạng `access.<resource>.<action>`; event obligation của IAM giữ dạng `access.<action>`.
- **IAM không rank.** Bảo vệ giữa IAM principal chỉ bằng grant, deny và permission boundary. Action tác động lên principal khác phải là `boundary: 'required'`; `account.suspend` hiện chỉ Root dùng được vì chưa có boundary nào cho `account`.
- **Bootstrap/revoke.** `bootstrap` chuyển một account pending `iam → root` đúng một lần cùng marker; `revoke-root` = suspended + tăng `auth_epoch`, marker giữ nguyên nên không có Root mới.
- **Genesis.** Reconciler product nhận release bất kỳ làm release đầu khi `release_sequence = 0` và catalog code-owned rỗng (cùng bảng/predicate với `protectedStateHash`); mọi trường hợp khác giữ predecessor nghiêm ngặt.
- **Migration 012 công bố `materialized_hash`.** Kiểm drift trước (hoặc catalog rỗng ở sequence 0), chuyển đổi, rồi đặt `materialized_hash = protectedStateHash` trên trạng thái sau chuyển đổi; không đổi `release_sequence`/`manifest_hash`; không baseline ngầm.
- **Protocol khóa.** Promotion khóa `FOR NO KEY UPDATE` dòng target trước khi kiểm; guard gắn fact/token đọc `kind` bằng `FOR SHARE` (FK `FOR KEY SHARE` không đủ). Promotion chỉ ở READ COMMITTED (guard từ chối mức khác). Lock ordering chỉ cam kết cho cặp promotion và gắn fact/token; `issueActivation` có thể gặp deadlock với SQL ngoài runner → fail closed, runner retry `40P01` hữu hạn.
- **`down` không đảo ngược** (`irreversible; restore from backup`): rank, role `system.root` và grants Root không khôi phục được và `release_sequence` không giảm. Rollback vận hành là restore backup hoặc forward repair.
- **Repair gỡ suspend Root** chỉ offline do owner bảng: một transaction `DISABLE TRIGGER guard_root_lifecycle` → `UPDATE` đúng dòng Root → `ENABLE`. Không ghi `audit_outbox`; bằng chứng là hồ sơ approval (reference, người duyệt, thời điểm, câu SQL).
- **Provenance.** Chỉ evaluator kiểm tập `issued`; SQL compiler và gateway dựa vào việc chỉ composition dựng được gateway. ESLint `no-restricted-syntax` giới hạn nơi gọi `planUnrestricted` là ranh giới developer, không phải sandbox.

## Rủi ro đã chấp nhận

- Lộ session Root cho phép đọc mọi dữ liệu nghiệp vụ; trong cửa sổ 300 giây sau reauth thì ghi được. Reauth OIDC phụ thuộc IdP. Giảm thiểu đầy đủ (MFA) thuộc spec MFA.
- Credential identity là ranh giới tin cậy của toàn bộ đăng nhập: `product_identity` bị chiếm có thể tạo session (kể cả `reauthenticated_at`) cho Root active.
- Mọi resource/action thêm sau tự động mở cho Root.
- Không còn bảo vệ peer mặc định giữa IAM principal (đúng mô hình IAM).
- Definition `rootAccounts@1` còn lại như dòng code-owned không binding sau nâng cấp.
- Migration import `protectedStateHash` của chính package: migration và binary release 2 phải cùng version.
- Không có Root sau nâng cấp khi Root đã bị revoke trước đó; cần repair offline có duyệt.
- Repair gỡ suspend dựa vào quyền DDL của owner bảng; DB không chặn owner.
- Chưa đo timing giữa Root/absent ở suspend.
```

- [ ] **Step 2: `AGENTS.md` (spec mục 8)**

Root `AGENTS.md`, mục "Bất biến bảo mật":

- Dòng `- Default deny; mọi deny thắng allow. …` → `- Với IAM principals: default deny; mọi deny thắng allow. Permission policy nằm ngoài mọi grant, kể cả record allow.`
- Thêm ngay sau: `- Root là account \`kind = root\` nằm ngoài IAM, là super admin bypass mọi kiểm tra phân quyền qua \`planUnrestricted\`, chỉ khi \`kind\` đến từ session đã kiểm chứng; tối đa một Root; chỉ bootstrap offline chuyển \`iam → root\`; mọi \`access\` của Root được audit; ghi nghiệp vụ/quản trị cần fresh-auth.`
- Dòng `- Cấm tự nâng quyền trực tiếp/gián tiếp, quản trị peer/superior, sửa code-owned …` → `- Không có rank ngầm. Bảo vệ giữa các IAM principal khai báo bằng boundary/deny. Action tác động lên principal khác phải là \`boundary: 'required'\`. Cấm tự nâng quyền trực tiếp/gián tiếp, sửa code-owned definitions qua UI và lấy quyền user admin để reset/link/impersonate global identity.`
- Mục "Ports và adapters", thêm cuối: `- Kế hoạch \`docs/superpowers/plans/2026-10-15-iam-root-separation.md\` (ADR 0012): IAM không rank, Root ngoài IAM, migration \`012\`; trạng thái theo checkbox/ledger của plan.`

`packages/core/AGENTS.md`: thay dòng `` `system.root` là role thông thường trong lõi … `` bằng `- Lõi không biết Root. \`planUnrestricted\` giữ mọi kiểm tra target/principal/user/validity của \`planUser\` cộng revision canonical, predicate \`true\`, không obligations; chỉ \`ProductAuthorization.access\` được gọi (ESLint \`no-restricted-syntax\`, test ở \`test/package-boundaries.spec.ts\`). Tên role, kể cả \`system.root\`, không tạo bypass.`; bảng file: `planner.ts` → `` `planUser`/`planUnrestricted`(chung`resolveTarget`) → `UserAuthorizedPlan`; `plan` là wrapper tenant cũ ``.

`packages/typeorm-postgres/AGENTS.md`, mục "Runtime một sản phẩm":

- `product-manifest.ts` → `` `product-manifest.ts`: release product v2 (role `{ key, label }`, tiền tố `system.` dự trữ, không system grants), genesis khi sequence 0 + catalog rỗng, drift gate qua `protected-state.ts`, bootstrap `iam → root` (khóa target trước), revoke = suspend. Boot không tạo user/assignment. ``
- `product-sql.ts, product-gateway.ts, product-authority.ts` → thêm `; nhánh Root duy nhất trong \`access\` (\`kind\` từ \`resolve_session\`, fresh-auth SQL \`PRODUCT_FRESH_AUTH_SQL\`, audit Root trực tiếp).`
- Thêm: `- Migration \`012\` (ADR 0012): \`app_user.kind\`, \`iam_account\`, năm guard Root SECURITY DEFINER owner \`product_session_owner\` (probe kiểm thân hàm, trigger và ACL owner chính xác); \`down\` không đảo ngược.`

`apps/api/AGENTS.md`, mục "Hiện trạng": `suspend user thấp cấp` → `suspend IAM user (Root, hoặc grant + boundary; resource \`account\` bind \`iam_account\`)`.

- [ ] **Step 3: Docs khác**

- `docs/prompt.md`: thêm dòng đầu `> **Prompt lịch sử.** Phần Root/rank của prompt này đã bị ADR 0012 (\`docs/decisions/0012-iam-root-separation.md\`) thay thế; không thực thi lại.` và một dòng trống; không sửa nội dung còn lại.
- `docs/permission-boundaries.md`: mục 6 (dòng 102) `rank trước/sau, self/peer` → `affected set, self và boundary/deny (không có rank; ADR 0012)`; thêm mục cuối "Root" 3 câu: Root ngoài IAM, không binding boundary, bypass qua `planUnrestricted`; boundary/deny chỉ áp IAM principals.
- `docs/authz-single-product-architecture.md`: dòng bảng `role_definition` bỏ `authority_level`; đầu mục 10.1 thêm `> Superseded bởi ADR 0012: Root là account \`kind = root\` ngoài IAM; nội dung bên dưới là lịch sử.`; dòng 327 bỏ `có rank cao hơn mọi user bị tác động trước/sau`.
- `docs/single-product-operations.md`: mục 2 bỏ `--boundaries`/`rootAccounts@1`, mô tả bootstrap `iam → root`; mục 4: revoke = suspend + auth_epoch; thêm mục "Nâng cấp lên migration 012" với runbook 5 bước của spec 4.1 (drain mọi instance/writer cũ, backup, provision với membership owner tạm, sync release 2, khởi động binary mới và probe pass), cảnh báo `down` không đảo ngược và migration/binary cùng version; thêm mục "Repair gỡ suspend Root":

```sql
BEGIN;
ALTER TABLE public.app_user DISABLE TRIGGER guard_root_lifecycle;
UPDATE public.app_user SET state='active' WHERE id='<root-uuid>' AND kind='root' AND state='suspended';
ALTER TABLE public.app_user ENABLE TRIGGER guard_root_lifecycle;
COMMIT;
```

kèm yêu cầu hồ sơ approval (reference, người duyệt, thời điểm, câu SQL) và chạy lại startup probe.

- `docs/single-product-reuse-map.md`: dòng `release validator/reconciler` → `stable system grants` thay bằng `release v2 (role key+label), genesis`; dòng planner thêm `planUnrestricted (Root, ADR 0012)`.

- [ ] **Step 4: Mutation check trên bản sao cô lập**

```bash
git worktree add /private/tmp/base-auth-iam-mutation HEAD
cd /private/tmp/base-auth-iam-mutation && pnpm install --frozen-lockfile
```

Mỗi mutation: sửa đúng chỗ, chạy lệnh, xác nhận FAIL ở test hành vi nêu tên, `git checkout -- .` trước mutation kế.

| #   | Mutation (spec mục 10)                    | Sửa                                                                                                                                       | Lệnh                                                                                                              | Test phải FAIL                                                               |
| --- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| 1   | Coi mọi principal là Root                 | `product-authority.ts`, ternary `decision`: `session.kind === 'root'` → `true`                                                            | `pnpm run test:integration -- test/product-root.integration-spec.ts`                                              | `IAM reads stay scoped and unaudited; a role named like Root grants nothing` |
| 2   | Lấy `kind` từ role name                   | cùng ternary → `snapshot.roles.includes('system.root')`                                                                                   | như #1                                                                                                            | cùng test #1 và `Root reads every document …`                                |
| 3   | Bỏ fresh-auth ghi Root                    | xóa dòng `if (session.kind === 'root' && mode !== 'read' && !session.fresh) throw …`                                                      | như #1                                                                                                            | `Root writes need a fresh reauthentication …`                                |
| 4   | Bỏ `kind = 'iam'` trong `iam_account`     | `012-iam-root.ts`: `… FROM public.app_user WHERE kind='iam'` → `… FROM public.app_user`                                                   | `pnpm run test:integration -- test/product-root-guards.integration-spec.ts test/product-root.integration-spec.ts` | `iam_account hides Root …`, `Root suspends an IAM account …`                 |
| 5   | Bỏ audit Root                             | xóa dòng `if (session.kind === 'root') await appendProductAudit(…)`                                                                       | như #1                                                                                                            | `Root reads every document …`                                                |
| 6   | Bỏ drift check trong migration            | `012-iam-root.ts`: xóa khối bước 2                                                                                                        | `pnpm run test:integration -- test/product-iam-migration.integration-spec.ts`                                     | `unmarked release 1: drift and a stray holder roll back …`                   |
| 7   | Genesis không kiểm catalog rỗng           | `product-manifest.ts`: `current!.sequence === '0' && (await codeOwnedCatalogIsEmpty(m))` → `current!.sequence === '0'`                    | `pnpm run test:integration -- test/product-genesis.integration-spec.ts`                                           | `genesis needs an empty code-owned catalog …`                                |
| 8   | Bỏ `FOR SHARE` trong guard subject        | `guardRootNotIamSubjectBody`: xóa ` FOR SHARE`                                                                                            | `pnpm run test:integration -- test/product-root-concurrency.integration-spec.ts`                                  | `facts and tokens written while a promotion holds the target wait …`         |
| 9   | Bỏ kiểm isolation trong `guard_root_kind` | xóa khối `IF current_setting('transaction_isolation')…END IF;`                                                                            | như #8                                                                                                            | `a promotion outside READ COMMITTED is refused …`                            |
| 10  | Cho `product_authority` sửa `state` Root  | `guardRootLifecycleBody`: `ELSIF session_user<>'product_identity'` → `ELSIF session_user NOT IN ('product_identity','product_authority')` | `pnpm run test:integration -- test/product-root-guards.integration-spec.ts`                                       | `lifecycle: bootstrap never touches IAM, authority never touches Root …`     |

Sau cùng: `git worktree remove /private/tmp/base-auth-iam-mutation --force`. Ghi từng kết quả thật (exit code, tên test fail) vào `docs/single-product-verification.md`.

- [ ] **Step 5: Kiểm tra thủ công một lần: binary cũ trên schema mới**

```bash
git worktree add /private/tmp/base-auth-50d6053 50d6053
(cd /private/tmp/base-auth-50d6053 && pnpm install --frozen-lockfile && pnpm run build)
docker run -d --rm --name iam-compat -e POSTGRES_USER=fixture -e POSTGRES_PASSWORD=compat-fixture -p 55432:5432 postgres:18.4
```

Script `/private/tmp/iam-compat-provision.ts` (chạy từ repo hiện tại, dist mới):

```ts
import { randomBytes } from 'node:crypto';
import { provisionProductDatabase } from '/Users/vinhdq2312/Documents/personal/base-auth/packages/typeorm-postgres/dist/operations.js';
const passwords = Object.fromEntries(
  ['data', 'identity', 'authority', 'sync', 'migration', 'bootstrap', 'outbox'].map((p) => [
    p,
    randomBytes(16).toString('hex'),
  ]),
);
// Run with Node type stripping (no type check): plain values, no casts.
const settings = await provisionProductDatabase(
  {
    host: '127.0.0.1',
    port: 55432,
    username: 'fixture',
    password: 'compat-fixture',
    database: 'postgres',
  },
  passwords,
);
console.log(JSON.stringify(settings));
```

Script `/private/tmp/iam-compat-old-probe.ts` (dist của `50d6053`) đọc JSON trên từ stdin, mở DataSource cho `data`, `identity`, `authority`, `sync` bằng `productDataSourceOptions` của `/private/tmp/base-auth-50d6053/packages/typeorm-postgres/dist/operations.js` và gọi `verifyProductPrivileges` của `/private/tmp/base-auth-50d6053/packages/typeorm-postgres/dist/composition.js`.

```bash
node /private/tmp/iam-compat-provision.ts | node /private/tmp/iam-compat-old-probe.ts
```

Expected: probe cũ ném `Product privilege drift …` hoặc `Product protection drift`. Ghi lệnh và kết quả (không ghi password) vào `docs/single-product-verification.md`; dọn: `docker stop iam-compat`, `git worktree remove /private/tmp/base-auth-50d6053 --force`, xóa hai script.

- [ ] **Step 6: `docs/single-product-verification.md`**

Giữ nguyên bằng chứng lịch sử (dòng mutation "Bypass Root" từng là lỗi). Thêm mục mới "IAM thuần / Root ngoài IAM (ADR 0012)" gồm: bảng lệnh gate với exit code và số test thật; bảng 10 mutation ở Step 4 với kết quả; kết quả kiểm tra thủ công Step 5; semantics mới (Root bypass có fresh-auth ghi và audit).

- [ ] **Step 7: Full gate**

Run (từ repo root, từng lệnh, ghi exit code và số test thật):

```bash
pnpm install --frozen-lockfile
pnpm run format:check
pnpm run lint
pnpm run typecheck
pnpm run build
pnpm run test:unit
pnpm run test:integration
pnpm run test:e2e
```

Expected: mọi lệnh exit 0. Lỗi môi trường (Docker/Testcontainers timeout) báo riêng, chạy lại đúng nhóm và ghi cả hai kết quả; không gọi là pass khi chưa pass.

- [ ] **Step 8: Cập nhật checkbox, ledger và commit**

Đánh dấu checkbox đã có bằng chứng; điền ledger bên dưới.

```bash
git add docs/decisions/0012-iam-root-separation.md AGENTS.md packages/core/AGENTS.md packages/typeorm-postgres/AGENTS.md apps/api/AGENTS.md docs/permission-boundaries.md docs/authz-single-product-architecture.md docs/single-product-operations.md docs/single-product-reuse-map.md docs/single-product-verification.md docs/prompt.md docs/superpowers/plans/2026-10-15-iam-root-separation.md
git commit -m "docs: ADR 0012, invariants, runbook and verification for IAM without rank and Root outside IAM"
```

---

## Spec deviations

1. **Revision trong `planUnrestricted`.** Spec 6.2 và mục 10 ("revision sai") nói `planUnrestricted` "vẫn kiểm … snapshot revision" như `planUser`, nhưng `planUser` không kiểm revision mà chỉ chép (`packages/core/src/planner.ts:258`). Plan: `planUnrestricted` từ chối `invalid_revision` khi revision không phải int64 canonical ≥ 1; `planUser` giữ nguyên (không thắt chặt ngầm đường IAM).
2. **Dạng event access.** Spec 6.5 đặt event Root là `access.<resource>.<action>`, còn obligation `audit@1` của IAM ghi `access.<action>` (`packages/typeorm-postgres/src/product-obligations.ts:16`). Plan theo đúng chữ của spec cho Root, giữ IAM nguyên (spec: event IAM không đổi); ADR 0012 ghi rõ hai dạng.
3. **Ngoại lệ ESLint cho core test.** Spec 6.2: "chỉ `packages/typeorm-postgres/src/product-authority.ts` được gọi". Test hành vi của core (spec mục 10 "Core") phải gọi trực tiếp, nên rule bỏ qua `packages/core/test/**`; mọi source và test khác vẫn bị chặn (ca negative gồm `test/product-root.integration-spec.ts`).
4. **"Bỏ toàn bộ khối `IF TG_TABLE_NAME='user_role'`" của guard 004.** Trong `004-protection-guards.ts:35-56`, khối đó là nhánh `IF` của một `IF/ELSIF` mà `ELSIF` xử lý `policy_rule`/`record_exception`. Xóa nguyên văn cả câu lệnh sẽ mất nhánh khác. Plan chỉ bỏ nhánh `user_role` và nâng `ELSIF` thành `IF` (`productRowsIamBody`), đúng ý "mọi nhánh khác giữ ngữ nghĩa".
5. **"Release 1 thật … bootstrap → revoke-root thật" sau khi code đổi.** Sau Task 3–4, package không còn đường ghi của release 1 (`systemGrants`, `authority_level`, gán `user_role`). Plan đóng băng bản `50d6053` bằng `git show` vào `test/fixtures/release-one/` (chỉ đổi import và constructor parameter-property vì `erasableSyntaxOnly`/strip-types), ghim hash `c1fbb345…`, và thêm tham số `migrations` cho `provisionProductDatabase` (`product-database.ts:62`) để dựng schema `011` qua provisioning thật. Hai trạng thái "holder ≠ marker" và "> 1 holder" không lệnh nào tạo được (007/004 chặn), nên dựng bằng owner bảng tắt trigger trong test; trạng thái "Root đã bị revoke" dùng bootstrap → revoke-root thật như spec yêu cầu.
6. **Thứ tự mục 12.** Bước 2 ("tách contract release, bỏ system grants") đứng trước migration ở spec, nhưng reconciler product ghi `role_definition.authority_level` (`product-manifest.ts:624-640`) và bootstrap ghi `user_role`/`user_boundary` (`product-manifest.ts:868-890`), cả hai chỉ đổi được cùng `012` mà vẫn giữ suite xanh. Plan: Task 1 làm phần không phụ thuộc schema (hash helper, validation dùng chung, genesis), Task 3 đổi schema cùng đường ghi DB và dữ liệu release 2, Task 4 xóa contract system grants. Bước 1 (ADR/AGENTS/prompt) dời về Task 10 theo yêu cầu người giao plan.
7. **"INSERT `kind = 'root'` bị từ chối với mọi login".** Các runtime login không có quyền INSERT cột `kind` (`002-protection.ts:64` chỉ cấp cột cho identity; các login khác không INSERT `app_user`), nên PostgreSQL chặn bằng ACL (`42501`) trước guard. Plan test cả hai tầng: ACL với mọi runtime login, guard với owner bảng `product_migration`.
8. **"Reauth OIDC" trong test fresh-auth.** Spec 6.4 yêu cầu ca reauth OIDC. Repo không có IdP thật trong suite `product-root`; plan dựng session OIDC bằng credential identity với `reauthenticated_at` đặt bởi DB (đúng cột mà luồng OIDC reauth ghi, `product-oidc.ts:387`), vì điều kiện fresh không phụ thuộc phương thức. Luồng OIDC reauth thật vẫn được `test/product-identity.integration-spec.ts` kiểm như cũ.

## Spec coverage (tự review)

| Mục spec                            | Task                                            |
| ----------------------------------- | ----------------------------------------------- |
| 3.1 schema đích                     | 3                                               |
| 3.2 guard, ACL owner, guard 004     | 3 (probe ACL owner, case drift)                 |
| 3.3 protocol khóa, isolation        | 3 (khóa trong bootstrap/reissue), 6             |
| 3.4 ma trận quyền                   | 3                                               |
| 3.5 CLI                             | 3 (DB path, thông điệp), 9                      |
| 4.1 quyền chạy, runbook             | 3 (migration), 5 (provision thật), 10 (runbook) |
| 4.2 trình tự 1–9                    | 3, 5                                            |
| 4.3 bảng backfill                   | 5                                               |
| 4.4 inventory trigger               | 3                                               |
| 4.5 `down`                          | 3, 5                                            |
| 4.6 repair                          | 3 (Review Focus 5), 10                          |
| 5.1 tách contract                   | 1, 4                                            |
| 5.2 release 2, genesis              | 1, 3, 4, 5                                      |
| 6.1–6.3 nguồn sự thật, core, access | 2, 7                                            |
| 6.4 fresh-auth                      | 7, 8                                            |
| 6.5 audit Root                      | 7, 8                                            |
| 7.1–7.2 account, suspend            | 3, 8                                            |
| 8 ADR, AGENTS, docs, prompt         | 10                                              |
| 9 bản kê fixtures                   | 3, 4, 7, 8, 9                                   |
| 10 kiểm thử + mutation + gate       | 1–10                                            |
| 11 rủi ro                           | 10 (ADR)                                        |

## Ledger trạng thái task

| Task                                                | Trạng thái   | Lệnh/bằng chứng mới | Rủi ro hoặc gate còn lại                                                                                           |
| --------------------------------------------------- | ------------ | ------------------- | ------------------------------------------------------------------------------------------------------------------ |
| T1 `protectedStateHash`, helper validation, genesis | Chưa bắt đầu | —                   | Literal hash legacy lấy từ dist `50d6053`; nếu HEAD khác, chụp lại trước refactor                                  |
| T2 Core `planUnrestricted`, ESLint                  | Chưa bắt đầu | —                   | —                                                                                                                  |
| T3 Migration `012`, guard, probe, đường ghi DB      | Chưa bắt đầu | —                   | Task lớn nhất; kiểm ACL owner (`is_grantable` của owner entry) trên PostgreSQL 18.4 thật                           |
| T4 Contract release v2                              | Chưa bắt đầu | —                   | Hash release 2 `e11f43e8…` tính từ envelope; khác thì so envelope                                                  |
| T5 Nâng cấp từ release 1 thật                       | Chưa bắt đầu | —                   | Fixture đóng băng phụ thuộc `git show 50d6053`                                                                     |
| T6 Concurrency                                      | Chưa bắt đầu | —                   | Đồng bộ bằng `pg_blocking_pids`, không sleep đoán                                                                  |
| T7 Bypass, fresh SQL, audit Root                    | Chưa bắt đầu | —                   | —                                                                                                                  |
| T8 Account, suspend                                 | Chưa bắt đầu | —                   | OpenAPI hash `f0f1c5c5…` tính từ summary mới                                                                       |
| T9 CLI Root                                         | Chưa bắt đầu | —                   | —                                                                                                                  |
| T10 Docs, ADR 0012, mutation, gate                  | Chưa bắt đầu | —                   | Kiểm tra binary cũ trên schema mới là thủ công một lần; local không thay CI/production, không gọi production-ready |
