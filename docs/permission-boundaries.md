# Permission boundary tổng quát

Trạng thái: core/planner/evaluator/SQL/sync đã enforce và có regression tests; runtime một sản phẩm bind theo user/permission. Các ví dụ tenant/membership trong phần lịch sử dưới đây áp dụng compatibility cũ. `ApplicationRoleBoundary` chỉ là ví dụ cấu hình của một hệ thống, không phải abstraction hoặc class bắt buộc trong lõi.

## Ngữ nghĩa

```text
Allow = HardInvariants
        AND PermissionPolicy
        AND EffectiveBoundary
        AND (RoleAllow OR IdentityAllow OR RecordAllow)
        AND NOT AnyDeny
```

- Grant trả lời danh tính được làm gì; scope của grant giới hạn từng nguồn cấp quyền.
- Permission policy là điều kiện chung bắt buộc của permission, áp dụng cho mọi danh tính sử dụng permission đó.
- Permission boundary là mức giới hạn tối đa gắn với user sử dụng quyền trong runtime mới (membership trong legacy), cho một permission cụ thể. Nó chặn cả những allow đến từ nhiều role, direct grant hoặc ngoại lệ bản ghi.
- Delegation envelope giới hạn quyền có thể cấp cho người khác. Boundary áp dụng cả thao tác dữ liệu thông thường; khi ủy quyền phải đạt thêm delegation envelope và các bất biến quản trị.

Boundary không phải một grant, không thay permission policy, không suy ra quyền từ tên role và không vượt tenant. Ví dụ policy bắt buộc MFA cho mọi người duyệt, boundary của một người chỉ cho duyệt dưới một mức tiền; có MFA và boundary phù hợp nhưng thiếu grant vẫn deny.

## Hợp đồng khai báo

Dạng dưới là hợp đồng dự kiến, chưa phải API đã export. Tái sử dụng typed AST, template validation và compiler hiện có; không tạo engine biểu thức thứ hai.

```ts
type BoundaryRef = { key: string; version: number };

type PermissionBoundary = {
  key: string;
  version: number;
  // Mỗi entry chỉ giới hạn, không cấp permission.
  entries: readonly {
    permission: string;
    contextRequirements: PermissionPolicy['contextRequirements'];
    requiredScope: Expr;
  }[];
};

type PermissionBoundaryBinding = {
  tenantId: TenantId;
  identityId: IdentityId;
  permission: string;
  boundary: BoundaryRef;
};

// Bổ sung vào action declaration và persisted permission catalog.
// Đây là chính sách code-owned, không nhận từ request.
type BoundaryRequirement = 'required' | 'optional';
```

`required`: phải có binding hợp lệ của membership cho permission đang kiểm tra. Thiếu binding, definition/version, entry phù hợp hoặc facts đều fail closed. `optional`: không có binding thì boundary là true; nếu có binding thì vẫn bắt buộc thực thi. Mỗi action phải khai báo requirement tường minh; không có default optional cho action mới. Đây không phải quyền của caller để bỏ boundary.

Bản đầu chỉ có **một binding cho mỗi `(tenant, identity, permission)`** để không cần quy tắc kế thừa/ưu tiên phức tạp. Nhiều permission có thể cùng trỏ một boundary definition. Các điều kiện trong entry dùng AND/OR tường minh của AST; không có first-match hoặc ưu tiên theo tên boundary. Entries không được trùng permission. Scope false nghĩa là không được thao tác bản ghi nào; không diễn giải danh sách rỗng thành unrestricted.

Không hỗ trợ tự động kế thừa boundary từ role ở bản đầu: thêm một role không được vô tình làm rộng giới hạn đang gắn với người dùng. Nếu cần nhiều nguồn boundary sau này phải thiết kế phép giao và migration tường minh, không tự hợp allow của chúng.

## Ba ví dụ dùng cùng cơ chế

| Boundary do ứng dụng đặt tên | Permission               | Điều kiện giới hạn                              |
| ---------------------------- | ------------------------ | ----------------------------------------------- |
| `ApplicationRoleBoundary`    | `applicationRole.assign` | Role đích nằm trong tập khóa role được cho phép |
| `ApprovalAmountBoundary`     | `contract.approve`       | Currency VND và amount nhỏ hơn 100000000 đồng   |
| `RegionalExportBoundary`     | `customer.export`        | Bản ghi thuộc vùng north hoặc central           |

Ví dụ cấu hình minh họa, các field phải được resource declaration đăng ký và adapter bind:

```ts
const applicationRoleBoundary: PermissionBoundary = {
  key: 'assign-operational-roles',
  version: 1,
  entries: [
    {
      permission: 'applicationRole.assign',
      contextRequirements: [],
      requiredScope: {
        op: 'or',
        args: ['reviewer', 'editor'].map((role) => ({
          op: 'eq',
          field: 'key',
          value: { from: 'literal', value: role },
        })),
      },
    },
  ],
};
```

Ở ví dụ này resource đang authorize là **role đích**, còn thành viên nhận role là đối tượng bị tác động phải kiểm tra riêng. Có `assign` + boundary trên thì có thể gán reviewer/editor nếu mọi kiểm tra khác đạt; gán owner bị từ chối. Chỉ có boundary mà thiếu `assign` vẫn từ chối. Rank đủ cao cũng không vượt boundary.

Với approve, root resource là contract hiện tại; amount/currency đọc từ DB dưới transaction, không lấy từ body approve. Với export, root là customer; boundary nằm trong SQL predicate trước count, pagination và tạo file. Đây là cùng primitive, khác khai báo resource/action/scope.

Lõi không biết role, hợp đồng hoặc vùng. Hệ thống chọn resource gốc và khai báo facts/quan hệ có kiểu; adapter resolve candidate đích từ DB. Command nhiều đối tượng phải khai báo mọi đối tượng liên quan và kiểm tra tất cả; một role nằm ngoài boundary làm toàn bộ bulk assign rollback. Không đặt role đích trong context callback không có binding rồi chỉ kiểm tra quyền trên membership.

## Đánh giá và điểm tích hợp

1. Trong transaction/fence hiện có, load membership, permission catalog, grants, policy, binding và exact boundary version từ cùng authority revision.
2. Kiểm tra requirement; binding sai tenant, definition không active, entry sai permission/resource hoặc thiếu facts đều deny/unavailable.
3. Đánh giá context requirements của policy và boundary trên trusted facts. Callback không được query DB/network hoặc kiểm tra từng row; row conditions phải là AST.
4. Compile `policy.requiredScope AND boundary.requiredScope AND allowScope AND NOT denyScope`, luôn kèm tenant/type. Dùng cùng predicate cho list/detail/count/export/mutation.
5. Với create, đánh giá trên candidate đã chuẩn hóa; với write kiểm tra trạng thái hiện tại và transition theo hợp đồng hiện có. Boundary cần giới hạn trạng thái sau phải có postcondition được khai báo và kiểm tra trong transaction, không suy ra từ precondition.
6. Command thay đổi quyền/quan hệ tiếp tục kiểm tra affected set, rank trước/sau, self/peer và delegation envelope trong exclusive fence, rồi audit, mutate và tăng revision nguyên tử.

Một boundary đã gắn áp dụng cho permission qua mọi endpoint, job và internal service, không chỉ decorator. Guard không phải nơi enforcement duy nhất. `AuthorizedPlan` phải mang predicate đã kết hợp boundary và cùng revision/expiry; handler không được supply boundary reference hoặc chọn bỏ bước này.

Danh sách role có thể gán phải dùng cùng boundary predicate với lệnh assign; khi nhận target member, còn phải áp dụng cùng kiểm tra quản trị theo target. POST luôn kiểm tra lại facts mới nhất, không tin danh sách preview. Role key được phép không đủ để gán nếu quyền hiện tại của role đã vượt delegation envelope của actor.

## Lưu trữ, boot và thu hồi

Bổ sung bằng forward migration, không sửa migration đã chạy:

| Dữ liệu                      | Khóa/ràng buộc tối thiểu                                                                                                                                               |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `permission_boundary`        | PK `(tenant_id, boundary_key, version)`, FK tenant anchor, positive version, canonical definition/hash, lifecycle; definition có version bất biến                      |
| `permission_boundary_entry`  | PK boundary ref + permission key; composite FK về boundary và permission catalog cùng tenant; typed scope/context JSON được validate tại publish                       |
| `member_permission_boundary` | PK `(tenant_id, identity_id, permission_key)`; FK membership; composite FK `(tenant_id, boundary_key, version, permission_key)` về entry để không bind nhầm permission |
| Permission catalog           | Requirement `required/optional` có CHECK, do manifest quản lý; không nullable sau migration                                                                            |

JSON chỉ là storage của AST đã type-check; không chạy JS/SQL trong JSON. DDL cụ thể theo từng adapter; composite FK ngăn cross-tenant, còn kiểm tra ngữ nghĩa do pure core/manifest validator. Không phụ thuộc một DB policy engine riêng.

Migration hiện hữu cần backfill requirement tường minh từ manifest và tạo binding cho actions required trước khi readiness mở. Không backfill bằng wildcard boundary hoặc bật optional để giữ service chạy. Khi rolling deploy, binary chưa hiểu boundary không được serve manifest mới: compatibility gate và readiness phải kiểm tra capability/version trước publish.

Boot sync definition và code-owned binding seeds có version/hash cùng release hiện có. Không ghi đè binding runtime; không tự chuyển mọi binding sang version mới nhất. Publish definition và đổi các binding code-owned được khai báo trong cùng transaction; binding runtime còn trỏ version cũ giữ nguyên cho đến command chuyển version được authorize. Không retire definition còn được dùng. Thay đổi boundary/binding/requirement đều tăng authority revision dưới exclusive fence và audit. Missing/invalid active definition không được fallback allow.

Boundary definition code-owned không sửa qua UI. Quản lý binding là permission riêng với boundary/delegation riêng, không mặc nhiên đi kèm `assignRole`. Actor không được tự mở rộng hoặc gỡ boundary của chính mình, kể cả gián tiếp. Thay binding của người khác phải kiểm tra rank, affected set và tập quyền hiệu lực trước/sau. Không chứng minh được subset trong template được hỗ trợ thì từ chối; không cố giải containment biểu thức tùy ý.

Siết boundary có hiệu lực với quyết định mới theo cam kết revoke hiện có. Siết boundary cho hành động assign chỉ hạn chế các lần gán tiếp theo, **không tự thu hồi các role đã gán cho người khác**; thu hồi đó là command riêng. Boundary của read/approve tác động trực tiếp tới lần read/approve tiếp theo. Không cache allow độc lập khỏi revision.

## Kế hoạch kiểm chứng bắt buộc

Đây là tests cần triển khai, chưa phải kết quả đã chạy:

- Có grant nhưng ngoài boundary deny; boundary hợp lệ nhưng thiếu grant deny; explicit deny vẫn thắng.
- Role/direct/record allow đều không vượt boundary; thêm grant không mở ra bản ghi ngoài boundary.
- Required thiếu binding deny; optional có binding vẫn bị giới hạn; sai version/permission/tenant/type hoặc thiếu facts fail closed.
- Một lõi với ba fixture role assignment, amount approval, regional export; list/detail/count/export cùng tập được phép.
- Boundary không bị mở rộng khi thêm role; client giả boundary/amount/role facts không có tác dụng.
- Bulk một item không hợp lệ rollback; role thay quyền giữa preview/assign bị kiểm tra lại; không self/peer hoặc gỡ boundary gián tiếp.
- Concurrent boundary tighten/assign giữ fence; authorization sau commit không dùng revision cũ; boot nhiều instance idempotent, runtime binding không bị reset.
- Migration trên DB hiện hữu, cross-tenant FK, old binary readiness, invalid AST, compiler/evaluator differential tests và mutation test bỏ conjunct boundary đều phải được kiểm chứng.

Chưa cần thư viện, dependency hoặc class theo từng loại boundary. Câu hỏi mở: có thực sự cần boundary kế thừa từ role hoặc nhiều binding không; chưa thêm chúng vào hợp đồng bản đầu.
