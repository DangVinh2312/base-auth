/** Contract for the deliberately small API. DTO validation uses the same field allowlists in handlers. */
const errors = {
  400: { description: 'Invalid DTO or cookie' },
  401: { description: 'Authentication failed' },
  403: { description: 'CSRF, permission, policy, boundary or invariant denied' },
  404: { description: 'Absent or hidden record' },
  409: { description: 'Bounded concurrency conflict' },
  503: { description: 'Authority or required capability unavailable' },
};
const fields = (names: readonly string[]) => ({
  type: 'object',
  additionalProperties: false,
  required: names,
  properties: Object.fromEntries(
    names.map((name) => [
      name,
      {
        type: 'string',
        maxLength: 2048,
        example:
          name === 'email'
            ? 'person@example.test'
            : name === 'issuer'
              ? 'https://idp.example.test'
              : name === 'subject'
                ? 'provider-subject'
                : name.toLowerCase().includes('password')
                  ? 'a unique password of at least fifteen characters'
                  : name === 'title'
                    ? 'Revised title'
                    : 'synthetic-one-time-proof',
      },
    ]),
  ),
});
const operation = (
  description: string,
  example: unknown,
  body: readonly string[] = [],
  authenticated = false,
) => ({
  summary: description,
  ...(authenticated ? { security: [{ sessionCookie: [] }] } : {}),
  ...(body.length
    ? { requestBody: { required: true, content: { 'application/json': { schema: fields(body) } } } }
    : {}),
  responses: {
    200: { description: 'Success', content: { 'application/json': { example } } },
    ...errors,
  },
});
const post = (summary: string, example: unknown, body: readonly string[], auth = false) => ({
  post: operation(summary, example, body, auth),
});
export const productOpenApi = {
  openapi: '3.1.0',
  info: { title: 'Single product authorization API', version: '1' },
  components: {
    securitySchemes: {
      sessionCookie: {
        type: 'apiKey',
        in: 'cookie',
        name: '__Host-authz_session',
        description:
          'Development HTTP uses authz_session. All mutations also require exact Origin and x-csrf-token matching the CSRF cookie.',
      },
    },
  },
  paths: {
    '/health/live': { get: operation('Process liveness', { status: 'ok' }) },
    '/health/ready': {
      get: operation('Readiness after privilege checks and manifest sync', { status: 'ready' }),
    },
    '/health/metrics': {
      get: operation('Bounded transaction metric histograms', [
        { metric: 'lock_wait', mode: 'read', count: 1, sum: 5, buckets: [{ upper: 10, count: 1 }] },
      ]),
    },
    '/openapi.json': { get: operation('This API contract', { openapi: '3.1.0' }) },
    '/auth/csrf': {
      get: operation('Issue a CSRF cookie and header token', { csrfToken: 'synthetic-csrf-token' }),
    },
    '/auth/login': post('Local password login', { expiresAt: '2026-10-14T00:00:00.000Z' }, [
      'email',
      'password',
    ]),
    '/auth/activate': post('Consume a local activation proof', { status: 'activated' }, [
      'token',
      'password',
    ]),
    '/auth/session': {
      get: operation(
        'Current verified session projection',
        { userId: '00000000-0000-4000-8000-000000000001', method: 'local', assurance: 'password' },
        [],
        true,
      ),
    },
    '/auth/reauthenticate': post(
      'Reauthenticate and rotate local session',
      { expiresAt: '2026-10-14T00:00:00.000Z' },
      ['password'],
      true,
    ),
    '/auth/logout': post('Revoke current application session', { status: 'revoked' }, [], true),
    '/auth/logout-all': post(
      'Revoke all current application sessions',
      { status: 'revoked' },
      [],
      true,
    ),
    '/auth/password': post(
      'Self-service password change; revokes sessions',
      { status: 'changed' },
      ['currentPassword', 'password'],
      true,
    ),
    '/auth/recovery/request': post(
      'Request recovery using configured delivery; unavailable if no delivery adapter',
      { status: 'accepted' },
      ['email'],
    ),
    '/auth/recovery/reset': post(
      'Consume reset proof once; cannot create a local credential on OIDC-only account',
      { status: 'reset' },
      ['token', 'password'],
    ),
    '/auth/oidc/begin': post(
      'Begin allowlisted OIDC Code+PKCE login',
      { authorizationUrl: 'https://idp.example.test/authorize' },
      ['issuer'],
    ),
    '/auth/oidc/activate': post(
      'Begin activation of a pending account with its offline one-time invitation; the IdP proof must be the exact pre-bound subject',
      { authorizationUrl: 'https://idp.example.test/authorize' },
      ['issuer', 'token'],
    ),
    '/auth/oidc/reauthenticate': post(
      'Fresh OIDC proof and session rotation',
      { authorizationUrl: 'https://idp.example.test/authorize' },
      ['issuer'],
      true,
    ),
    '/auth/oidc/link': post(
      'Link provider after recent reauthentication and new provider proof',
      { authorizationUrl: 'https://idp.example.test/authorize' },
      ['issuer'],
      true,
    ),
    '/auth/oidc/unlink': post(
      'Unlink provider; refuses last authentication method',
      { status: 'unlinked' },
      ['issuer', 'subject'],
      true,
    ),
    '/auth/oidc/callback': {
      get: {
        ...operation('Consume browser-bound OIDC attempt', { status: 'authenticated' }),
        parameters: [
          { name: 'state', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'code', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'iss', in: 'query', required: false, schema: { type: 'string' } },
        ],
      },
    },
    '/documents': {
      get: operation(
        'Scoped list before pagination with allowed projection',
        {
          items: [
            { key: '00000000-0000-4000-8000-000000000002', title: 'Visible draft', state: 'draft' },
          ],
          total: '1',
        },
        [],
        true,
      ),
    },
    '/documents/{id}': {
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
      ],
      get: operation(
        'Scoped detail; hidden and absent return identical404',
        { key: '00000000-0000-4000-8000-000000000002', title: 'Visible draft', state: 'draft' },
        [],
        true,
      ),
      patch: operation('Update title of authorized draft', { status: 'updated' }, ['title'], true),
    },
    '/administration/users/{id}/suspend': {
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
      ],
      ...post(
        'Suspend a strictly lower user under policy and required boundary',
        { status: 'suspended' },
        [],
        true,
      ),
    },
  },
};
