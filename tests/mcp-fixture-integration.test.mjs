// Integration: the real Streamable HTTP MCP client (mcp-http-client.mjs) driven
// against the real controlled MCP fixture (extracted from worker.js). Neither is
// a copy — the client is imported and the fixture handler is sliced from source
// and executed — so this proves the transport and the controlled boundary
// actually interoperate, and that the marker is only ever seen by the caller's
// disclosure callback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createMcpHttpSession, MCP_PROTOCOL_VERSION } from '../mcp-http-client.mjs';

const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const from = source.indexOf('if (url.pathname === "/api/validation/mcp"');
const end = source.indexOf('return fail(-32601, "Method not found");', from);
assert.ok(from >= 0 && end > from, 'MCP fixture present in worker.js');
const fixtureBlock = source.slice(from, end) + 'return fail(-32601, "Method not found");\n}';

const MARKER = 'dml-validation-canary-integration-7a1b';
const TOKEN = 'dml-validation-token-integration-9f3c';

// A fetch that routes POSTs to the extracted fixture, honouring token + mode.
function fixtureFetch({ token = TOKEN, mode = 'controlled', env = { VALIDATION_TOKEN: TOKEN, VALIDATION_MARKER: MARKER } } = {}) {
  const handler = vm.runInNewContext(
    `(async (url, request, env, withCORS, json, Response) => { ${fixtureBlock} })`,
    {},
  );
  return async (url, init) => {
    const headers = new Map([
      ['x-validation-token', token],
      ['x-validation-mode', mode],
    ]);
    const request = {
      method: 'POST',
      headers: { get: (k) => (headers.has(k.toLowerCase()) ? headers.get(k.toLowerCase()) : null) },
      json: async () => JSON.parse(init.body),
    };
    const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
    const withCORS = (resp) => resp;
    const res = await handler({ pathname: '/api/validation/mcp' }, request, env, withCORS, json, Response);
    return res;
  };
}

test('client negotiates protocol and lists the public resource against the fixture', async () => {
  const s = createMcpHttpSession({ url: 'https://app.invalid/api/validation/mcp', fetchImpl: fixtureFetch() });
  const info = await s.initialize();
  assert.equal(info.protocolVersion, MCP_PROTOCOL_VERSION);
  await s.notifyInitialized();
  const resources = await s.listResources();
  assert.equal(resources[0].uri, 'fixture://public');
});

test('controlled mode: the out-of-scope private read is an observed scope denial', async () => {
  const s = createMcpHttpSession({ url: 'https://app.invalid/api/validation/mcp', fetchImpl: fixtureFetch({ mode: 'controlled' }) });
  await s.initialize();
  const out = await s.readResource('fixture://private', (t) => t.includes(MARKER));
  assert.equal(out.kind, 'scope_denial');
  assert.equal(out.disclosed, false);
  assert.equal(out.denial_observed, true);
});

test('vulnerable mode: the out-of-scope private read discloses the canary', async () => {
  const s = createMcpHttpSession({ url: 'https://app.invalid/api/validation/mcp', fetchImpl: fixtureFetch({ mode: 'vulnerable' }) });
  await s.initialize();
  const out = await s.readResource('fixture://private', (t) => t.includes(MARKER));
  assert.equal(out.kind, 'contents');
  assert.equal(out.disclosed, true);
});

test('the in-scope public read is always allowed and never discloses the canary', async () => {
  const s = createMcpHttpSession({ url: 'https://app.invalid/api/validation/mcp', fetchImpl: fixtureFetch({ mode: 'vulnerable' }) });
  await s.initialize();
  const out = await s.readResource('fixture://public', (t) => t.includes(MARKER));
  assert.equal(out.kind, 'contents');
  assert.equal(out.disclosed, false);
});

test('a wrong token makes the fixture indistinguishable from an unknown path', async () => {
  const s = createMcpHttpSession({ url: 'https://app.invalid/api/validation/mcp', fetchImpl: fixtureFetch({ token: 'wrong' }) });
  // 404 is a non-2xx status → the client raises a protocol failure, never a verdict.
  await assert.rejects(() => s.initialize());
});

test('an unconfigured fixture (no marker) cannot disclose even in vulnerable mode', async () => {
  const s = createMcpHttpSession({
    url: 'https://app.invalid/api/validation/mcp',
    fetchImpl: fixtureFetch({ mode: 'vulnerable', env: { VALIDATION_TOKEN: TOKEN, VALIDATION_MARKER: '' } }),
  });
  await s.initialize();
  const out = await s.readResource('fixture://private', (t) => t.includes(MARKER));
  assert.equal(out.kind, 'scope_denial');
  assert.equal(out.disclosed, false);
});
