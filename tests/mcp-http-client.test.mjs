// Streamable HTTP MCP client (Phase 2). Strictness is the security property:
// any deviation from JSON-RPC 2.0 single-response framing is a protocol failure,
// which the evidence model must treat as ERROR/UNKNOWN, never a security outcome.
// Transport text is never returned verbatim; disclosure is decided by a caller
// callback so this module never sees or retains a marker.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseMcpBody, validateJsonRpcResponse, createMcpHttpSession,
  McpProtocolError, MCP_PROTOCOL_VERSION, MCP_EXECUTABLE_TRANSPORTS,
} from '../mcp-http-client.mjs';

// ── transport constraint ────────────────────────────────────────────────────
test('only Streamable HTTP is executable; stdio is never guessed', () => {
  assert.deepEqual(MCP_EXECUTABLE_TRANSPORTS, ['STREAMABLE_HTTP']);
  assert.equal(MCP_EXECUTABLE_TRANSPORTS.includes('STDIO'), false);
});

// ── parseMcpBody ────────────────────────────────────────────────────────────
test('parses a bare application/json object', () => {
  const m = parseMcpBody('application/json', '{"jsonrpc":"2.0","id":1,"result":{}}');
  assert.equal(m.id, 1);
});
test('parses a single SSE data frame', () => {
  const body = 'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"ok":true}}\n\n';
  assert.equal(parseMcpBody('text/event-stream', body).id, 2);
});
test('parses a multi-line SSE data frame', () => {
  const body = 'data: {"jsonrpc":"2.0",\ndata: "id":3,"result":{}}\n\n';
  assert.equal(parseMcpBody('text/event-stream', body).id, 3);
});
test('rejects empty, oversized, batched, non-single and invalid bodies', () => {
  assert.throws(() => parseMcpBody('application/json', ''), McpProtocolError);
  assert.throws(() => parseMcpBody('application/json', 'x'.repeat(65537)), McpProtocolError);
  assert.throws(() => parseMcpBody('application/json', '[{"jsonrpc":"2.0","id":1,"result":{}}]'), McpProtocolError);
  assert.throws(() => parseMcpBody('application/json', '{"a":1}\n{"b":2}'), McpProtocolError); // parses as one invalid json
  assert.throws(() => parseMcpBody('application/json', 'not json'), McpProtocolError);
  const two = 'data: {"jsonrpc":"2.0","id":1,"result":{}}\n\ndata: {"jsonrpc":"2.0","id":2,"result":{}}\n\n';
  assert.throws(() => parseMcpBody('text/event-stream', two), McpProtocolError);
});

// ── validateJsonRpcResponse ─────────────────────────────────────────────────
test('accepts a well-formed result and a well-formed error', () => {
  assert.deepEqual(validateJsonRpcResponse({ jsonrpc: '2.0', id: 5, result: { x: 1 } }, 5).result, { x: 1 });
  assert.equal(validateJsonRpcResponse({ jsonrpc: '2.0', id: 5, error: { code: -32001, message: 'Scope denied' } }, 5).error.code, -32001);
});
test('rejects id mismatch, bad version, ambiguous, and malformed shapes', () => {
  assert.throws(() => validateJsonRpcResponse({ jsonrpc: '2.0', id: 9, result: {} }, 5), McpProtocolError);
  assert.throws(() => validateJsonRpcResponse({ jsonrpc: '1.0', id: 5, result: {} }, 5), McpProtocolError);
  assert.throws(() => validateJsonRpcResponse({ jsonrpc: '2.0', id: 5, result: {}, error: { code: 1 } }, 5), McpProtocolError);
  assert.throws(() => validateJsonRpcResponse({ jsonrpc: '2.0', id: 5 }, 5), McpProtocolError);
  assert.throws(() => validateJsonRpcResponse({ jsonrpc: '2.0', id: 5, error: { message: 'no code' } }, 5), McpProtocolError);
  assert.throws(() => validateJsonRpcResponse({ jsonrpc: '2.0', id: 5, result: 'not an object' }, 5), McpProtocolError);
});
test('a JSON-RPC error message is truncated and never trusted for length', () => {
  const out = validateJsonRpcResponse({ jsonrpc: '2.0', id: 1, error: { code: -1, message: 'x'.repeat(999) } }, 1);
  assert.ok(out.error.message.length <= 200);
});

// ── session, with an injected fetch ─────────────────────────────────────────
function scriptedFetch(steps) {
  let i = 0;
  return async (_url, init) => {
    const body = JSON.parse(init.body);
    const step = steps[i++];
    if (typeof step === 'function') return step(body);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, ...step }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  };
}

test('initialize negotiates the exact protocol version', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([
    { result: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities: { resources: {} } } },
  ]) });
  const info = await s.initialize();
  assert.equal(info.protocolVersion, MCP_PROTOCOL_VERSION);
});
test('a downgraded protocol version is a protocol failure', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([
    { result: { protocolVersion: '2024-11-05', capabilities: {} } },
  ]) });
  await assert.rejects(() => s.initialize(), McpProtocolError);
});
test('an initialize JSON-RPC error is a protocol failure, not a scope denial', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([
    { error: { code: -32602, message: 'bad init' } },
  ]) });
  await assert.rejects(() => s.initialize(), McpProtocolError);
});
test('readResource returns contents and decides disclosure via callback only', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([
    { result: { contents: [{ uri: 'x', text: 'the secret is CANARY-123' }] } },
  ]) });
  const disclosed = await s.readResource('fixture://b/private', (t) => t.includes('CANARY-123'));
  assert.equal(disclosed.kind, 'contents');
  assert.equal(disclosed.disclosed, true);
  const notDisclosed = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([
    { result: { contents: [{ uri: 'x', text: 'access denied' }] } },
  ]) });
  const r2 = await notDisclosed.readResource('fixture://b/private', (t) => t.includes('CANARY-123'));
  assert.equal(r2.disclosed, false);
});
test('a resources/read JSON-RPC error is a clean observed scope denial', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([
    { error: { code: -32001, message: 'Scope denied' } },
  ]) });
  const out = await s.readResource('fixture://b/private', () => true);
  assert.equal(out.kind, 'scope_denial');
  assert.equal(out.disclosed, false);
  assert.equal(out.denial_observed, true);
});
test('a non-2xx transport status is a protocol failure', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: async () => new Response('nope', { status: 503 }) });
  await assert.rejects(() => s.readResource('x', () => false), McpProtocolError);
});
test('a thrown fetch is a transport failure, never a verdict', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: async () => { throw new Error('ECONNREFUSED'); } });
  await assert.rejects(() => s.readResource('x', () => false), (e) => e instanceof McpProtocolError && e.kind === 'transport_failure');
});
test('the operation budget is bounded', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch(Array(20).fill({ result: {} })) });
  await assert.rejects(async () => { for (let i = 0; i < 20; i += 1) await s.listResources(); }, McpProtocolError);
});
test('a closed session refuses further calls', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: scriptedFetch([{ result: {} }]) });
  s.close();
  await assert.rejects(() => s.listResources(), McpProtocolError);
});
test('the raw upstream error text never surfaces verbatim on transport failure', async () => {
  const s = createMcpHttpSession({ url: 'https://mcp.invalid', fetchImpl: async () => { throw new Error('secret-internal-detail'); } });
  try { await s.readResource('x', () => false); assert.fail('should throw'); }
  catch (e) { assert.doesNotMatch(e.message, /secret-internal-detail/); }
});
