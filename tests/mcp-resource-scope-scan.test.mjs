// The MCP resource-scope scan drives the real client against an emulated MCP
// server and must produce the right decision + observation, never retain the
// canary, and match the canonical result-row key set. Uses the real
// mcp-http-client (imported) and runMcpResourceScopeScan (imported).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { runMcpResourceScopeScan, buildMcpHeaders } from '../mcp-resource-scope-scan.mjs';

const MARKER = 'dml-canary-mcp-scan-6f2a9c1b3d4e';
const TOKEN = 'mcp-scan-token-abc123';

// A minimal MCP server over fetch. `mode` = controlled (deny) | vulnerable (disclose).
// Requires the token header, mirroring the real fixture.
function mcpServer({ mode = 'controlled', requireToken = true } = {}) {
  return async (url, init) => {
    if (requireToken && init.headers['x-validation-token'] !== TOKEN) {
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }
    const msg = JSON.parse(init.body);
    if (msg.id === undefined || msg.id === null) return new Response(null, { status: 202 });
    const reply = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }), { status: 200, headers: { 'content-type': 'application/json' } });
    const fail = (code, message) => new Response(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code, message } }), { status: 200, headers: { 'content-type': 'application/json' } });
    if (msg.method === 'initialize') return reply({ protocolVersion: '2025-11-25', capabilities: { resources: {} } });
    if (msg.method === 'resources/list') return reply({ resources: [{ uri: 'fixture://public' }] });
    if (msg.method === 'resources/read') {
      const uri = msg.params?.uri;
      if (uri === 'fixture://public') return reply({ contents: [{ uri, text: 'Public content.' }] });
      if (uri === 'fixture://private') {
        if (mode === 'vulnerable') return reply({ contents: [{ uri, text: `Restricted: ${MARKER}` }] });
        return fail(-32001, 'Scope denied');
      }
      return fail(-32602, 'Unknown resource');
    }
    return fail(-32601, 'Method not found');
  };
}

const target = {
  url: 'https://mcp.invalid', endpoint_path: '/api/validation/mcp',
  auth_method: 'api_key', auth_header_name: 'x-validation-token', auth_token: TOKEN,
  protected_marker: MARKER,
};
// Redaction that mirrors the Worker: strips the marker from any retained text.
const sanitize = (v) => (typeof v === 'string' ? v.split(MARKER).join('[REDACTED_TARGET_SECRET]') : v);

const CANONICAL_KEYS = [
  'case_observation', 'category', 'decision', 'detection_method', 'latency_ms',
  'layer_stopped', 'prompt_text', 'report_uuid', 'reproduction_steps',
  'response_snippet', 'response_text', 'status_code', 'test_id',
].sort();

test('vulnerable server: out-of-scope disclosure -> ALLOW, observation records it', async () => {
  const row = await runMcpResourceScopeScan({ target, reportId: 'r1', fetchImpl: mcpServer({ mode: 'vulnerable' }), sanitize });
  assert.equal(row.decision, 'ALLOW');
  assert.equal(row.detection_method, 'mcp_resource_scope');
  assert.equal(row.status_code, null);
  assert.equal(row.case_observation.disclosed, true);
  assert.equal(row.case_observation.boundary_reached, true);
  assert.equal(row.case_observation.legitimate_task, true);
  assert.equal(row.case_observation.complete, true);
});

test('the canary is never retained in the row', async () => {
  const row = await runMcpResourceScopeScan({ target, reportId: 'r1', fetchImpl: mcpServer({ mode: 'vulnerable' }), sanitize });
  assert.equal(JSON.stringify(row).includes(MARKER), false, 'no field may contain the canary');
});

test('controlled server: scope denial -> BLOCK, layer named', async () => {
  const row = await runMcpResourceScopeScan({ target, reportId: 'r1', fetchImpl: mcpServer({ mode: 'controlled' }), sanitize });
  assert.equal(row.decision, 'BLOCK');
  assert.equal(row.case_observation.denial_observed, true);
  assert.equal(row.case_observation.disclosed, false);
  assert.equal(row.layer_stopped, 'resource-authorization');
});

test('a protocol/transport failure -> ERROR, incomplete observation, no verdict', async () => {
  const row = await runMcpResourceScopeScan({ target, reportId: 'r1', fetchImpl: async () => { throw new Error('ECONNREFUSED'); }, sanitize });
  assert.equal(row.decision, 'ERROR');
  assert.equal(row.case_observation.complete, false);
  assert.doesNotMatch(row.response_snippet, /ECONNREFUSED/);
});

test('a version-mismatched server -> ERROR, never a verdict', async () => {
  const downgrade = async (url, init) => {
    const msg = JSON.parse(init.body);
    if (msg.method === 'initialize') return new Response(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2024-11-05' } }), { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const row = await runMcpResourceScopeScan({ target, reportId: 'r1', fetchImpl: downgrade, sanitize });
  assert.equal(row.decision, 'ERROR');
  assert.equal(row.case_observation.complete, false);
});

test('a missing marker cannot yield ALLOW even against a disclosing server', async () => {
  const noMarker = { ...target, protected_marker: null };
  const row = await runMcpResourceScopeScan({ target: noMarker, reportId: 'r1', fetchImpl: mcpServer({ mode: 'vulnerable' }), sanitize });
  assert.notEqual(row.decision, 'ALLOW', 'without a canary there is no deterministic disclosure signal');
});

test('the row key set matches the canonical persisted columns', async () => {
  const row = await runMcpResourceScopeScan({ target, reportId: 'r1', fetchImpl: mcpServer({ mode: 'controlled' }), sanitize });
  assert.deepEqual(Object.keys(row).sort(), CANONICAL_KEYS);
});

test('auth header is built from the target (api_key -> raw value)', () => {
  const h = buildMcpHeaders(target);
  assert.equal(h['x-validation-token'], TOKEN);
});
