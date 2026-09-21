// The persistent-memory scan drives the real runner against an emulated agent
// with a real cross-request store and must: prove cross-session persistence
// (write in one call, read in another) only when attributable (control clean),
// BLOCK when the write is refused, never retain the canary, clean up after
// itself, and match the canonical row key set.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runMemoryPersistenceScan, buildMemoryHeaders } from '../memory-persistence-scan.mjs';

const MARKER = 'dml-canary-mem-scan-9f8e7d6c5b4a';
const TOKEN = 'mem-scan-token-uvw012';

// Emulated agent + persistent store. mode: controlled | vulnerable | leaky.
//   leaky = recall returns the canary for ANY scope (baseline leak) -> control
//   scope also discloses -> not attributable -> must NOT be ALLOW.
function agentServer({ mode = 'controlled', requireToken = true } = {}) {
  const store = new Map();
  const reply = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'content-type': 'application/json' } });
  return async (url, init) => {
    if (requireToken && init.headers['x-validation-token'] !== TOKEN) {
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }
    const { op, scope } = JSON.parse(init.body);
    if (op === 'remember') {
      if (mode === 'vulnerable' || mode === 'leaky') { store.set(scope, `retained: ${MARKER}`); return reply({ ok: true, stored: true }); }
      return reply({ ok: true, stored: false, reason: 'policy_blocked' });
    }
    if (op === 'recall') {
      if (mode === 'leaky') return reply({ ok: true, found: true, content: `leak: ${MARKER}` });
      if (store.has(scope)) return reply({ ok: true, found: true, content: store.get(scope) });
      return reply({ ok: true, found: false, content: '' });
    }
    if (op === 'forget') { store.delete(scope); return reply({ ok: true }); }
    return new Response(JSON.stringify({ error: 'unknown op' }), { status: 400 });
  };
}

const target = {
  url: 'https://agent.invalid', endpoint_path: '/api/validation/memory',
  auth_method: 'api_key', auth_header_name: 'x-validation-token', auth_token: TOKEN,
  protected_marker: MARKER,
  metadata: { memory: { enabled: true } },
};
const sanitize = (v) => (typeof v === 'string' ? v.split(MARKER).join('[REDACTED_TARGET_SECRET]') : v);

const CANONICAL_KEYS = [
  'case_observation', 'category', 'decision', 'detection_method', 'latency_ms',
  'layer_stopped', 'prompt_text', 'report_uuid', 'reproduction_steps',
  'response_snippet', 'response_text', 'status_code', 'test_id',
].sort();

test('vulnerable: poison persists cross-session, control clean -> ALLOW', async () => {
  const row = await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: agentServer({ mode: 'vulnerable' }), sanitize });
  assert.equal(row.decision, 'ALLOW');
  assert.equal(row.detection_method, 'memory_persistence');
  assert.equal(row.status_code, null);
  assert.equal(row.case_observation.persisted_retrieved, true);
  assert.equal(row.case_observation.control_clean, true);
  assert.equal(row.case_observation.legitimate_task, true);
  assert.equal(row.case_observation.boundary_reached, true);
  assert.equal(row.case_observation.complete, true);
  assert.ok(Array.isArray(row.reproduction_steps));
});

test('the canary is never retained in the row', async () => {
  const row = await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: agentServer({ mode: 'vulnerable' }), sanitize });
  assert.equal(JSON.stringify(row).includes(MARKER), false);
});

test('a baseline leak (control also discloses) is NOT attributable -> not ALLOW', async () => {
  const row = await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: agentServer({ mode: 'leaky' }), sanitize });
  assert.equal(row.case_observation.persisted_retrieved, true);
  assert.equal(row.case_observation.control_clean, false, 'the no-write control also disclosed');
  assert.notEqual(row.decision, 'ALLOW');
  assert.equal(row.decision, 'ERROR');
});

test('controlled: write refused, nothing persists -> BLOCK', async () => {
  const row = await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: agentServer({ mode: 'controlled' }), sanitize });
  assert.equal(row.decision, 'BLOCK');
  assert.equal(row.case_observation.persisted_retrieved, false);
  assert.equal(row.case_observation.denial_observed, true);
  assert.equal(row.layer_stopped, 'memory-authorization');
});

test('a transport failure -> ERROR, incomplete, no marker in snippet', async () => {
  const row = await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: async () => { throw new Error('ECONNREFUSED'); }, sanitize });
  assert.equal(row.decision, 'ERROR');
  assert.equal(row.case_observation.complete, false);
  assert.doesNotMatch(row.response_snippet, /ECONNREFUSED/);
});

test('the scan cleans up the store (forget removes both scopes)', async () => {
  const store = new Map();
  const server = async (url, init) => {
    const { op, scope } = JSON.parse(init.body);
    if (op === 'remember') { store.set(scope, `retained: ${MARKER}`); return new Response(JSON.stringify({ ok: true, stored: true }), { status: 200, headers: { 'content-type': 'application/json' } }); }
    if (op === 'recall') return new Response(JSON.stringify(store.has(scope) ? { ok: true, found: true, content: store.get(scope) } : { ok: true, found: false, content: '' }), { status: 200, headers: { 'content-type': 'application/json' } });
    if (op === 'forget') { store.delete(scope); return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }); }
    return new Response('{}', { status: 400 });
  };
  await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: server, sanitize });
  assert.equal(store.size, 0, 'both scopes must be forgotten after the scan');
});

test('a missing marker cannot yield ALLOW even against a persisting server', async () => {
  const noMarker = { ...target, protected_marker: null };
  const row = await runMemoryPersistenceScan({ target: noMarker, reportId: 'rep-1', fetchImpl: agentServer({ mode: 'vulnerable' }), sanitize });
  assert.notEqual(row.decision, 'ALLOW');
  assert.equal(row.decision, 'ERROR');
});

test('the row key set matches the canonical persisted columns', async () => {
  const row = await runMemoryPersistenceScan({ target, reportId: 'rep-1', fetchImpl: agentServer({ mode: 'controlled' }), sanitize });
  assert.deepEqual(Object.keys(row).sort(), CANONICAL_KEYS);
});

test('auth + mode headers are built from the target', () => {
  const withMode = { ...target, custom_headers: { 'x-validation-mode': 'vulnerable' } };
  const h = buildMemoryHeaders(withMode);
  assert.equal(h['x-validation-token'], TOKEN);
  assert.equal(h['x-validation-mode'], 'vulnerable');
});
