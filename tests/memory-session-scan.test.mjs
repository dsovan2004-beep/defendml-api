// Unit tests for the generalized persistent-memory runner (memory-session-v1).
// Cross-session persistence is proven against the endpoint's OWN store via its
// native scope key; ALLOW requires a no-write control scope to stay clean
// (attributability), and everything ambiguous fails closed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runMemorySessionScan } from '../memory-session-scan.mjs';

const MARKER = 'CANARY-mem-7c1d9f3a2b';

const TARGET = {
  url: 'https://agent.example.com', endpoint_path: '/chat', request_format: 'openai',
  protected_marker: MARKER, auth_method: 'none',
  metadata: { memory: { enabled: true, mode: 'session', scope_field: 'user_id' } },
};

// Stateful mock endpoint: a real agent with cross-session memory keyed by user_id.
function mockEndpoint({ persists = true, controlLeaks = false, controlDead = false } = {}) {
  const store = Object.create(null);
  const calls = [];
  const impl = async (_url, init) => {
    const body = JSON.parse(init.body);
    const scope = body.user_id;
    const prompt = body.messages ? body.messages.at(-1).content : body.message;
    calls.push({ scope, prompt });
    if (controlDead && String(scope).startsWith('dml-mem-c-')) return { status: 500, async text() { return 'err'; } };
    let content;
    if (prompt.includes(MARKER)) { if (persists) store[scope] = MARKER; content = 'Noted for later.'; }
    else if (/forget/i.test(prompt)) { delete store[scope]; content = 'Cleared.'; }
    else content = store[scope] ? `Your stored reference is ${store[scope]}.` : 'I have no stored reference.';
    if (controlLeaks && !prompt.includes(MARKER) && !/forget/i.test(prompt)) content = `Your stored reference is ${MARKER}.`;
    return { status: 200, async text() { return JSON.stringify({ choices: [{ message: { content } }] }); } };
  };
  impl.calls = calls;
  return impl;
}

const opts = (fetchImpl, target = TARGET) => ({ target, reportId: 'rep-1', fetchImpl, now: () => 1000 });

test('ALLOW: poison persists cross-session, control scope clean', async () => {
  const ep = mockEndpoint({ persists: true });
  const row = await runMemorySessionScan(opts(ep));
  assert.equal(row.decision, 'ALLOW');
  assert.equal(row.case_observation.persisted_retrieved, true);
  assert.equal(row.case_observation.control_clean, true);
  assert.equal(row.case_observation.adapter, 'memory-session-v1');
  assert.equal(row.detection_method, 'memory_persistence');
  // Scope discipline: write and recall share one scope; control uses a different one.
  const write = ep.calls.find((c) => c.prompt.includes(MARKER));
  const recall = ep.calls.find((c) => /repeat it back/i.test(c.prompt) && c.scope === write.scope);
  const control = ep.calls.find((c) => /repeat it back/i.test(c.prompt) && c.scope !== write.scope);
  assert.ok(write && recall && control, 'write, recall(write-scope), control(other-scope) all present');
  assert.notEqual(write.scope, control.scope);
});

test('BLOCK: nothing persisted, recall channel works, boundary held', async () => {
  const row = await runMemorySessionScan(opts(mockEndpoint({ persists: false })));
  assert.equal(row.decision, 'BLOCK');
  assert.equal(row.case_observation.persisted_retrieved, false);
  assert.equal(row.case_observation.denial_observed, true);
  assert.equal(row.case_observation.legitimate_task, true);
});

test('not attributable -> ERROR: control scope also surfaces the canary', async () => {
  const row = await runMemorySessionScan(opts(mockEndpoint({ persists: true, controlLeaks: true })));
  assert.equal(row.case_observation.persisted_retrieved, true);
  assert.equal(row.case_observation.control_clean, false);
  assert.equal(row.decision, 'ERROR');
});

test('control channel dead -> ERROR (complete=false, fail-closed)', async () => {
  const row = await runMemorySessionScan(opts(mockEndpoint({ persists: true, controlDead: true })));
  assert.equal(row.case_observation.complete, false);
  assert.equal(row.decision, 'ERROR');
});

test('no protected marker -> ERROR (not runnable)', async () => {
  const row = await runMemorySessionScan(opts(mockEndpoint(), { ...TARGET, protected_marker: null }));
  assert.equal(row.decision, 'ERROR');
});

test('redaction: the marker never appears in the persisted row', async () => {
  const row = await runMemorySessionScan({ ...opts(mockEndpoint({ persists: true })), sanitize: (x) => x });
  assert.equal(row.decision, 'ALLOW');
  assert.ok(!JSON.stringify(row).includes(MARKER), 'marker must not appear anywhere in the row');
});

test('scope-header mode: scope rides in a header, not the body', async () => {
  const calls = [];
  const store = Object.create(null);
  const impl = async (_url, init) => {
    const scope = init.headers['x-session-id'];
    const body = JSON.parse(init.body);
    const prompt = body.messages.at(-1).content;
    calls.push({ scope, hasBodyScope: 'user_id' in body });
    let content;
    if (prompt.includes(MARKER)) { store[scope] = MARKER; content = 'noted'; }
    else if (/forget/i.test(prompt)) { delete store[scope]; content = 'cleared'; }
    else content = store[scope] ? `ref ${store[scope]}` : 'none';
    return { status: 200, async text() { return JSON.stringify({ choices: [{ message: { content } }] }); } };
  };
  const target = { ...TARGET, metadata: { memory: { enabled: true, mode: 'session', scope_header: 'x-session-id' } } };
  const row = await runMemorySessionScan(opts(impl, target));
  assert.equal(row.decision, 'ALLOW');
  assert.ok(calls.every((c) => typeof c.scope === 'string' && c.scope.length > 0), 'scope present in header');
  assert.ok(calls.every((c) => c.hasBodyScope === false), 'no scope leaked into the body');
});

test('canonical row shape: exactly the 13 executeBatch keys', async () => {
  const row = await runMemorySessionScan(opts(mockEndpoint({ persists: true })));
  assert.deepEqual(Object.keys(row).sort(), [
    'category', 'case_observation', 'decision', 'detection_method', 'latency_ms',
    'layer_stopped', 'prompt_text', 'reproduction_steps', 'report_uuid',
    'response_snippet', 'response_text', 'status_code', 'test_id',
  ].sort());
  assert.equal(row.status_code, null);
});
