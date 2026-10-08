import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runToolActionCallbackScan } from '../action-callback-scan.mjs';
import { CanaryJournal, carriesProof, ingestCanary, makeJournalStore } from '../canary-journal.mjs';
import worker from '../worker.js';

function fakeJournal(initial = new Map()) {
  const values = initial;
  let failNextPut = false;
  let chain = Promise.resolve();
  const storage = {
    async get(k) { return values.get(k); },
    async put(k, v) { if (failNextPut) { failNextPut = false; throw new Error('synthetic storage failure'); } values.set(k, structuredClone(v)); },
    async deleteAll() { values.clear(); },
    async setAlarm() {},
    async deleteAlarm() {},
    failNext() { failNextPut = true; },
    values,
  };
  const ctx = { storage, blockConcurrencyWhile(fn) { const result = chain.then(fn); chain = result.catch(() => {}); return result; } };
  return { journal: new CanaryJournal(ctx), storage, ctx };
}

test('R007-2: production journal store aborts a stalled response-body read', async () => {
  let signal;
  const namespace = {
    idFromName: value => value,
    get: () => ({ fetch: async request => {
      signal = request.signal;
      if (new URL(request.url).pathname === '/arm') return Response.json({ ok: true, epoch: 'epoch-1' });
      return { ok: true, json: () => new Promise(() => {}) };
    } }),
  };
  const store = makeJournalStore(namespace, 20);
  assert.equal(await store.arm('dml-cb-' + 'a'.repeat(32), 'synthetic', 'SYNTHETIC-PROOF'), true);
  const result = await Promise.race([store.poll('dml-cb-' + 'a'.repeat(32)), new Promise(r => setTimeout(() => r('hung'), 150))]);
  assert.notEqual(result, 'hung');
  assert.equal(result.storeOk, false);
  assert.equal(signal.aborted, true);
});

test('R007-2: stalled journal read remains bounded and the scan still disarms every nonce', async () => {
  const nonces = ['a', 'b', 'c'].map(suffix => 'dml-cb-' + suffix.repeat(32));
  const nonceQueue = [...nonces];
  const disarmed = [];
  let stalledSignal;
  const namespace = {
    idFromName: value => value,
    get: nonce => ({ fetch: async request => {
      const op = new URL(request.url).pathname;
      if (op === '/arm') return Response.json({ ok: true, epoch: nonce });
      if (op === '/disarm') { disarmed.push(nonce); return Response.json({ ok: true }); }
      if (op === '/poll' && nonce === nonces[1]) {
        stalledSignal = request.signal;
        return { ok: true, json: () => new Promise(() => {}) };
      }
      return Response.json({ storeOk: true, proofObserved: op === '/poll' && nonce === nonces[2],
        received: op === '/poll' && nonce === nonces[2], events: [], collectionComplete: op === '/seal' });
    } }),
  };
  const store = makeJournalStore(namespace, 20);
  const row = await Promise.race([
    runToolActionCallbackScan({
      target: { url: 'https://isolated.invalid', protected_marker: 'SYNTHETIC-CANARY', metadata: { action: {} } },
      reportId: 'synthetic-report', genNonce: () => nonceQueue.shift(), pollAttempts: 1, sleep: async () => {},
      callbackUrl: 'https://isolated.invalid/callback', probeFetch: async () => ({ status: 200 }),
      fetchImpl: async () => ({ status: 200, text: async () => 'response completed' }), store,
    }),
    new Promise(resolve => setTimeout(() => resolve('hung'), 500)),
  ]);
  assert.notEqual(row, 'hung');
  assert.equal(row.decision, 'ERROR');
  assert.equal(stalledSignal.aborted, true);
  assert.deepEqual(disarmed.sort(), [...nonces].sort());
});

test('R008-1: failed poll followed by successful no-proof seal remains a technical error', async () => {
  const nonces = ['a', 'b', 'c'].map(suffix => 'dml-cb-' + suffix.repeat(32));
  const queue = [...nonces];
  const journals = new Map();
  const armed = [];
  const namespace = {
    idFromName: value => value,
    get: nonce => {
      if (!journals.has(nonce)) journals.set(nonce, fakeJournal().journal);
      const journal = journals.get(nonce);
      return { fetch: async request => {
        const op = new URL(request.url).pathname;
        if (op === '/arm') armed.push(nonce);
        if (op === '/poll' && nonce === nonces[1]) return { ok: true, json: () => new Promise(() => {}) };
        return journal.fetch(request);
      } };
    },
  };
  const store = makeJournalStore(namespace, 15);
  const row = await runToolActionCallbackScan({
    target: { url: 'https://isolated.invalid', protected_marker: 'SYNTHETIC-CANARY', metadata: { action: {} } },
    reportId: 'synthetic-report', genNonce: () => queue.shift(), pollAttempts: 1, sleep: async () => {},
    callbackUrl: 'https://isolated.invalid/callback',
    probeFetch: async (_url, init) => ingestCanary(new Request('https://isolated.invalid/callback', init), namespace),
    fetchImpl: async () => ({ status: 200, text: async () => 'completed' }), store,
  });
  assert.equal(row.decision, 'ERROR');
  assert.equal(row.case_observation.collection_failed, true);
  assert.equal(row.case_observation.complete, false, 'seal cannot erase the failed poll');
  assert.equal(row.case_observation.exploit_complete, false);
  assert.equal(row.case_observation.collection_verified, true, 'the probe succeeds independently of the injected exploit-poll failure');
  assert.deepEqual(armed.sort(), [...nonces].sort(), 'each nonce is armed in its own journal');
});

test('R009-1: a real journal callback remains a finding when the target response fails', async () => {
  const nonces = ['d', 'e', 'f'].map(suffix => 'dml-cb-' + suffix.repeat(32));
  const queue = [...nonces];
  const journals = new Map();
  const namespace = {
    idFromName: value => value,
    get: nonce => {
      if (!journals.has(nonce)) journals.set(nonce, fakeJournal().journal);
      return { fetch: request => journals.get(nonce).fetch(request) };
    },
  };
  let agentRequests = 0;
  const store = makeJournalStore(namespace, 50);
  const row = await runToolActionCallbackScan({
    target: { url: 'https://isolated.invalid', protected_marker: 'SYNTHETIC-CANARY', metadata: { action: {} } },
    reportId: 'synthetic-report', genNonce: () => queue.shift(), pollAttempts: 1, sleep: async () => {},
    callbackUrl: 'https://isolated.invalid/callback',
    probeFetch: async (_url, init) => ingestCanary(new Request('https://isolated.invalid/callback', init), namespace),
    fetchImpl: async () => {
      agentRequests += 1;
      if (agentRequests === 1) return { status: 200, text: async () => 'benign request complete' };
      const callback = await ingestCanary(new Request('https://isolated.invalid/callback', {
        method: 'POST', body: JSON.stringify({ scan_nonce: nonces[1], note: 'SYNTHETIC-CANARY' }),
      }), namespace);
      assert.equal(callback.status, 200);
      return { status: 503, text: async () => 'temporary synthetic failure' };
    },
    store,
  });
  assert.equal(row.decision, 'ALLOW');
  assert.equal(row.case_observation.executed, true);
  assert.equal(row.case_observation.boundary_reached, true, 'the matched callback independently proves the action crossed the boundary');
  assert.equal(row.case_observation.exploit_response_failed, true);
  assert.equal(row.case_observation.complete, false, 'the response failure remains a limitation');
  assert.equal(row.case_observation.exploit_complete, true);
  assert.match(row.response_snippet, /target-response=failed/);
  assert.match(row.response_snippet, /callback-received=true/);
  assert.match(row.response_snippet, /callback-deliveries=1/);
  assert.ok(!JSON.stringify(row).includes('SYNTHETIC-CANARY'));
});

test('R008-1: seal failure cannot erase proof already observed by polling', async () => {
  const nonces = ['benign', 'exploit', 'probe'];
  const row = await runToolActionCallbackScan({
    target: { url: 'https://isolated.invalid', protected_marker: 'SYNTHETIC-CANARY', metadata: { action: {} } },
    reportId: 'synthetic-report', genNonce: () => nonces.shift(), pollAttempts: 1, sleep: async () => {},
    callbackUrl: 'https://isolated.invalid/callback', probeFetch: async () => ({ status: 200 }),
    fetchImpl: async () => ({ status: 200, text: async () => 'completed' }),
    store: {
      arm: async () => true,
      poll: async nonce => ({ storeOk: true, proofObserved: nonce === 'exploit' || nonce === 'probe', received: nonce === 'exploit' || nonce === 'probe', count: 1, events: [] }),
      seal: async nonce => nonce === 'exploit'
        ? { storeOk: false }
        : { storeOk: true, proofObserved: nonce === 'probe', received: nonce === 'probe', count: 1, events: [], collectionComplete: true },
      disarm: async () => {},
    },
  });
  assert.equal(row.decision, 'ALLOW');
  assert.equal(row.case_observation.executed, true);
  assert.equal(row.case_observation.exploit_complete, true);
  assert.equal(row.case_observation.collection_failed, true);
  assert.equal(row.case_observation.complete, false, 'the seal failure remains a limitation');
  assert.ok(!JSON.stringify(row).includes('SYNTHETIC-CANARY'));
});

test('R007-1: independently recorded exploit survives failed benign collection', async () => {
  const nonces = ['benign', 'exploit', 'probe'];
  let cleaned = false;
  const row = await runToolActionCallbackScan({
    target: { url: 'https://isolated.invalid', protected_marker: 'SYNTHETIC-CANARY', metadata: { action: {} } },
    reportId: 'synthetic-report', genNonce: () => nonces.shift(), pollAttempts: 1,
    sleep: async () => {}, callbackUrl: 'https://isolated.invalid/callback',
    probeFetch: async () => ({ status: 200 }),
    fetchImpl: async () => ({ status: 200, text: async () => 'request complete' }),
    store: {
      arm: async () => true,
      poll: async n => ({ storeOk: n !== 'benign', proofObserved: n !== 'benign', events: [] }),
      disarm: async () => { cleaned = true; },
    },
  });
  assert.equal(row.decision, 'ALLOW');
  assert.equal(row.case_observation.complete, false);
  assert.equal(row.case_observation.exploit_complete, true);
  assert.equal(row.case_observation.control_complete, false);
  assert.equal(row.case_observation.legitimate_task, false);
  assert.match(row.reproduction_steps[0], /not established/);
  assert.equal(cleaned, true);
  assert.ok(!JSON.stringify(row).includes('SYNTHETIC-CANARY'));
});

test('callback summary reports received delivery without claiming proof or prevention', async () => {
  const nonces = ['benign', 'exploit', 'probe'];
  const row = await runToolActionCallbackScan({
    target: { url: 'https://isolated.invalid', protected_marker: 'SYNTHETIC-CANARY', metadata: { action: {} } },
    reportId: 'synthetic-report', genNonce: () => nonces.shift(), pollAttempts: 1,
    sleep: async () => {}, callbackUrl: 'https://isolated.invalid/callback',
    probeFetch: async () => ({ status: 200 }),
    fetchImpl: async () => ({ status: 200, text: async () => 'I completed that' }),
    store: {
      arm: async () => true,
      poll: async n => n === 'probe'
        ? { storeOk: true, proofObserved: true, received: true, count: 1, events: [], collectionComplete: true }
        : { storeOk: true, proofObserved: false, received: true, count: 3, events: [], collectionComplete: true },
      seal: async n => n === 'probe'
        ? { storeOk: true, proofObserved: true, received: true, count: 1, events: [], collectionComplete: true }
        : { storeOk: true, proofObserved: false, received: true, count: 3, events: [], collectionComplete: true },
      disarm: async () => {},
    },
  });
  assert.equal(row.decision, 'ERROR');
  assert.equal(row.case_observation.executed, false);
  assert.equal(row.case_observation.narrated_only, true);
  assert.match(row.response_snippet, /callback-received=true/);
  assert.match(row.response_snippet, /callback-deliveries=3/);
  assert.doesNotMatch(row.response_snippet, /decision=BLOCK/i);
});

test('R005-1: journal finds canaries in numeric primitives and object keys beyond bounded diagnostics', async () => {
  for (const body of [
    { scan_nonce: 'dml-cb-' + 'a'.repeat(32), padding: 'x'.repeat(9000), zz: 87654321 },
    { scan_nonce: 'dml-cb-' + 'a'.repeat(32), padding: 'x'.repeat(9000), 'CANARY-KEY-12345': true },
  ]) {
    const { journal } = fakeJournal();
    const nonce = body.scan_nonce;
    const armed = await journal.fetch(new Request('https://journal.internal/arm', { method: 'POST', body: JSON.stringify({ expected: body.zz ? '87654321' : 'CANARY-KEY-12345' }) }));
    assert.equal(armed.status, 200);
    const result = await ingestCanary(new Request('https://worker.invalid/api/canary/ingest', { method: 'POST', body: JSON.stringify(body) }), { idFromName: () => nonce, get: () => ({ fetch: req => journal.fetch(req) }) });
    assert.equal(result.status, 200);
    const poll = await journal.fetch(new Request('https://journal.internal/poll', { method: 'POST', body: JSON.stringify({}) }));
    const state = await poll.json();
    assert.equal(state.proofObserved, true);
    assert.equal(JSON.stringify(state).includes('CANARY-KEY-12345'), false);
  }
});

test('R005-1: diagnostic saturation cannot discard a later proof', async () => {
  const { journal } = fakeJournal();
  const nonce = 'dml-cb-' + 'b'.repeat(32);
  const armed = await (await journal.fetch(new Request('https://journal.internal/arm', { method: 'POST', body: JSON.stringify({ expected: 'SYNTHETIC-PROOF-123' }) }))).json();
  for (let i = 0; i < 8; i++) await journal.fetch(new Request('https://journal.internal/ingest', { method: 'POST', body: JSON.stringify({ raw: JSON.stringify({ scan_nonce: nonce, note: `junk-${i}` }) }) }));
  await journal.fetch(new Request('https://journal.internal/ingest', { method: 'POST', body: JSON.stringify({ raw: JSON.stringify({ scan_nonce: nonce, note: 'SYNTHETIC-PROOF-123' }) }) }));
  const state = await (await journal.fetch(new Request('https://journal.internal/seal', { method: 'POST', body: JSON.stringify({ epoch: armed.epoch }) }))).json();
  assert.equal(state.proofObserved, true);
  assert.equal(state.collectionComplete, true);
});

test('R005-2: journal write failure poisons no-proof completeness even if later reads work', async () => {
  const { journal, storage } = fakeJournal();
  const nonce = 'dml-cb-' + 'c'.repeat(32);
  const armed = await (await journal.fetch(new Request('https://journal.internal/arm', { method: 'POST', body: JSON.stringify({ expected: 'SYNTHETIC-PROOF-123' }) }))).json();
  assert.equal(armed.ok, true);
  storage.failNext();
  const failed = await journal.fetch(new Request('https://journal.internal/ingest', { method: 'POST', body: JSON.stringify({ raw: JSON.stringify({ scan_nonce: nonce, note: 'SYNTHETIC-PROOF-123' }) }) }));
  assert.equal(failed.status, 503);
  const after = await (await journal.fetch(new Request('https://journal.internal/seal', { method: 'POST', body: JSON.stringify({ epoch: armed.epoch }) }))).json();
  assert.equal(after.storeOk, false);
  assert.equal(after.proofObserved, false);
  assert.equal(after.collectionComplete, false);
});

test('journal restart keeps proven ALLOW evidence but invalidates no-proof completeness', async () => {
  for (const proof of [false, true]) {
    const { journal, storage } = fakeJournal();
    const nonce = 'dml-cb-' + (proof ? 'd' : 'e').repeat(32);
    await journal.fetch(new Request('https://journal.internal/arm', { method: 'POST', body: JSON.stringify({ expected: 'SYNTHETIC-PROOF-123' }) }));
    if (proof) await journal.fetch(new Request('https://journal.internal/ingest', { method: 'POST', body: JSON.stringify({ raw: JSON.stringify({ note: 'SYNTHETIC-PROOF-123' }) }) }));
    const restarted = new CanaryJournal({ storage, blockConcurrencyWhile: fn => fn() });
    const state = await (await restarted.fetch(new Request('https://journal.internal/seal', { method: 'POST', body: JSON.stringify({}) }))).json();
    assert.equal(state.proofObserved, proof);
    assert.equal(state.storeOk, proof);
    assert.equal(state.collectionComplete, false);
  }
});

test('public journal ingress bounds body size and hides nonce existence', async () => {
  let calls = 0;
  const namespace = { idFromName: n => n, get: () => ({ fetch: async () => { calls++; return new Response(JSON.stringify({ ok: true }), { status: 200 }); } }) };
  const oversize = await ingestCanary(new Request('https://worker.invalid', { method: 'POST', body: 'x'.repeat(32769) }), namespace);
  assert.equal(oversize.status, 400);
  assert.equal(calls, 0);
  const unknown = await ingestCanary(new Request('https://worker.invalid', { method: 'POST', body: JSON.stringify({ scan_nonce: 'dml-cb-' + 'f'.repeat(32), note: 'junk' }) }), namespace);
  assert.equal(unknown.status, 200);
  assert.deepEqual(await unknown.json(), { ok: true });
});

test('R008-2: oversized-body cancellation cannot stall public ingress', async () => {
  let cancelCalled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(32769)); },
    cancel() { cancelCalled = true; return new Promise(() => {}); },
  });
  const request = new Request('https://worker.invalid/callback', { method: 'POST', body, duplex: 'half' });
  const response = await Promise.race([
    ingestCanary(request, null, 20),
    new Promise(resolve => setTimeout(() => resolve('hung'), 200)),
  ]);
  assert.notEqual(response, 'hung');
  assert.equal(response.status, 400);
  assert.equal(cancelCalled, true);
});

test('R008-2: timed-out Durable Object ingress dispatch receives an aborted signal', async () => {
  let dispatchSignal;
  const namespace = {
    idFromName: value => value,
    get: () => ({ fetch: async request => { dispatchSignal = request.signal; return new Promise(() => {}); } }),
  };
  const request = new Request('https://worker.invalid/callback', { method: 'POST', body: JSON.stringify({
    scan_nonce: 'dml-cb-' + 'f'.repeat(32), note: 'synthetic',
  }) });
  const response = await ingestCanary(request, namespace, 20);
  assert.equal(response.status, 503);
  assert.equal(dispatchSignal.aborted, true);
});

test('public journal ingress is rate-limited before Durable Object dispatch', async () => {
  let dispatches = 0;
  let rateLimitWrites = 0;
  const kv = (initial = null) => ({
    value: initial,
    async get() { return this.value; },
    async put(_key, value) { this.value = value; rateLimitWrites += 1; },
  });
  const audit = { async get() { return '[]'; }, async put() {} };
  const journal = { idFromName: value => value, get: () => ({ fetch: async () => {
    dispatches += 1;
    return Response.json({ ok: true });
  } }) };
  const ctx = { waitUntil(promise) { this.pending = promise; } };
  const request = () => new Request('https://worker.invalid/api/canary/ingest', {
    method: 'POST', headers: { 'cf-connecting-ip': '198.51.100.10', origin: 'https://app.defendml.com' },
    body: JSON.stringify({ scan_nonce: 'dml-cb-' + 'a'.repeat(32), note: 'synthetic' }),
  });

  const accepted = await worker.fetch(request(), { RATE_LIMIT: kv(), AUDIT_LOG: audit, CANARY_JOURNAL: journal }, ctx);
  await ctx.pending;
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers.get('access-control-allow-origin'), 'https://app.defendml.com');
  assert.equal(dispatches, 1);
  assert.equal(rateLimitWrites, 1);

  const denied = await worker.fetch(request(), {
    RATE_LIMIT: kv(JSON.stringify({ tokens: 0, ts: Date.now() })),
    AUDIT_LOG: audit, CANARY_JOURNAL: journal,
  }, { waitUntil(promise) { this.pending = promise; } });
  assert.equal(denied.status, 429);
  assert.equal(dispatches, 1, 'rate-limited requests never create/dispatch a journal request');
});
