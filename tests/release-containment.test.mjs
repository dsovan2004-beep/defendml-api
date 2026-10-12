import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.js';

for (const path of ['/api/scan-jobs/dispatch', '/api/red-team/execute']) {
  test(`release hold rejects ${path} without service credentials or side effects`, async (t) => {
    t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected network call'); });
    const env = { SCAN_RELEASE_HOLD: 'true', get SUPABASE_SERVICE_ROLE_KEY() { throw new Error('Unexpected credential access'); } };
    const response = await worker.fetch(new Request('https://worker.invalid' + path, {
      method: 'POST', headers: { 'x-scan-job-token': 'synthetic-internal-token', origin: 'https://app.defendml.com' },
      body: JSON.stringify({ targetId: crypto.randomUUID(), grant_id: crypto.randomUUID(), jobId: crypto.randomUUID() }),
    }), env, { waitUntil() { throw new Error('Unexpected side effect'); } });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'scan_release_maintenance');
    assert.equal(response.headers.get('retry-after'), '60');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.defendml.com');
  });
}
test('release hold retries deliveries without acknowledging, reading or modifying jobs', async () => {
  let retried = 0;
  const message = () => ({ get body() { throw new Error('Must not read pending job'); }, attempts: 999,
    retry(options) { assert.equal(options.delaySeconds, 60); retried++; },
    ack() { throw new Error('Must not acknowledge pending work'); },
  });
  await worker.queue({ messages: [message(), message()] }, {
    SCAN_RELEASE_HOLD: 'true', get SUPABASE_SERVICE_ROLE_KEY() { throw new Error('Must not access service bindings'); },
  }, {});
  assert.equal(retried, 2);
});
test('release hold leaves health available', async () => {
  const response = await worker.fetch(new Request('https://worker.invalid/'), { SCAN_RELEASE_HOLD: 'true' }, { waitUntil() {} });
  assert.equal(response.status, 200);
});
test('release hold does not replace callback validation with maintenance', async () => {
  const response = await worker.fetch(new Request('https://worker.invalid/api/canary/ingest', { method: 'POST', body: '{}' }),
    { SCAN_RELEASE_HOLD: 'true' }, { waitUntil() {} });
  assert.equal(response.status, 400);
});
test('without release hold normal unauthenticated dispatch still denies access', async () => {
  const response = await worker.fetch(new Request('https://worker.invalid/api/scan-jobs/dispatch', { method: 'POST', body: '{}' }), {
    SUPABASE_URL: 'https://synthetic.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service', SCAN_JOBS: {},
  }, { waitUntil() {} });
  assert.equal(response.status, 401);
});
test('flag activation is exact and variants retain ordinary authorization denial', async () => {
  for (const value of [undefined, false, true, 'TRUE', ' true ', 'false']) {
    const response = await worker.fetch(new Request('https://worker.invalid/api/scan-jobs/dispatch', { method: 'POST', body: '{}' }), {
      SCAN_RELEASE_HOLD: value, SUPABASE_URL: 'https://synthetic.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service', SCAN_JOBS: {},
    }, { waitUntil() {} });
    assert.equal(response.status, 401);
  }
});
test('hold preserves allowed-origin CORS preflight', async () => {
  const response = await worker.fetch(new Request('https://worker.invalid/api/red-team/execute', {
    method: 'OPTIONS', headers: { origin: 'https://app.defendml.com' },
  }), { SCAN_RELEASE_HOLD: 'true' }, {});
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.defendml.com');
});
