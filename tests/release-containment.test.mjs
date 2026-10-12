import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.js';

for (const path of ['/api/scan-jobs/dispatch', '/api/red-team/execute']) {
  test(`release hold rejects ${path} without service credentials or side effects`, async () => {
    const response = await worker.fetch(new Request('https://worker.invalid' + path, {
      method: 'POST', body: JSON.stringify({ targetId: crypto.randomUUID(), grant_id: crypto.randomUUID() }),
    }), { SCAN_RELEASE_HOLD: 'true' }, { waitUntil() { throw new Error('Unexpected side effect'); } });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'scan_release_maintenance');
    assert.equal(response.headers.get('retry-after'), '60');
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });
}
test('release hold retries deliveries without acknowledging, reading or modifying jobs', async () => {
  let retried = 0;
  await worker.queue({ messages: [{ body: { jobId: crypto.randomUUID() },
    retry(options) { assert.equal(options.delaySeconds, 60); retried++; },
    ack() { throw new Error('Must not acknowledge pending work'); },
  }] }, { SCAN_RELEASE_HOLD: 'true' }, {});
  assert.equal(retried, 1);
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
