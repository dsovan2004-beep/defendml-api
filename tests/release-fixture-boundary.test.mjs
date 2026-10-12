import test from 'node:test';
import assert from 'node:assert/strict';
import { releaseValidationTargets, scanReleaseHeld } from '../scan-release-hold.mjs';
import worker from '../worker.js';
const a = crypto.randomUUID(), b = crypto.randomUUID(), foreign = crypto.randomUUID();
test('held release permits only operator-selected fixture IDs', () => {
  const env = { SCAN_RELEASE_HOLD: 'true', SCAN_RELEASE_QA_TARGETS: `${a},${b}` };
  assert.equal(scanReleaseHeld(env, a), false);
  assert.equal(scanReleaseHeld(env, b), false);
  assert.equal(scanReleaseHeld(env, foreign), true);
  assert.equal(scanReleaseHeld(env, undefined), true);
});
test('missing, malformed and oversized fixture configuration stays fully held', () => {
  for (const value of [undefined, '', 'bad', `${a},bad`, `${a},${b},${foreign}`, [a]]) {
    const env = { SCAN_RELEASE_HOLD: 'true', SCAN_RELEASE_QA_TARGETS: value };
    assert.equal(releaseValidationTargets(env).size, 0);
    assert.equal(scanReleaseHeld(env, a), true);
  }
});
test('explicitly selected fixture still requires user authentication', async () => {
  const r = await worker.fetch(new Request('https://worker.invalid/api/scan-jobs/dispatch', {
    method: 'POST', body: JSON.stringify({ targetId: a, grant_id: crypto.randomUUID() }),
  }), { SCAN_RELEASE_HOLD: 'true', SCAN_RELEASE_QA_TARGETS: a,
    SUPABASE_URL: 'https://synthetic.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service', SCAN_JOBS: {},
  }, { waitUntil() {} });
  assert.equal(r.status, 401);
});
test('foreign direct execution is held without credential or Target access', async () => {
  const env = { SCAN_RELEASE_HOLD: 'true', SCAN_RELEASE_QA_TARGETS: a,
    SUPABASE_URL: 'https://synthetic.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service' };
  const r = await worker.fetch(new Request('https://worker.invalid/api/red-team/execute', {
    method: 'POST', body: JSON.stringify({ targetId: foreign }),
  }), env, { waitUntil() {} });
  assert.equal(r.status, 503);
  assert.equal((await r.json()).error, 'scan_release_maintenance');
});
test('held non-fixture queued job is never claimed, modified or acknowledged', async t => {
  let retries = 0, reads = 0;
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(init.method, undefined);
    assert.match(String(url), /red_team_reports\?/);
    reads++;
    return Response.json([{ job_state: 'queued', target_id: foreign }]);
  });
  await worker.queue({ messages: [{ body: { jobId: crypto.randomUUID() }, attempts: 999,
    retry() { retries++; }, ack() { throw new Error('Pending job acknowledged'); },
  }] }, { SCAN_RELEASE_HOLD: 'true', SCAN_RELEASE_QA_TARGETS: a, SUPABASE_URL: 'https://synthetic.invalid',
    SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service', SCAN_JOB_INTERNAL_TOKEN: 'synthetic-internal' }, {});
  assert.equal(reads, 1);
  assert.equal(retries, 1);
});
for (const failure of ['throw', 'http-error', 'invalid-json', 'missing-job', 'missing-target']) {
  test(`held unresolved ${failure} job is retried without mutation even at exhausted attempts`, async t => {
    let retries = 0;
    t.mock.method(globalThis, 'fetch', async (url, init) => {
      assert.equal(init.method, undefined, 'No job writes before fixture validation');
      if (failure === 'throw') throw new Error('Synthetic lookup failure');
      if (failure === 'http-error') return Response.json([{ target_id: a }], { status: 503 });
      if (failure === 'invalid-json') return new Response('{');
      if (failure === 'missing-job') return Response.json([]);
      return Response.json([{ job_state: 'queued' }]);
    });
    await worker.queue({ messages: [{ body: { jobId: crypto.randomUUID() }, attempts: 999,
      retry() { retries++; }, ack() { throw new Error('Unresolved pending job acknowledged'); },
    }] }, { SCAN_RELEASE_HOLD: 'true', SCAN_RELEASE_QA_TARGETS: a, SUPABASE_URL: 'https://synthetic.invalid',
      SUPABASE_SERVICE_ROLE_KEY: 'synthetic-service', SCAN_JOB_INTERNAL_TOKEN: 'synthetic-internal' }, {});
    assert.equal(retries, 1);
  });
}
