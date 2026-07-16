import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const worker = await readFile(new URL('./worker.js', import.meta.url), 'utf8');
const dispatch = worker.slice(worker.indexOf('DURABLE SCAN DISPATCH'), worker.indexOf('RED TEAM EXECUTE'));
assert.match(dispatch, /body\.grant_id/);
assert.match(dispatch, /consume_attack_authorization_grant/);
assert.match(dispatch, /p_user_id: auth\.user\.id/);
assert.match(dispatch, /p_organization_id: target\.organization_id/);
assert.match(dispatch, /p_target_id: target\.id/);
assert.match(dispatch, /authorization_grant_invalid/);
assert.doesNotMatch(dispatch, /authorization_confirmed/);
assert.match(worker, /verified_authorization_grant_required/);
assert.match(worker, /SCAN_JOBS\.send\(buildScanJobMessage\(jobId\)\)/);
console.log('worker authorization boundary: PASS');
