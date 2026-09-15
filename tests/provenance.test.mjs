import test from 'node:test';
import assert from 'node:assert/strict';
import { receipt, buildOptions } from '../scripts/provenance.mjs';

const manifest = { artifact: { sha256: 'a'.repeat(64) }, runtime: { compatibilityDate: '2025-01-01', compatibilityFlags: [] } };
const observation = { versionId: '11111111-1111-1111-1111-111111111111', deploymentId: '22222222-2222-2222-2222-222222222222', deployedAt: '2026-07-22T08:06:36.788Z', operator: 'release-operator', kind: 'existing-deployment-adoption', artifactSHA256: 'a'.repeat(64), compatibilityDate: '2025-01-01', compatibilityFlags: [], trafficPercent: 100 };
test('provenance preserves verified metadata and exact build options', () => {
  assert.deepEqual(receipt(manifest, observation, 200).deployment, observation);
  assert.equal(buildOptions.target, 'es2022');
  assert.equal(buildOptions.keepNames, true);
});
test('provenance rejects mismatched artifact, runtime, traffic and failed health', () => {
  for (const change of [{ artifactSHA256: 'b'.repeat(64) }, { compatibilityDate: '2026-01-01' }, { compatibilityFlags: ['nodejs_compat'] }, { trafficPercent: 50 }]) {
    assert.throws(() => receipt(manifest, { ...observation, ...change }, 200));
  }
  assert.throws(() => receipt(manifest, observation, 503));
});
test('provenance rejects unknown fields and malformed identifiers or dates', () => {
  for (const change of [{ bindings: {} }, { versionId: '../invalid' }, { deployedAt: 'invalid' }, { deployedAt: '2999-01-01T00:00:00Z' }, { operator: 'https://invalid/' }, { kind: 'unknown' }]) {
    assert.throws(() => receipt(manifest, { ...observation, ...change }, 200));
  }
});
test('configuration-only revisions require a recorded unchanged predecessor artifact', () => {
  const next = { ...observation, versionId: '33333333-3333-3333-3333-333333333333', kind: 'configuration-only', previousVersionId: observation.versionId };
  assert.throws(() => receipt(manifest, next, 200));
  const previous = receipt(manifest, observation, 200);
  assert.equal(receipt(manifest, next, 200, previous).deployment.kind, 'configuration-only');
  assert.throws(() => receipt(manifest, next, 200, { ...previous, build: { artifact: { sha256: 'b'.repeat(64) } } }));
});
