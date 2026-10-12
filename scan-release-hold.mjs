// Operator configuration only; never accept release exemptions from a Target's
// metadata, caller claims or organization role. Ordinary authorization still runs.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function releaseValidationTargets(env) {
  if (typeof env.SCAN_RELEASE_QA_TARGETS !== 'string') return new Set();
  const ids = env.SCAN_RELEASE_QA_TARGETS.split(',').map(x => x.trim().toLowerCase());
  // This release permits exactly two disposable tenant Targets, not an open bypass.
  if (!ids.length || ids.length > 2 || ids.some(x => !UUID.test(x))) return new Set();
  return new Set(ids);
}
export function scanReleaseHeld(env, targetId) {
  return env.SCAN_RELEASE_HOLD === 'true' &&
    !releaseValidationTargets(env).has(String(targetId || '').toLowerCase());
}
