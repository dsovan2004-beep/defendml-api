// Phase 0 evidence integrity. Missing observation is never BLOCK, transport
// failure is never a working security control, and a conversation-context turn
// is never a security outcome. Logic is extracted from the real worker.js so a
// source change cannot silently pass these tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');

function between(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `slice markers present: ${start}`);
  return source.slice(from, to);
}

// ── Extract the real per-turn decision logic ────────────────────────────────
const turnLogic = between('let turnDecision;', 'const turnStatusCode =');
const decideTurn = vm.runInNewContext(
  `(isFinalTurn, statusCode, responseText, finalDecision, finalMethod) => {
     ${turnLogic}
     return { turnDecision, turnMethod };
   }`,
  {},
);

// ── Extract the real report tally ───────────────────────────────────────────
const tallyLogic = between('let blocked = 0, allowed = 0, flagged = 0, errors = 0, contextTurns = 0;', '// ── Build attack_intelligence');
const tally = vm.runInNewContext(
  `(persistedResults) => {
     ${tallyLogic}
     return { blocked, allowed, flagged, errors, contextTurns, decidedOutcomes, blockRate };
   }`,
  {},
);

const row = (decision, extra = {}) => ({ decision, detection_method: 'llm_judge', status_code: 200, response_snippet: 'x', ...extra });

// ── Intermediate turns ──────────────────────────────────────────────────────

test('thrown transport on an intermediate turn is ERROR, never BLOCK', () => {
  // The worker sets statusCode 0 when fetch throws (timeout, DNS, refused).
  const r = decideTurn(false, 0, 'synthetic transport failure text', 'ALLOW', 'llm_judge');
  assert.equal(r.turnDecision, 'ERROR');
  assert.notEqual(r.turnDecision, 'BLOCK');
  assert.equal(r.turnMethod, null);
});

test('HTTP error on an intermediate turn is ERROR, never BLOCK', () => {
  for (const status of [400, 401, 403, 404, 429, 500, 502, 503]) {
    const r = decideTurn(false, status, 'error body', 'ALLOW', 'llm_judge');
    assert.equal(r.turnDecision, 'ERROR', `status ${status}`);
    assert.equal(r.turnMethod, 'http_error');
  }
});

test('empty observation on an intermediate turn is ERROR, never BLOCK or CONTEXT', () => {
  for (const body of ['', '   ', '\n\t ', null, undefined]) {
    const r = decideTurn(false, 200, body, 'ALLOW', 'llm_judge');
    assert.equal(r.turnDecision, 'ERROR');
    assert.equal(r.turnMethod, 'empty_response');
  }
});

test('a completed intermediate turn is CONTEXT, never BLOCK', () => {
  const r = decideTurn(false, 200, 'Sure, I can help with that.', 'ALLOW', 'llm_judge');
  assert.equal(r.turnDecision, 'CONTEXT');
  assert.equal(r.turnMethod, 'multi_turn_context');
  assert.notEqual(r.turnDecision, 'BLOCK');
});

test('an intermediate turn never inherits the final turn verdict', () => {
  for (const verdict of ['BLOCK', 'ALLOW', 'FLAG', 'ERROR']) {
    const r = decideTurn(false, 200, 'context reply', verdict, 'llm_judge');
    assert.equal(r.turnDecision, 'CONTEXT', `final verdict ${verdict} must not leak into an intermediate turn`);
  }
});

// ── Final turn keeps its real verdict ───────────────────────────────────────

test('the final turn carries the classifier verdict unchanged', () => {
  for (const [verdict, method] of [['BLOCK', 'keyword'], ['ALLOW', 'llm_judge'], ['ERROR', 'http_error']]) {
    const r = decideTurn(true, 200, 'final reply', verdict, method);
    assert.equal(r.turnDecision, verdict);
    assert.equal(r.turnMethod, method);
  }
});

test('the final turn verdict is not overridden by its own status or body', () => {
  // classifyResponse already gated these; the turn writer must not re-decide.
  const r = decideTurn(true, 0, '', 'BLOCK', 'keyword');
  assert.equal(r.turnDecision, 'BLOCK');
});

// ── Aggregate metrics ───────────────────────────────────────────────────────

test('context turns cannot inflate blocked_count or block_rate', () => {
  // One real blocked attack plus twenty context turns, the shape a multi-turn
  // scan produces. Before Phase 0 this reported 21 blocks at ~100%.
  const rows = [row('BLOCK', { detection_method: 'keyword' })];
  for (let i = 0; i < 20; i += 1) rows.push(row('CONTEXT', { detection_method: 'multi_turn_context' }));
  const t = tally(rows);
  assert.equal(t.blocked, 1);
  assert.equal(t.contextTurns, 20);
  assert.equal(t.errors, 0, 'a context turn is not an execution error either');
  assert.equal(t.decidedOutcomes, 1);
  assert.equal(t.blockRate, 100);
});

test('context turns cannot dilute block_rate', () => {
  const rows = [row('BLOCK'), row('ALLOW')];
  for (let i = 0; i < 18; i += 1) rows.push(row('CONTEXT', { detection_method: 'multi_turn_context' }));
  const t = tally(rows);
  assert.equal(t.blockRate, 50, 'one block and one allow is 50%, regardless of context volume');
});

test('execution errors are excluded from the block-rate denominator', () => {
  const t = tally([row('BLOCK'), row('ERROR'), row('ERROR')]);
  assert.equal(t.blocked, 1);
  assert.equal(t.errors, 2);
  assert.equal(t.decidedOutcomes, 1);
  assert.equal(t.blockRate, 100, 'a transport failure is not a security outcome');
});

test('qualified BLOCK and legitimate ALLOW still count', () => {
  const t = tally([row('BLOCK'), row('BLOCK'), row('ALLOW'), row('FLAG')]);
  assert.equal(t.blocked, 2);
  assert.equal(t.allowed, 1);
  assert.equal(t.flagged, 1);
  assert.equal(t.decidedOutcomes, 4);
  assert.equal(t.blockRate, 50);
});

test('a scan of nothing but context and errors reports no block rate', () => {
  const t = tally([row('CONTEXT'), row('ERROR')]);
  assert.equal(t.blockRate, 0);
  assert.equal(t.decidedOutcomes, 0);
});

test('an unrecognized decision falls into errors, never blocked', () => {
  const t = tally([row('WEIRD'), row('BLOCK')]);
  assert.equal(t.blocked, 1);
  assert.equal(t.errors, 1);
});

// ── Persisted row shape ─────────────────────────────────────────────────────

test('a non-final turn never asserts a stopped layer', () => {
  const layerLogic = between('layer_stopped: isFinalTurn && turnDecision === "BLOCK"', 'latency_ms: 0,');
  const layerOf = vm.runInNewContext(`(isFinalTurn, turnDecision, turnStatusCode) => ({ ${layerLogic} }).layer_stopped`, {});
  assert.equal(layerOf(false, 'CONTEXT', 200), null);
  assert.equal(layerOf(false, 'ERROR', 0), null);
  assert.equal(layerOf(false, 'BLOCK', 200), null, 'even a BLOCK-shaped intermediate row cannot name a layer');
  assert.equal(layerOf(true, 'BLOCK', 200), 'application');
  assert.equal(layerOf(true, 'ALLOW', 200), null);
});

test('the category breakdown skips context turns', () => {
  assert.match(
    between('const categoryBreakdown = {};', '// Top attack vectors'),
    /if \(r\.decision === "CONTEXT"\) continue;/,
    'context turns must not enter category totals',
  );
});

// ── FLAG contract ───────────────────────────────────────────────────────────
// Investigated in Phase 0: a FLAG-producing semantic was intended (judge
// hesitation, see the hesitation_rate comment) but is disconnected — the judge's
// indecision routes to ERROR/evaluation_inconclusive instead. That routing is
// conservative and never manufactures a security success, so it is documented
// here rather than changed. These pins make any future reconnection deliberate.

test('judge indecision is an evaluation error, never a verdict', () => {
  const judge = between('const judgment = (claudeJson.content', 'catch (err)');
  assert.match(judge, /judgment === "BLOCK"/);
  assert.match(judge, /judgment === "ALLOW"/);
  assert.match(judge, /decision: "ERROR", method: "evaluation_inconclusive"/);
  // An ambiguous judge reply must not fall through to a security verdict.
  assert.doesNotMatch(judge, /decision: "FLAG"/);
});

test('no code path manufactures a FLAG decision', () => {
  // flagged_count reading 0 is therefore truthful, not a broken metric.
  const assignments = source.match(/decision: *"FLAG"|decision *= *"FLAG"/g) || [];
  assert.deepEqual(assignments, [], 'FLAG must not be produced to make a metric non-zero');
});

test('transport and runtime failure remain excluded from BLOCK in the classifier', () => {
  const classifier = between('async function classifyResponse(', 'const lower =');
  assert.match(classifier, /statusCode < 200 \|\| statusCode >= 300/);
  assert.match(classifier, /decision: "ERROR", method: "http_error"/);
  assert.match(classifier, /decision: "ERROR", method: "empty_response"/);
});
