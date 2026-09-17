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
const selectors = between('const CATEGORY_MAP = {', '// Fetch all tests from DB (or fallback)');
const scout = between('// ── AGENT 1: Scout', '// ── AGENT 2: Probe');

function seeded(seed) {
  return () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const state = { rand: seeded(1), sent: [] };
const ctx = vm.createContext({
  Math: Object.assign(Object.create(Math), { random: () => state.rand() }),
  allTests: [], THREAT_INTEL_PATTERNS: [], swarmIntel: { scoutResults: {} },
  executeBatch: async (prompts) => {
    state.sent = prompts;
    return prompts.map((p) => ({ category: p.category, prompt_text: p.prompt_text, decision: 'BLOCK' }));
  },
  console: { log() {} },
});
vm.runInContext(`${selectors}\n${scout}\nglobalThis.runScoutAgent = runScoutAgent; globalThis.CANONICAL = CANONICAL_CATEGORIES;`, ctx);
const CANONICAL = Array.from(ctx.CANONICAL);

async function scoutRun(pool, seed, threatIntel = []) {
  state.rand = seeded(seed);
  ctx.allTests = pool;
  ctx.THREAT_INTEL_PATTERNS = threatIntel;
  ctx.swarmIntel = { scoutResults: {} };
  await ctx.runScoutAgent();
  return { sent: Array.from(state.sent), scoutResults: ctx.swarmIntel.scoutResults };
}
const rows = (category, texts, copies = 1) => Array.from({ length: texts * copies }, (_, i) => ({
  id: `${category}-${i}`, category, prompt_text: `synthetic ${category} ${Math.floor(i / copies)}`,
}));

// Synthetic rows shaped like the 2026-09-17 read-only precheck (per-category row/distinct-text counts only).
const LIVE_SHAPE = {
  'Constitutional Violations': [40, 1], 'Deployment Standard': [35, 1], 'Security Standard': [30, 1], 'Backdoor Attack': [12, 1],
  'Data Theft': [6, 1], 'PII Data Extraction': [35, 1], 'Jailbreak': [7, 1], 'Prompt Injection': [23, 1], 'Model Manipulation': [25, 1],
  'Agentic AI Attack': [7, 1], 'ASI01 Agent Goal Hijack': [15, 1], 'ASI02 Tool Misuse': [15, 1], 'Multi Turn Sequences': [20, 1],
  'MCP Attack': [10, 2], 'ASI03 Memory Poisoning': [10, 2], 'ASI04 Resource Overload': [10, 2], 'ASI05 Trust Boundary Violations': [10, 2],
  'ASI06 Data Exfiltration via Agents': [10, 2], 'ASI08 Repudiation': [10, 1], 'ASI09 Uncontrolled Agent Spawning': [10, 1],
  'ASI10 Insecure Agent Communication': [10, 1],
};
const livePool = [
  ...Object.entries(LIVE_SHAPE).flatMap(([category, [texts, copies]]) => rows(category, texts, copies)),
  ...rows('ASI07 Cascading Hallucination', 8, 2), ...rows('ASI07 Cascading Hallucination', 2).map((r) => ({ ...r, id: `${r.id}-single`, prompt_text: `${r.prompt_text} single` })),
  ...rows('bias_fairness', 30), ...rows('misinformation', 15), ...rows('adversarial_robustness', 15),
];
const populated = CANONICAL.filter((c) => livePool.some((r) => r.category === c));
const SEEDS = 2000;
const liveRuns = [];
for (let seed = 1; seed <= SEEDS; seed++) liveRuns.push(await scoutRun(livePool, seed));

test('fixture matches the precheck shape: 22 populated categories, Custom Objective empty', () => {
  assert.equal(populated.length, 22);
  assert.equal(populated.includes('Custom Objective'), false);
});

test('every populated category is reachable with near-uniform Scout frequency', () => {
  for (const category of populated) {
    const share = liveRuns.filter((run) => run.sent.some((p) => p.category === category)).length / SEEDS;
    assert.ok(share >= 0.40 && share <= 0.50, `${category} share ${share}`);
  }
});

test('each scan sends 20 distinct prompts, 2 from each of 10 categories', () => {
  for (const { sent } of liveRuns) {
    assert.equal(sent.length, 20);
    assert.equal(new Set(sent.map((p) => p.prompt_text)).size, 20);
    const perCategory = Object.values(sent.reduce((m, p) => (m[p.category] = (m[p.category] || 0) + 1, m), {}));
    assert.deepEqual(perCategory, Array(10).fill(2));
  }
});

test('Scout results are still recorded per canonical category', () => {
  const { scoutResults } = liveRuns[0];
  assert.equal(Object.keys(scoutResults).length, 10);
  for (const s of Object.values(scoutResults)) assert.deepEqual({ ...s }, { allowed: 0, flagged: 0, blocked: 2, total: 2 });
});

test('duplicate-text categories never repeat a prompt within Scout', async () => {
  const pool = ['MCP Attack', 'ASI03 Memory Poisoning', 'ASI04 Resource Overload', 'ASI05 Trust Boundary Violations', 'ASI06 Data Exfiltration via Agents']
    .flatMap((category) => rows(category, 10, 2));
  for (let seed = 1; seed <= 300; seed++) {
    const { sent } = await scoutRun(pool, seed);
    assert.equal(sent.length, 20);
    assert.equal(new Set(sent.map((p) => p.prompt_text)).size, 20);
  }
});

test('sparse inventories send only available distinct rows, without fabrication', async () => {
  const cases = [
    { pool: populated.map((category) => rows(category, 1)[0]), expected: 20 },
    { pool: [...rows('Jailbreak', 3, 2), ...rows('Prompt Injection', 3), ...rows('Data Theft', 3), ...rows('misinformation', 5, 3)], expected: 14 },
    { pool: rows('Jailbreak', 5, 3), expected: 5 },
    { pool: rows('bias_fairness', 4), expected: 4 },
    { pool: [], expected: 0 },
  ];
  for (const { pool, expected } of cases) {
    for (let seed = 1; seed <= 50; seed++) {
      const { sent } = await scoutRun(pool, seed);
      assert.equal(sent.length, expected);
      assert.equal(new Set(sent.map((p) => p.prompt_text)).size, expected);
      assert.ok(sent.every((p) => pool.includes(p)), 'every sent prompt comes from the inventory');
    }
  }
});

test('threat-intel patterns stay additive after the 20-prompt Scout budget', async () => {
  const intel = [{ id: 'threat-intel-a', category: 'Prompt Injection', prompt_text: 'synthetic intel a' }, { id: 'threat-intel-b', category: 'Jailbreak', prompt_text: 'synthetic intel b' }];
  const { sent } = await scoutRun(livePool, 7, intel);
  assert.equal(sent.length, 22);
  assert.deepEqual(sent.slice(20).map((p) => p.id), ['threat-intel-a', 'threat-intel-b']);
});
