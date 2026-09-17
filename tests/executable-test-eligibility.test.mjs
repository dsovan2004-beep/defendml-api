import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { isExecutableTest } from '../executable-test-eligibility.mjs';

const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
function between(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `slice markers present: ${start}`);
  return source.slice(from, to);
}

// Exact Fix #212 redaction markers held by the 22 active placeholder rows (IDs 579–600). Metadata, not payloads.
const CBRN_MARKER = '[REDACTED — CBRN test, see worker.js BUILTIN_TESTS]';
const CYBER_MARKER = '[REDACTED — Cyber exploit, see worker.js BUILTIN_TESTS]';
const placeholders = [
  ...Array.from({ length: 11 }, (_, i) => ({ id: 579 + i, test_id: `placeholder-cbrn-${i + 1}`, category: 'cbrn_wmd', prompt_text: CBRN_MARKER })),
  ...Array.from({ length: 11 }, (_, i) => ({ id: 590 + i, test_id: `placeholder-cyber-${i + 1}`, category: 'cybersecurity_exploits', prompt_text: CYBER_MARKER })),
];
const synthetic = (id, category = 'Prompt Injection') => ({ id, test_id: `synthetic-${id}`, category, prompt_text: `synthetic probe ${id}` });
const isPlaceholder = (t) => t.prompt_text === CBRN_MARKER || t.prompt_text === CYBER_MARKER;
function seeded(seed) {
  return () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('metadata markers, blank and non-string prompts are not executable', () => {
  for (const prompt_text of [CBRN_MARKER, CYBER_MARKER, `  ${CYBER_MARKER}\n`, '[REDACTED_TARGET_SECRET]', '', '   ', null, undefined, 42]) {
    assert.equal(isExecutableTest({ prompt_text }), false, String(prompt_text));
  }
  assert.equal(isExecutableTest(null), false);
  assert.equal(isExecutableTest({}), false);
});

test('real prompt text stays executable and rows are not rewritten', () => {
  const rows = [synthetic(1), { ...synthetic(2), prompt_text: `synthetic probe quoting ${CBRN_MARKER} mid-text` }];
  const before = JSON.stringify(rows);
  assert.deepEqual(rows.filter(isExecutableTest), rows);
  assert.equal(JSON.stringify(rows), before);
});

test('built-in fallback inventory remains fully executable', () => {
  const literal = between('const BUILTIN_TESTS = [', '// ── FIX #109: 5-Agent Swarm Pipeline')
    .replace('const BUILTIN_TESTS = ', '').trim().replace(/;$/, '');
  const builtin = vm.runInNewContext(`(${literal})`);
  assert.ok(builtin.length > 0);
  assert.equal(builtin.filter(isExecutableTest).length, builtin.length);
});

const ingestion = between('const testsRes = await fetch(', '// Fetch SwarmMemory for this target');
async function ingest(raw) {
  const pool = await vm.runInNewContext(`(async () => { ${ingestion}; return allTests; })()`, {
    fetch: async () => ({ text: async () => raw }), SB_URL: 'https://synthetic.invalid', sbHeaders: {},
    BUILTIN_TESTS: [synthetic('builtin')], isExecutableTest, console: { log() {} },
  });
  return Array.from(pool, (t) => t.id);
}

test('primary inventory load excludes placeholders and preserves valid rows', async () => {
  const rows = [...placeholders, synthetic(1), { ...synthetic(2), prompt_text: '  ' }, { ...synthetic(3), prompt_text: null }, synthetic(4, 'Jailbreak')];
  assert.deepEqual(await ingest(JSON.stringify(rows)), [1, 4]);
});

test('unmapped or missing category labels do not make valid prompts ineligible', async () => {
  const rows = ['bias_fairness', 'misinformation', 'adversarial_robustness', null, undefined].map((category, i) => ({ ...synthetic(10 + i), category }));
  assert.deepEqual(await ingest(JSON.stringify([...rows, placeholders[0]])), [10, 11, 12, 13, 14]);
  const { sent } = await runBatch(rows);
  assert.equal(sent.length, rows.length);
});

test('placeholder-only inventory reduces execution instead of substituting fallback payloads', async () => {
  assert.deepEqual(await ingest(JSON.stringify(placeholders)), []);
});

test('degraded primary fetch keeps the existing built-in fallback', async () => {
  for (const raw of ['', 'not json', '{}', '[]']) assert.deepEqual(await ingest(raw), ['builtin'], raw);
});

test('every selection path reads the filtered pool', () => {
  const filterAt = source.indexOf('allTests = allTests.filter(isExecutableTest);');
  const ingestStart = source.indexOf('const testsRes = await fetch(');
  assert.ok(filterAt > source.indexOf('allTests = BUILTIN_TESTS;'));
  for (const m of source.matchAll(/\ballTests\b/g)) {
    if (m.index < filterAt) assert.ok(m.index > ingestStart, 'allTests used before ingestion');
  }
  assert.doesNotMatch(source.slice(filterAt + 1), /\ballTests\s*=(?!=)/);
});

const selectors = between('const CATEGORY_MAP = {', '// Fetch all tests from DB (or fallback)');
function loadSelectors(seed) {
  return vm.runInNewContext(`${selectors}; ({ CANONICAL_CATEGORIES, selectSpread, selectByCategories, shuffle })`, {
    Math: Object.assign(Object.create(Math), { random: seeded(seed) }),
  });
}
// Mirrors the agents' spread + filler expressions (e.g. Probe): shuffle(allTests).filter(t => !used.has(t.prompt_text)).
function spreadThenFiller(s, pool, target) {
  let prompts = s.selectSpread(pool, s.CANONICAL_CATEGORIES, 2);
  const used = new Set(prompts.map((p) => p.prompt_text));
  const filler = s.shuffle(pool).filter((t) => !used.has(t.prompt_text));
  return [...prompts, ...filler.slice(0, target - prompts.length)];
}

test('deficient category spread reached placeholders through filler before filtering', () => {
  const pool = [...placeholders, synthetic(1), synthetic(2), synthetic(3, 'Jailbreak'), synthetic(4, 'Jailbreak')];
  assert.ok(spreadThenFiller(loadSelectors(1), pool, 20).some(isPlaceholder));
});

test('category, filler and repeated-agent selection never return placeholders after filtering', () => {
  const pool = [...placeholders, synthetic(1), synthetic(2), synthetic(3, 'Jailbreak'), synthetic(4, 'Jailbreak')].filter(isExecutableTest);
  for (let seed = 1; seed <= 200; seed++) {
    const s = loadSelectors(seed);
    const picks = [...spreadThenFiller(s, pool, 20), ...s.selectByCategories(pool, s.CANONICAL_CATEGORIES, 50)];
    assert.equal(picks.some(isPlaceholder), false);
    assert.equal(spreadThenFiller(s, pool, 20).length, 4); // actual reduced count, nothing fabricated
  }
});

const supplement = between('let MCP_ATTACKS = [];', '// FIX #322 (2026-05-20): Phase 12 per-scan reference');
async function loadSupplement(fetch) {
  const out = await vm.runInNewContext(`(async () => { ${supplement}; return { mcp: MCP_ATTACKS.map(r => r.id), asi: ASI_EXTENDED_PROMPTS.map(r => r.id) }; })()`, {
    env: {}, fetch, isExecutableTest, console: { log() {}, warn() {} },
  });
  return { mcp: Array.from(out.mcp), asi: Array.from(out.asi) };
}

test('supplemental MCP and ASI rows exclude non-executable prompts', async () => {
  const rows = [
    { test_id: 'mcp-01', category: 'MCP Attack', prompt_text: 'synthetic mcp probe' },
    { test_id: 'mcp-marker', category: 'MCP Attack', prompt_text: CBRN_MARKER },
    { test_id: 'asi03-01', category: 'ASI03 Memory Poisoning', prompt_text: 'synthetic asi probe' },
    { test_id: 'asi03-blank', category: 'ASI03 Memory Poisoning', prompt_text: ' ' },
    { test_id: 'asi03-null', category: 'ASI03 Memory Poisoning', prompt_text: null },
  ];
  assert.deepEqual(await loadSupplement(async () => ({ ok: true, json: async () => rows })), { mcp: ['mcp-01'], asi: ['asi03-01'] });
});

test('degraded supplemental fetch still leaves empty pools', async () => {
  assert.deepEqual(await loadSupplement(async () => ({ ok: false, status: 503 })), { mcp: [], asi: [] });
  assert.deepEqual(await loadSupplement(async () => { throw Error('synthetic'); }), { mcp: [], asi: [] });
});

const executeBatchSource = between('async function executeBatch(prompts', '// ── Fix #256-full (2026-04-27)');
async function runBatch(prompts) {
  const sent = [];
  const executeBatch = vm.runInNewContext(`(${executeBatchSource.trim()})`, {
    BATCH_SIZE: 3, targetUrl: 'https://target.invalid/synthetic', targetHeaders: {}, report: { id: 'synthetic-report' },
    buildRequestBody: (text) => JSON.stringify({ message: text }),
    fetch: async (_url, init) => { sent.push(JSON.parse(init.body).message); return { status: 200, text: async () => 'synthetic refusal' }; },
    AbortSignal: { timeout: () => undefined }, extractResponseText: (t) => t, sanitizeTargetEvidence: (t) => t,
    sanitizeTargetError: (e) => String(e), classifyResponse: async () => ({ decision: 'BLOCK', method: 'keyword' }),
    buildReproSteps: () => [], isExecutableTest,
  });
  const results = await executeBatch(prompts);
  return { sent, testIds: Array.from(results, (r) => r.test_id) };
}

test('HTTP adapter never submits or counts non-executable prompts from any source', async () => {
  const { sent, testIds } = await runBatch([
    placeholders[0], synthetic(1), { id: 'blank', prompt_text: '   ' }, { id: 'null', prompt_text: null },
    { id: 'mem-marker', category: 'Jailbreak', prompt_text: CYBER_MARKER }, synthetic(2), { id: 'padded', prompt_text: `  ${CBRN_MARKER}\n` },
  ]);
  assert.deepEqual(sent, ['synthetic probe 1', 'synthetic probe 2']);
  assert.deepEqual(testIds, ['1', '2']);
});

test('placeholder-only batch sends nothing', async () => {
  assert.deepEqual(await runBatch(placeholders), { sent: [], testIds: [] });
});

// The optional adapter seam must stay inert: a transport without an independent
// observer cannot execute, and the failure must never resolve as prevention.
async function runSeam(prompts, caseObserver, caseTransport) {
  const sent = [];
  const executeBatch = vm.runInNewContext(`(${executeBatchSource.trim()})`, {
    BATCH_SIZE: 3, targetUrl: 'https://target.invalid/synthetic', targetHeaders: {}, report: { id: 'synthetic-report' },
    buildRequestBody: (text) => JSON.stringify({ message: text }),
    fetch: async (_url, init) => { sent.push(JSON.parse(init.body).message); return { status: 200, text: async () => 'synthetic refusal' }; },
    AbortSignal: { timeout: () => undefined }, extractResponseText: (t) => t, sanitizeTargetEvidence: (t) => t,
    sanitizeTargetError: (e) => String(e), classifyResponse: async () => ({ decision: 'BLOCK', method: 'keyword' }),
    buildReproSteps: () => [], isExecutableTest,
  });
  return { sent, results: await executeBatch(prompts, caseObserver, caseTransport) };
}

test('transport without an independent observer fails closed and never reports prevention', async () => {
  const transport = Object.assign(async () => ({ protocol: 'mcp-stdio', execution_status: 'COMPLETE', text: 'disclosed' }), { protocol: 'mcp-stdio' });
  const { sent, results } = await runSeam([synthetic(1)], null, transport);
  assert.deepEqual(sent, []); // no HTTP fallback smuggling the prompt out
  assert.equal(results.length, 1);
  assert.equal(results[0].decision, 'ERROR');
  assert.notEqual(results[0].decision, 'BLOCK');
  assert.equal(results[0].execution_status, 'FAILED');
  assert.equal(results[0].status_code, null);
});

test('unsupported transport protocol cannot execute', async () => {
  const observer = async () => ({ decision: 'ALLOW', evidence: {} });
  const transport = Object.assign(async () => ({ protocol: 'http-smuggled', execution_status: 'COMPLETE', text: 'x' }), { protocol: 'http-smuggled' });
  const { sent, results } = await runSeam([synthetic(1)], observer, transport);
  assert.deepEqual(sent, []);
  assert.equal(results[0].decision, 'ERROR');
  assert.equal(results[0].execution_status, 'FAILED');
});
