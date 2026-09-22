// DefendML's own evaluator/generation model must come from configuration
// (env.CLAUDE_MODEL), never a compiled-in model identifier. Guards against the
// hardcoded-judge-model defect found in the 2026-09-21 architecture audit.
// Target-facing request bodies (the CUSTOMER's model, e.g. "gpt-4") are separate
// and legitimately defaulted from target.model_name — not covered here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const worker = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const toml = fs.readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');

test('DefendML judge/generation calls read the model from env.CLAUDE_MODEL', () => {
  // Every anthropic.com request body model should be env-driven.
  const modelLines = worker.split('\n').filter((l) => /model:\s*env\.CLAUDE_MODEL/.test(l));
  assert.ok(modelLines.length >= 2, `expected >=2 env-driven model calls, found ${modelLines.length}`);
});

test('no compiled-in DefendML model identifier remains', () => {
  assert.equal(/claude-haiku-4-5-20251001/.test(worker), false, 'pinned haiku literal must be gone');
  assert.equal(/claude-3-5-sonnet-20241022/.test(worker), false, 'stale sonnet literal must be absent');
});

test('config carries the canonical CLAUDE_MODEL var; the stale ANTHROPIC_MODEL is gone', () => {
  assert.match(toml, /CLAUDE_MODEL\s*=\s*"claude-haiku-4-5"/, 'wrangler.toml must define CLAUDE_MODEL');
  assert.equal(/ANTHROPIC_MODEL/.test(toml), false, 'stale ANTHROPIC_MODEL var must be removed');
});

test('target-facing model (customer request body) stays target-driven', () => {
  // The body sent TO the target uses the customer model with a gpt-4 fallback.
  assert.match(worker, /model:\s*target\.model_name\s*\|\|\s*"gpt-4"/);
});
