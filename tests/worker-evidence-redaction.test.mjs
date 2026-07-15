import test from "node:test";
import assert from "node:assert/strict";
import {
  TARGET_SECRET_REDACTION_MARKER,
  buildTargetSensitiveValues,
  redactTargetSecrets,
  safeTargetUrl,
} from "../worker.js";

const generated = (label) => `${label}-${crypto.randomUUID()}`;
const fixture = () => {
  const token = generated("token");
  const header = generated("header");
  const query = generated("query");
  const fragment = generated("fragment");
  return {
    token,
    header,
    query,
    fragment,
    target: {
      auth_token: token,
      custom_headers: { "x-qa-auth": header },
      url: `https://qa.invalid/reflect?credential=${encodeURIComponent(query)}`,
      endpoint_path: `/scan#credential=${encodeURIComponent(fragment)}`,
    },
  };
};

test("1 direct token reflection", () => {
  const f = fixture();
  assert.equal(redactTargetSecrets(f.token, buildTargetSensitiveValues(f.target)), TARGET_SECRET_REDACTION_MARKER);
});

test("2 embedded token reflection", () => {
  const f = fixture();
  assert.equal(redactTargetSecrets(`before ${f.token} after`, buildTargetSensitiveValues(f.target)), `before ${TARGET_SECRET_REDACTION_MARKER} after`);
});

test("3 custom-header reflection", () => {
  const f = fixture();
  assert.equal(redactTargetSecrets(f.header, buildTargetSensitiveValues(f.target)), TARGET_SECRET_REDACTION_MARKER);
});

test("4 multiple secrets", () => {
  const f = fixture();
  const output = redactTargetSecrets(`${f.token} ${f.header}`, buildTargetSensitiveValues(f.target));
  assert.equal(output, `${TARGET_SECRET_REDACTION_MARKER} ${TARGET_SECRET_REDACTION_MARKER}`);
});

test("5 repeated occurrences", () => {
  const f = fixture();
  assert.equal(redactTargetSecrets(`${f.token}/${f.token}`, buildTargetSensitiveValues(f.target)), `${TARGET_SECRET_REDACTION_MARKER}/${TARGET_SECRET_REDACTION_MARKER}`);
});

test("6 longest-first replacement", () => {
  const short = generated("shared");
  const long = `${short}-longer`;
  const values = buildTargetSensitiveValues({ auth_token: short, custom_headers: { x: long } });
  assert.equal(values[0], long);
  assert.equal(redactTargetSecrets(long, values), TARGET_SECRET_REDACTION_MARKER);
});

test("7 empty values ignored", () => {
  assert.deepEqual(buildTargetSensitiveValues({ auth_token: "", custom_headers: { x: "" } }), []);
});

test("8 short-value safety", () => {
  assert.deepEqual(buildTargetSensitiveValues({ auth_token: "short", custom_headers: { x: "1234567" } }), []);
});

test("9 ordinary evidence unchanged", () => {
  const f = fixture();
  const ordinary = "The target refused the attack request.";
  assert.equal(redactTargetSecrets(ordinary, buildTargetSensitiveValues(f.target)), ordinary);
});

test("10 result insert fixture contains marker only", () => {
  const f = fixture();
  const result = redactTargetSecrets({ response_text: f.token, response_snippet: `echo ${f.header}` }, buildTargetSensitiveValues(f.target));
  const serialized = JSON.stringify(result);
  assert.ok(serialized.includes(TARGET_SECRET_REDACTION_MARKER));
  assert.ok(!serialized.includes(f.token) && !serialized.includes(f.header));
});

test("11 report-derived fixture contains marker only", () => {
  const f = fixture();
  const report = redactTargetSecrets({ intelligence: { evaluator_text: f.query }, playbook: [f.fragment] }, buildTargetSensitiveValues(f.target));
  const serialized = JSON.stringify(report);
  assert.ok(serialized.includes(TARGET_SECRET_REDACTION_MARKER));
  assert.ok(!serialized.includes(f.query) && !serialized.includes(f.fragment));
});

test("12 retry/update fixture remains redacted", () => {
  const f = fixture();
  const retry = redactTargetSecrets({ attempt: 2, diagnostic: `retry ${f.token}` }, buildTargetSensitiveValues(f.target));
  assert.equal(retry.diagnostic, `retry ${TARGET_SECRET_REDACTION_MARKER}`);
});

test("13 error/log fixture contains no synthetic secret", () => {
  const f = fixture();
  const safe = redactTargetSecrets(`request failed for ${f.target.url}: ${f.token}`, buildTargetSensitiveValues(f.target));
  assert.ok(!safe.includes(f.token) && !safe.includes(f.query));
  assert.ok(!safeTargetUrl(f.target.url).includes(f.query));
});

test("14 server-side credential transport source remains configured", () => {
  const f = fixture();
  buildTargetSensitiveValues(f.target);
  assert.equal(f.target.auth_token, f.token);
  assert.equal(f.target.custom_headers["x-qa-auth"], f.header);
});

test("15 verification states remain unchanged", () => {
  const f = fixture();
  const result = redactTargetSecrets({ decision: "ALLOW", detection_method: "llm_judge", response_text: f.token }, buildTargetSensitiveValues(f.target));
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.detection_method, "llm_judge");
});

test("16 execution error and inconclusive remain honest", () => {
  const f = fixture();
  const records = redactTargetSecrets([{ decision: "ERROR", response_snippet: f.token }, { decision: "INCONCLUSIVE", response_snippet: f.header }], buildTargetSensitiveValues(f.target));
  assert.deepEqual(records.map((record) => record.decision), ["ERROR", "INCONCLUSIVE"]);
});

test("17 timeout cannot bypass worker persistence redaction", () => {
  const f = fixture();
  const persistedBeforeProxyResponse = redactTargetSecrets({ response_text: f.token, proxy_status: 502 }, buildTargetSensitiveValues(f.target));
  assert.equal(persistedBeforeProxyResponse.response_text, TARGET_SECRET_REDACTION_MARKER);
  assert.equal(persistedBeforeProxyResponse.proxy_status, 502);
});
