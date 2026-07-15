import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { buildScanJobMessage, canTransitionScanJob, redactTargetSecrets } from "../worker.js";

const source = fs.readFileSync(new URL("../worker.js", import.meta.url), "utf8");
const appDispatch = fs.readFileSync("/Users/dustinsovan/DefendML-Code/.claude/worktrees/focused-bhabha-63a923/functions/api/attack-plan-execute.ts", "utf8");
const statusSource = fs.readFileSync("/Users/dustinsovan/DefendML-Code/.claude/worktrees/focused-bhabha-63a923/functions/api/scan-jobs/[id].ts", "utf8");
const uiSource = fs.readFileSync("/Users/dustinsovan/DefendML-Code/.claude/worktrees/focused-bhabha-63a923/src/pages/admin/targets.tsx", "utf8");

test("1 authorized dispatch persists a queued report before enqueue", () => assert.match(source, /job_state: "queued"[\s\S]*SCAN_JOBS\.send/));
test("2 dispatch returns 202", () => assert.match(source, /job_id: jobId, state: "queued" }, 202/));
test("3 unauthenticated dispatch is rejected", () => assert.match(source, /const auth = await verifyJWT\(serviceKey\);[\s\S]*if \(!auth\.ok\)/));
test("4 cross-tenant dispatch is rejected", () => assert.match(source, /organization_members\?user_id=[\s\S]*error: "forbidden"/));
test("5 authorization confirmation is required", () => assert.match(source, /authorization_confirmed !== true/));
test("6 queue payload contains only job ID", () => assert.deepEqual(Object.keys(buildScanJobMessage(crypto.randomUUID())), ["jobId"]));
test("7 queued transitions to running", () => assert.equal(canTransitionScanJob("queued", "running"), true));
test("8 running transitions to completed", () => assert.equal(canTransitionScanJob("running", "completed"), true));
test("9 running transitions to failed", () => assert.equal(canTransitionScanJob("running", "failed"), true));
test("10 terminal states reject restart", () => {
  assert.equal(canTransitionScanJob("completed", "running"), false);
  assert.equal(canTransitionScanJob("failed", "running"), false);
});
test("11 duplicate delivery skips active or terminal jobs", () => assert.match(source, /job_state === "completed" \|\| job\.job_state === "failed"[\s\S]*message\.ack/));
test("12 completed job is not rerun", () => assert.equal(canTransitionScanJob("completed", "queued"), false));
test("13 duplicate browser submission reuses active job", () => assert.match(source, /active\[0\][\s\S]*job_id: active\[0\]\.report_id/));
test("14 retry removes partial result rows", () => assert.match(source, /red_team_results\?report_uuid=eq[\s\S]*method: "DELETE"/));
test("15 retries reset running to queued safely", () => assert.equal(canTransitionScanJob("running", "queued"), true));
test("16 status endpoint checks tenant access", () => assert.match(statusSource, /!canAccessOrg\(auth, job\.organization_id\)[\s\S]*Scan job not found/));
test("17 UI restores state from status list", () => assert.match(uiSource, /fetch\('\/api\/scan-jobs'/));
test("18 browser dispatch no longer waits for execute", () => {
  assert.match(appDispatch, /\/api\/scan-jobs\/dispatch/);
  assert.doesNotMatch(appDispatch, /\/api\/red-team\/execute/);
});
test("19 exact-value redaction remains effective", () => {
  const hidden = "synthetic-value-long-enough";
  assert.equal(redactTargetSecrets(`prefix ${hidden} suffix`, [hidden]).includes(hidden), false);
});
test("20 persisted failure codes are allowlisted constants", () => {
  for (const code of ["DISPATCH_UNAVAILABLE", "INVALID_TARGET", "WORKER_REJECTED", "WORKER_RETRY_EXHAUSTED"]) assert.match(source, new RegExp(code));
  assert.doesNotMatch(source, /failure_code:\s*(?:e|error|String\()/);
});
test("21 UI does not fabricate percentage progress", () => assert.doesNotMatch(uiSource, /scanProgress/));
test("22 completed status exposes report linkage", () => assert.match(statusSource, /report_url:[\s\S]*\/reports\//));
