import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../worker.js';
import { buildTargetSensitiveValues, redactTargetSecrets } from '../worker-helpers.mjs';
import { isQualifiedMemory, qualifiesMemoryOutcome, MEMORY_QUALIFICATION_VERSION } from '../memory-qualification.mjs';

// Exact ordinary-swarm post-execution seam: real final redaction/dedup, bulk
// storage, completion, memory and return. Attack/model/auth admission is upstream.
const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const startMarker = '        const sanitizedResults = sanitizeTargetEvidence(results);';
const endMarker = '        return resp;';
assert.equal(source.split(startMarker).length, 2);
const start = source.indexOf(startMarker), end = source.indexOf(endMarker, start) + endMarker.length;
assert.ok(start > 0 && end > start);
const names = ['fetch','results','SB_URL','sbHeaders','report','targetId','target','scanStart',
  'sanitizeTargetEvidence','sanitizeTargetError','withCORS','json','request','internalJob',
  'ctx','console','logEvent','toCanonical','qualifiesMemoryOutcome','isQualifiedMemory',
  'MEMORY_QUALIFICATION_VERSION','scoutResults','probeResults','exploitResults','exfilResults',
  'persistResults','escalationResults','poisonResults','socialResults','multiTurnResults',
  'customObjectiveResults','swarmIntel','runPhaseD','runFreeOnly','customObjective',
  'pipelineVersion','targetIsAI','targetTypeReason'];
const execute = new (Object.getPrototypeOf(async function(){}).constructor)(...names, source.slice(start,end));
const DB = 'https://storage.synthetic.invalid';
const REPORT = '20000000-0000-4000-8000-000000000001';
const TARGET = '30000000-0000-4000-8000-000000000001';
const JOB = '40000000-0000-4000-8000-000000000001';
const SECRET = 'synthetic-only-credential-marker';
const target = { id: TARGET, total_scans: 4, auth_token: SECRET };
const sensitive = buildTargetSensitiveValues(target);
const sanitize = value => redactTargetSecrets(value, sensitive);
function rows() {
  return ['ALLOW','BLOCK','FLAG','ERROR','CONTEXT'].map((decision,i) => ({
    report_uuid: REPORT, test_id: `case-${i}`, decision, category: 'prompt_injection',
    detection_method: 'keyword', status_code: decision === 'ERROR' ? 500 : 200,
    prompt_text: `synthetic prompt ${SECRET}`, response_snippet: `synthetic response ${SECRET}`,
    case_observation: { observed_effect: decision === 'ALLOW', private_value: SECRET },
  }));
}
function database(mode, queued = false) {
  const requests = [], retained = []; let state = queued ? 'queued' : 'running';
  let bodyReads = 0;
  const fetcher = async (input, init = {}) => {
    const u = new URL(String(input)); assert.equal(u.origin, DB, 'no external network');
    const method = init.method || 'GET', body = init.body ? JSON.parse(init.body) : null;
    requests.push({ path:u.pathname, query:u.search, method, body, headers:init.headers });
    if (u.pathname === '/rest/v1/red_team_results' && method === 'POST') {
      if (mode === 'throw') throw Error(`synthetic failure ${SECRET}`);
      if (mode === 'committed-then-threw') { retained.push(...structuredClone(body)); throw Error(`ambiguous ${SECRET}`); }
      if (typeof mode === 'number' && mode < 300) retained.push(...structuredClone(body));
      // A rejection must not need to consume a potentially stalled/private body.
      if (mode === 'unreadable-body') return { ok:false, status:500,
        text(){ bodyReads++; throw Error('body must not be consumed'); } };
      const response = new Response(mode >= 400 ? `private storage detail ${SECRET}` : null, {status:mode});
      const originalText = response.text.bind(response);
      response.text = () => { bodyReads++; return originalText(); };
      return response;
    }
    if (u.pathname === '/rest/v1/red_team_reports') {
      if (method === 'GET') return Response.json([{job_state:state,target_id:TARGET}]);
      assert.equal(method,'PATCH'); state = body.job_state || state;
      return Response.json([{target_id:TARGET,job_state:state}]);
    }
    if (u.pathname === '/rest/v1/targets' && method === 'PATCH') return new Response(null,{status:204});
    if (u.pathname === '/rest/v1/target_memory') {
      if (method === 'GET') return Response.json([],{headers:{'content-range':'*/0'}});
      assert.equal(method,'POST'); return new Response(null,{status:201});
    }
    throw Error('unexpected synthetic request');
  };
  return {fetcher,requests,retained,state:()=>state,bodyReads:()=>bodyReads};
}
async function invoke(db, input = rows(), internalJob = true) {
  const logs=[],events=[],waits=[],original=structuredClone(input);
  const values = { fetch:db.fetcher,results:input,SB_URL:DB,sbHeaders:{'content-type':'application/json'},
    report:{id:REPORT,report_id:JOB},targetId:TARGET,target,scanStart:Date.now(),
    sanitizeTargetEvidence:sanitize,sanitizeTargetError:e=>sanitize(String(e)).slice(0,500),
    withCORS:r=>r,json:(body,status=200)=>Response.json(body,{status}),
    request:new Request('https://request.synthetic.invalid'),internalJob,
    ctx:{waitUntil:p=>waits.push(p)},console:{log:x=>logs.push(x),error:x=>logs.push(x)},
    logEvent:async e=>events.push(e),toCanonical:x=>x,qualifiesMemoryOutcome,isQualifiedMemory,
    MEMORY_QUALIFICATION_VERSION,scoutResults:[],probeResults:[],exploitResults:[],exfilResults:[],
    persistResults:[],escalationResults:[],poisonResults:[],socialResults:[],multiTurnResults:[],
    customObjectiveResults:[],swarmIntel:{scoutResults:{},weakCategories:[],confirmedExploits:{},exfilResults:{succeeded:0}},
    runPhaseD:false,runFreeOnly:true,customObjective:null,pipelineVersion:'synthetic',targetIsAI:true,targetTypeReason:'synthetic' };
  const response = await execute(...names.map(n=>values[n])); await Promise.all(waits);
  assert.deepEqual(input,original,'raw observations not mutated');
  return {response,logs,events};
}
const failures = [400,401,403,409,429,500,'throw','committed-then-threw','unreadable-body'];
for (const mode of failures) test(`swarm: ${mode} cannot complete or update Target/memory`,async()=>{
  const db=database(mode); const {response,logs,events}=await invoke(db);
  assert.equal(response.status,500);
  assert.deepEqual(await response.json(),{success:false,error:'swarm_result_write_failed'});
  assert.equal(db.requests.length,1,'stop before completion/Target/memory/retry/delete in this seam');
  assert.equal(db.bodyReads(),0,'failure body is not required');
  assert.equal(db.retained.length,mode==='committed-then-threw'?5:0);
  assert.ok(!JSON.stringify({logs,events,retained:db.retained}).includes(SECRET));
  assert.ok(!events.some(e=>e.action==='SCAN_COMPLETE'));
});
for (const status of [201,204]) for (const internal of [true,false]) test(`swarm: ${status} success, internal=${internal}`,async()=>{
  const db=database(status); const input=rows(); input.push({...input[0],decision:'ERROR',status_code:500});
  const {response,events}=await invoke(db,input,internal); const result=await response.json();
  assert.equal(response.status,200); assert.equal(result.success,true);
  assert.equal(db.retained.length,5,'existing last-occurrence dedup unchanged');
  assert.equal(db.retained[0].decision,'ERROR');
  assert.equal(result.total_tests,5); assert.equal(result.blocked_count,1);
  assert.equal(result.allowed_count,0); assert.equal(result.flagged_count,1); assert.equal(result.error_count,2);
  assert.equal(result.block_rate,50,'ERROR/CONTEXT excluded from decided denominator');
  assert.equal(db.requests[0].query,'?on_conflict=report_uuid,test_id');
  assert.equal(db.requests[0].headers.prefer,'return=minimal,resolution=ignore-duplicates');
  assert.ok(db.retained.every(r=>r.report_uuid===REPORT));
  const reportPatch=db.requests.find(r=>r.path==='/rest/v1/red_team_reports'&&r.method==='PATCH');
  assert.equal(reportPatch.query,`?id=eq.${REPORT}`);
  assert.equal(reportPatch.body.job_state,internal?'completed':undefined);
  assert.equal(reportPatch.body.attack_intelligence.results_write_diagnostic.status,'ok');
  const targetPatch=db.requests.find(r=>r.path==='/rest/v1/targets');
  assert.equal(targetPatch.query,`?id=eq.${TARGET}`); assert.equal(targetPatch.body.total_scans,5);
  const memories=db.requests.filter(r=>r.path==='/rest/v1/target_memory'&&r.method==='POST');
  assert.equal(memories.length,1,'positive control exercises unchanged qualified memory path');
  assert.equal(memories[0].body.target_id,TARGET); assert.equal(memories[0].body.response_patterns.qualification.qualified_outcomes,2);
  assert.ok(!JSON.stringify(db.requests).includes(SECRET),'real final redactor covers payloads');
  assert.ok(events.some(e=>e.action==='SCAN_COMPLETE'));
});
test('swarm: existing empty-input path is unchanged, not new proof of safety',async()=>{
  const db=database(201); const {response}=await invoke(db,[]);
  assert.equal(response.status,200); assert.equal(db.retained.length,0);
  assert.ok(!db.requests.some(r=>r.path==='/rest/v1/red_team_results'));
});
for (const mode of [400,'throw','committed-then-threw',201]) for (const attempts of [1,3]) {
  test(`swarm: existing queue lifecycle ${mode}, attempt ${attempts}`,{concurrency:false},async()=>{
    const db=database(mode,true);let ack=0,retry=0,executions=0;
    const originalFetch=globalThis.fetch,originalWorkerFetch=worker.fetch;
    globalThis.fetch=db.fetcher;
    worker.fetch=async()=>{executions++;return (await invoke(db)).response;};
    try {
      await worker.queue({messages:[{body:{jobId:JOB},attempts,ack(){ack++;},retry(){retry++;}}]},
        {SUPABASE_URL:DB,SUPABASE_SERVICE_ROLE_KEY:'synthetic-local-key',SCAN_JOB_INTERNAL_TOKEN:'synthetic-local-token'},{});
      const success=mode===201;
      assert.equal(executions,1);
      assert.equal(db.state(),success?'completed':attempts===1?'queued':'failed');
      assert.equal(ack,success||attempts===3?1:0); assert.equal(retry,!success&&attempts===1?1:0);
      if (!success) assert.ok(!db.requests.some(r=>r.body?.job_state==='completed'||r.body?.last_scan_status==='completed'));
      if (!success&&attempts===3) assert.ok(db.requests.some(r=>r.body?.failure_code==='WORKER_RETRY_EXHAUSTED'));
      // Full handler/attack execution and pre-scan retry cleanup are outside the
      // injected queue seam. This is not across-retry durability or live RLS proof.
    } finally {globalThis.fetch=originalFetch;worker.fetch=originalWorkerFetch;}
  });
}
