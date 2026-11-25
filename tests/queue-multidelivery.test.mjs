import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.js';

// Baseline characterization plus named correction acceptance cases. Real queue
// method; handler/model execution replaced by a counted, fixed Response. Every
// fetch is intercepted, host/path/method/query checked; no live database or RLS.
const ORIGIN = 'https://queue-storage.synthetic.invalid';
const JOB = '40000000-0000-4000-8000-000000000024';
const TARGET = '30000000-0000-4000-8000-000000000024';
const NOW = Date.parse('2026-11-24T21:40:00Z');
const env = { SUPABASE_URL:ORIGIN, SUPABASE_SERVICE_ROLE_KEY:'synthetic-only',
  SCAN_JOB_INTERNAL_TOKEN:'synthetic-only' };

async function scenario(options, run) {
  let job = {report_id:JOB,job_state:options.state || 'queued',target_id:TARGET,
    job_started_at:options.startedAt || null};
  let now=NOW, executions=0, terminalWrites=0, targetState='idle', lookupBodyReads=0;
  const scenarioEnv={...env,...options.env};
  const requests=[], deliveries=[];
  const oldFetch=globalThis.fetch, oldHandler=worker.fetch, OldDate=Date;
  // Top-level node:test cases are sequential; never enable file concurrency.
  globalThis.Date=class extends OldDate {
    constructor(...args){super(...(args.length?args:[now]));}
    static now(){return now;}
  };
  globalThis.fetch=async(input,init={})=>{
    const u=new URL(String(input)), method=init.method || 'GET';
    assert.equal(u.origin,ORIGIN,'external network forbidden');
    const body=init.body ? JSON.parse(init.body) : null;
    requests.push({path:u.pathname,query:u.search,method,body});
    if (u.pathname==='/rest/v1/red_team_reports') {
      assert.equal(u.searchParams.get('report_id'),`eq.${JOB}`);
      if (method==='GET') {
        const lookup=Array.isArray(options.lookup)?options.lookup[deliveries.length-1]:options.lookup;
        if (lookup) {
          if (lookup==='throw') throw Error('synthetic lookup failure');
          let response;
          if (typeof lookup==='number') response=Response.json([structuredClone(job)],{status:lookup});
          else if(lookup==='reject') response=Response.json({error:'synthetic'},{status:503});
          else if(lookup==='invalid-json') response=new Response('{');
          else if(lookup==='non-array') response=Response.json({error:'synthetic'});
          else if(lookup==='multiple') response=Response.json([job,job]);
          else if(lookup==='null-row') response=Response.json([null]);
          else if(lookup==='array-row') response=Response.json([[]]);
          else if(lookup==='wrong-id') response=Response.json([{...job,report_id:'wrong-job'}]);
          else if(lookup==='empty') response=Response.json([]);
          else if(lookup==='terminal') response=Response.json([{...job,job_state:'failed'}]);
          else throw Error('unknown synthetic mode');
          const json=response.json.bind(response);
          response.json=()=>{lookupBodyReads++;return json();};
          return response;
        }
        if(terminalWrites && options.reread==='reject') return Response.json({error:'synthetic'},{status:503});
        if(terminalWrites && options.reread==='empty') return Response.json([]);
        if(terminalWrites && options.reread==='non-array') return Response.json({error:'synthetic'});
        if(terminalWrites && options.reread==='completed') job={...job,job_state:'completed'};
        return Response.json([structuredClone(job)]);
      }
      assert.equal(method,'PATCH');
      const expected=u.searchParams.get('job_state')?.slice(3);
      assert.ok(['queued','running'].includes(expected),'conditional transition required');
      if(options.claimMiss && expected==='queued') return Response.json([]);
      if (body.job_state==='failed') {
        terminalWrites++;
        if (options.terminal==='zero-running') return Response.json([]);
        if (options.terminal==='wrong-identity') return Response.json([{...job,report_id:'wrong-job',job_state:'failed'}]);
        if (options.terminal==='reject') return new Response(null,{status:503});
        if (options.terminal==='throw') throw Error('synthetic terminal failure');
        if (options.terminal==='race-queued') {
          job={...job,job_state:'queued',job_started_at:null};
          return Response.json([]);
        }
        if (options.terminal==='commit-then-throw' && job.job_state===expected) {
          job={...job,...body}; throw Error('synthetic ambiguous terminal commit');
        }
      }
      if (job.job_state!==expected) return Response.json([]);
      job={...job,...body};
      return Response.json([structuredClone(job)]);
    }
    assert.equal(u.pathname,'/rest/v1/targets');
    assert.equal(method,'PATCH');
    assert.equal(u.searchParams.get('id'),`eq.${TARGET}`);
    if (body.last_scan_status==='failed' && options.targetThrows) throw Error('synthetic Target failure');
    targetState=body.last_scan_status;
    return new Response(null,{status:204});
  };
  worker.fetch=async(request)=>{
    executions++;
    assert.equal(new URL(request.url).origin,'https://internal.defendml');
    assert.equal(request.headers.get('x-scan-job-token'),'synthetic-only');
    assert.deepEqual(await request.json(),{jobId:JOB,targetId:TARGET});
    if (options.complete) job={...job,job_state:'completed'};
    return Response.json({success:!!options.complete,error:options.complete?undefined:'synthetic_failure'},
      {status:options.status || 500,headers:options.marker===undefined?{}:{'x-defendml-result-storage':options.marker}});
  };
  const api={
    get job(){return structuredClone(job);}, get executions(){return executions;},
    get terminalWrites(){return terminalWrites;}, requests,deliveries,
    get lookupBodyReads(){return lookupBodyReads;},
    get targetState(){return targetState;},
    async deliver(attempts,ageMinutes=0){
      now=NOW+ageMinutes*60000;
      const receipt={attempts,ack:0,retry:0,delays:[]}; deliveries.push(receipt);
      await worker.queue({messages:[{body:{jobId:JOB},attempts,
        ack(){receipt.ack++;},retry(value){receipt.retry++;receipt.delays.push(value.delaySeconds);}}]},scenarioEnv,{});
      return receipt;
    },
  };
  try {await run(api);} finally {globalThis.fetch=oldFetch;worker.fetch=oldHandler;globalThis.Date=OldDate;}
}

test('baseline generic500 invokes handler three times across actual deliveries',async()=>scenario({},async s=>{
  for (let n=1;n<=3;n++) await s.deliver(n);
  assert.equal(s.executions,3); assert.equal(s.job.job_state,'failed');
  assert.equal(s.job.failure_code,'WORKER_RETRY_EXHAUSTED');
  assert.deepEqual(s.deliveries.map(d=>[d.ack,d.retry]),[[0,1],[0,1],[1,0]]);
  assert.deepEqual(s.deliveries.map(d=>d.delays),[[15],[30],[]]);
  assert.deepEqual(s.requests.slice(0,4).map(r=>[r.method,r.path]),[
    ['GET','/rest/v1/red_team_reports'],['PATCH','/rest/v1/red_team_reports'],
    ['PATCH','/rest/v1/targets'],['PATCH','/rest/v1/red_team_reports']]);
}));
test('baseline4xx confirmed terminal write prevents repeat handler invocation',async()=>scenario({status:422},async s=>{
  await s.deliver(1); await s.deliver(2);
  assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.job.failure_code,'INVALID_TARGET');
  assert.equal(s.targetState,'failed');
  assert.ok(s.deliveries.every(d=>d.ack===1&&d.retry===0));
}));
test('baseline rejected terminal PATCH is acknowledged while job still running',async()=>scenario({status:422,terminal:'reject'},async s=>{
  const first=await s.deliver(1);
  assert.equal(first.ack,1); assert.equal(first.retry,0); assert.equal(s.job.job_state,'running');
  assert.equal(s.job.job_started_at,new Date(NOW).toISOString(),'same clock for claim and age');
  await s.deliver(2); assert.equal(s.executions,1); assert.equal(s.deliveries[1].ack,1);
}));
test('baseline thrown terminal PATCH requeues and executes all three attempts',async()=>scenario({status:422,terminal:'throw'},async s=>{
  for(let n=1;n<=3;n++) await s.deliver(n);
  assert.equal(s.executions,3); assert.equal(s.job.job_state,'running');
  assert.equal(s.deliveries[2].ack,1); assert.equal(s.terminalWrites,4);
}));
test('baseline ambiguous committed terminal PATCH does not reset failed job',async()=>scenario({status:422,terminal:'commit-then-throw'},async s=>{
  await s.deliver(1); assert.equal(s.job.job_state,'failed');
  await s.deliver(2); assert.equal(s.executions,1); assert.equal(s.deliveries[1].ack,1);
}));
test('baseline zero-row raced-to-queued terminal write can ack queued job',async()=>scenario({status:422,terminal:'race-queued'},async s=>{
  await s.deliver(1); assert.equal(s.job.job_state,'queued'); assert.equal(s.deliveries[0].ack,1);
  assert.equal(s.targetState,'failed','baseline Target can disagree with queued Report');
  await s.deliver(2); assert.equal(s.executions,2);
}));
test('baseline Target failure after terminal commit does not re-execute handler',async()=>scenario({status:422,targetThrows:true},async s=>{
  await s.deliver(1); await s.deliver(2);
  assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.deliveries[0].retry,1); assert.equal(s.deliveries[1].ack,1);
  assert.equal(s.targetState,'running','baseline Target can remain stale after failed Report');
}));
test('baseline recent-running delivery acks without verified terminal state',async()=>scenario({state:'running',startedAt:new Date(NOW).toISOString()},async s=>{
  await s.deliver(2,1); assert.equal(s.executions,0); assert.equal(s.job.job_state,'running');
  assert.equal(s.deliveries[0].ack,1);
}));
test('baseline delayed running delivery requeues then invokes handler',async()=>scenario({state:'running',startedAt:new Date(NOW).toISOString()},async s=>{
  await s.deliver(2,16); assert.equal(s.job.job_state,'queued'); assert.equal(s.executions,0);
  await s.deliver(3,16); assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
}));
test('completed success redelivery invokes handler only once',async()=>scenario({status:200,complete:true},async s=>{
  await s.deliver(1); await s.deliver(2); assert.equal(s.executions,1);
  assert.equal(s.job.job_state,'completed'); assert.equal(s.terminalWrites,0);
  assert.deepEqual(s.requests.map(r=>[r.method,r.path]),[
    ['GET','/rest/v1/red_team_reports'],['PATCH','/rest/v1/red_team_reports'],
    ['PATCH','/rest/v1/targets'],['GET','/rest/v1/red_team_reports']]);
}));
for(const lookup of ['reject','non-array']) test(`lookup correction: ${lookup} retries queued job without execution`,async()=>scenario({lookup},async s=>{
  await s.deliver(1); assert.equal(s.executions,0); assert.equal(s.job.job_state,'queued');
  assert.equal(s.deliveries[0].ack,0); assert.deepEqual(s.deliveries[0].delays,[60]); assert.equal(s.requests.length,1);
}));
for(const attempts of [1,3]) test(`baseline claim-miss attempt${attempts} retries without terminalizing`,async()=>scenario({claimMiss:true},async s=>{
  await s.deliver(attempts); assert.equal(s.executions,0); assert.equal(s.job.job_state,'queued');
  assert.equal(s.deliveries[0].ack,0); assert.deepEqual(s.deliveries[0].delays,[5]);
}));
test('baseline stale reclaim attempt3 retries queued state, not terminal',async()=>scenario({state:'running',startedAt:new Date(NOW).toISOString()},async s=>{
  await s.deliver(3,16); assert.equal(s.executions,0); assert.equal(s.job.job_state,'queued');
  assert.deepEqual(s.deliveries[0].delays,[5]); assert.equal(s.deliveries[0].ack,0);
}));
test('baseline future-dated running job also receives nonterminal ack',async()=>scenario({state:'running',startedAt:new Date(NOW+60000).toISOString()},async s=>{
  await s.deliver(1); assert.equal(s.executions,0); assert.equal(s.job.job_state,'running');
  assert.equal(s.deliveries[0].ack,1);
}));
for(const [status,code] of [[409,'TARGET_INACTIVE'],[429,'WORKER_REJECTED']]) test(`baseline internal${status} terminal mapping`,async()=>scenario({status},async s=>{
  await s.deliver(1); assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.job.failure_code,code); assert.equal(s.deliveries[0].ack,1);
}));

const MARKER='rejected-no-retry';
for(const lookup of [401,403,404,429,500,503,'throw','invalid-json','non-array','multiple','null-row','array-row','wrong-id']) {
  for(const attempts of [1,3]) test(`lookup correction: ${lookup} at attempt${attempts} has no side effects`,async()=>scenario({lookup},async s=>{
    const d=await s.deliver(attempts);
    assert.deepEqual([d.ack,d.retry,d.delays],[0,1,[60]]);
    assert.equal(s.executions,0); assert.equal(s.terminalWrites,0);
    assert.equal(s.job.job_state,'queued'); assert.equal(s.targetState,'idle');
    assert.equal(s.requests.length,1); assert.equal(s.requests[0].method,'GET');
    assert.equal(new URLSearchParams(s.requests[0].query).get('select'),'report_id,job_state,job_started_at,target_id');
    if(typeof lookup==='number') assert.equal(s.lookupBodyReads,0,'HTTP rejection body must remain unread');
  }));
}
for(const lookup of [503,'throw','invalid-json','wrong-id']) test(`lookup correction: ${lookup} then recovered delivery executes exactly once`,async()=>scenario({lookup:[lookup,null],status:200,complete:true},async s=>{
  await s.deliver(1); assert.equal(s.executions,0); assert.equal(s.requests.length,1);
  await s.deliver(2); assert.equal(s.executions,1); assert.equal(s.job.job_state,'completed');
  assert.deepEqual(s.deliveries.map(d=>[d.ack,d.retry]),[[0,1],[1,0]]);
}));
test('lookup correction: persistent outage never acknowledges or writes even at attempt3',async()=>scenario({lookup:503},async s=>{
  for(let i=1;i<=3;i++) await s.deliver(i);
  assert.equal(s.executions,0); assert.equal(s.requests.length,3);
  assert.ok(s.requests.every(r=>r.method==='GET'));
  assert.ok(s.deliveries.every(d=>d.ack===0&&d.retry===1));
  assert.equal(s.lookupBodyReads,0); assert.equal(s.job.job_state,'queued');
}));
for(const lookup of ['empty','terminal']) test(`lookup correction: successful ${lookup} preserves acknowledgment`,async()=>scenario({lookup},async s=>{
  const d=await s.deliver(3); assert.equal(d.ack,1); assert.equal(d.retry,0);
  assert.equal(s.executions,0); assert.equal(s.requests.length,1);
}));
for(const lookup of ['empty','non-array',503]) test(`lookup correction: held ${lookup} never acknowledges`,async()=>scenario({lookup,env:{SCAN_RELEASE_HOLD:'true',SCAN_RELEASE_QA_TARGETS:TARGET}},async s=>{
  const d=await s.deliver(3); assert.equal(d.ack,0); assert.deepEqual(d.delays,[60]);
  assert.equal(s.executions,0); assert.equal(s.requests.length,1);
}));
test('correction: marked500 confirms failure and redelivery executes no new handler',async()=>scenario({marker:MARKER},async s=>{
  await s.deliver(1); await s.deliver(2);
  assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.job.failure_code,'RESULT_STORAGE_REJECTED'); assert.equal(s.targetState,'failed');
  assert.ok(s.deliveries.every(d=>d.ack===1&&d.retry===0));
  assert.equal(s.requests.filter(r=>r.method==='GET').length,2,'no reread after confirmed PATCH');
}));
test('correction: ambiguous terminal commit is confirmed by one reread',async()=>scenario({marker:MARKER,terminal:'commit-then-throw'},async s=>{
  await s.deliver(1); assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.deliveries[0].ack,1); assert.equal(s.deliveries[0].retry,0);
  assert.equal(s.requests.filter(r=>r.method==='GET').length,2);
}));
test('correction: Target failure after confirmed Report does not schedule retry',async()=>scenario({marker:MARKER,targetThrows:true},async s=>{
  await s.deliver(1); await s.deliver(2); assert.equal(s.executions,1);
  assert.equal(s.job.job_state,'failed'); assert.equal(s.targetState,'running');
  assert.ok(s.deliveries.every(d=>d.ack===1&&d.retry===0));
}));
for(const terminal of ['reject','throw','race-queued','zero-running','wrong-identity']) {
  test(`correction: unconfirmed ${terminal} retains bounded fallback, not no-rerun guarantee`,async()=>scenario({marker:MARKER,terminal},async s=>{
    await s.deliver(1); assert.equal(s.job.job_state,'queued');
    assert.equal(s.deliveries[0].ack,0); assert.deepEqual(s.deliveries[0].delays,[15]);
    assert.equal(s.requests.filter(r=>r.method==='GET').length,2,'only one confirmation reread');
    await s.deliver(2); assert.equal(s.executions,2,'outage fallback may re-execute');
  }));
}
for(const reread of ['reject','empty','non-array']) {
  test(`correction: ${reread} confirmation is UNKNOWN, not terminal closure`,async()=>scenario({marker:MARKER,terminal:'zero-running',reread},async s=>{
    await s.deliver(1); assert.equal(s.deliveries[0].ack,0); assert.equal(s.deliveries[0].retry,1);
    assert.equal(s.job.job_state,'queued');
  }));
}
test('correction: already-completed reread does not overwrite Target as failed',async()=>scenario({marker:MARKER,terminal:'zero-running',reread:'completed'},async s=>{
  await s.deliver(1); assert.equal(s.job.job_state,'completed'); assert.equal(s.targetState,'running');
  assert.equal(s.deliveries[0].ack,1); assert.equal(s.deliveries[0].retry,0);
  assert.ok(!s.requests.some(r=>r.body?.last_scan_status==='failed'));
}));
for(const [status,marker] of [[500,'invalid'],[503,MARKER],[200,MARKER]]) {
  test(`correction: marker/status mismatch ${status}/${marker} cannot select new failure code`,async()=>scenario({status,marker},async s=>{
    await s.deliver(1); assert.ok(!s.requests.some(r=>r.body?.failure_code==='RESULT_STORAGE_REJECTED'));
  }));
}
