import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.js';

// Baseline characterization, NOT a fixed-behavior acceptance suite. Real queue
// method; handler/model execution replaced by a counted, fixed Response. Every
// fetch is intercepted, host/path/method/query checked; no live database or RLS.
const ORIGIN = 'https://queue-storage.synthetic.invalid';
const JOB = '40000000-0000-4000-8000-000000000024';
const TARGET = '30000000-0000-4000-8000-000000000024';
const NOW = Date.parse('2026-11-24T21:40:00Z');
const env = { SUPABASE_URL:ORIGIN, SUPABASE_SERVICE_ROLE_KEY:'synthetic-only',
  SCAN_JOB_INTERNAL_TOKEN:'synthetic-only' };

async function scenario(options, run) {
  let job = {job_state:options.state || 'queued',target_id:TARGET,
    job_started_at:options.startedAt || null};
  let now=NOW, executions=0, terminalWrites=0;
  const requests=[], deliveries=[];
  const oldFetch=globalThis.fetch, oldHandler=worker.fetch, oldNow=Date.now;
  globalThis.fetch=async(input,init={})=>{
    const u=new URL(String(input)), method=init.method || 'GET';
    assert.equal(u.origin,ORIGIN,'external network forbidden');
    const body=init.body ? JSON.parse(init.body) : null;
    requests.push({path:u.pathname,query:u.search,method,body});
    if (u.pathname==='/rest/v1/red_team_reports') {
      assert.equal(u.searchParams.get('report_id'),`eq.${JOB}`);
      if (method==='GET') return Response.json([structuredClone(job)]);
      assert.equal(method,'PATCH');
      const expected=u.searchParams.get('job_state')?.slice(3);
      assert.ok(['queued','running'].includes(expected),'conditional transition required');
      if (body.job_state==='failed') {
        terminalWrites++;
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
    return new Response(null,{status:204});
  };
  worker.fetch=async(request)=>{
    executions++;
    assert.equal(new URL(request.url).origin,'https://internal.defendml');
    assert.equal(request.headers.get('x-scan-job-token'),'synthetic-only');
    assert.deepEqual(await request.json(),{jobId:JOB,targetId:TARGET});
    if (options.complete) job={...job,job_state:'completed'};
    return Response.json({success:!!options.complete,error:options.complete?undefined:'synthetic_failure'},
      {status:options.status || 500});
  };
  Date.now=()=>now;
  const api={
    get job(){return structuredClone(job);}, get executions(){return executions;},
    get terminalWrites(){return terminalWrites;}, requests,deliveries,
    async deliver(attempts,ageMinutes=0){
      now=NOW+ageMinutes*60000;
      const receipt={attempts,ack:0,retry:0,delays:[]}; deliveries.push(receipt);
      await worker.queue({messages:[{body:{jobId:JOB},attempts,
        ack(){receipt.ack++;},retry(value){receipt.retry++;receipt.delays.push(value.delaySeconds);}}]},env,{});
      return receipt;
    },
  };
  try {await run(api);} finally {globalThis.fetch=oldFetch;worker.fetch=oldHandler;Date.now=oldNow;}
}

test('baseline generic500 invokes handler three times across actual deliveries',async()=>scenario({},async s=>{
  for (let n=1;n<=3;n++) await s.deliver(n);
  assert.equal(s.executions,3); assert.equal(s.job.job_state,'failed');
  assert.equal(s.job.failure_code,'WORKER_RETRY_EXHAUSTED');
  assert.deepEqual(s.deliveries.map(d=>[d.ack,d.retry]),[[0,1],[0,1],[1,0]]);
}));
test('baseline4xx confirmed terminal write prevents repeat handler invocation',async()=>scenario({status:422},async s=>{
  await s.deliver(1); await s.deliver(2);
  assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.job.failure_code,'INVALID_TARGET');
  assert.ok(s.deliveries.every(d=>d.ack===1&&d.retry===0));
}));
test('baseline rejected terminal PATCH is acknowledged while job still running',async()=>scenario({status:422,terminal:'reject'},async s=>{
  const first=await s.deliver(1);
  assert.equal(first.ack,1); assert.equal(first.retry,0); assert.equal(s.job.job_state,'running');
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
  await s.deliver(2); assert.equal(s.executions,2);
}));
test('baseline Target failure after terminal commit does not re-execute handler',async()=>scenario({status:422,targetThrows:true},async s=>{
  await s.deliver(1); await s.deliver(2);
  assert.equal(s.executions,1); assert.equal(s.job.job_state,'failed');
  assert.equal(s.deliveries[0].retry,1); assert.equal(s.deliveries[1].ack,1);
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
}));
