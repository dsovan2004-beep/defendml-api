import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../worker.js';

// Execute each complete, unmodified persistence-to-return branch from worker.js.
// The attack runner is outside this seam: no target/model/auth/DB is contacted.
const source=fs.readFileSync(new URL('../worker.js',import.meta.url),'utf8');
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const families=[['multiturn','mt'],['action','act'],['memory','mem'],['rag','rag'],['mcp','mcp']];
const DB='https://database.synthetic.invalid';
const jobId='10000000-0000-4000-8000-000000000001';
function branch(family,prefix){
  const anchor=source.indexOf(`const ${prefix}Row =`);
  assert.equal(source.split(`const ${prefix}Row =`).length,2,'one row-assignment anchor');
  const start=source.indexOf('          try {',anchor);
  const finish=source.indexOf(`          return withCORS(json({ success: true, report_id: report.report_id, interface: "${family}"`,start);
  const end=source.indexOf('\n',finish);
  assert.ok(anchor>0&&start>anchor&&finish>start&&end>finish,'exact branch boundaries');
  const body=source.slice(start,end);
  assert.ok(body.includes(`JSON.stringify([${prefix}Row])`),'actual canonical result write is inside seam');
  return new AsyncFunction('fetch','SB_URL','sbHeaders',`${prefix}Row`,`${prefix}Start`,'withCORS','json','request','report','sanitizeTargetError','console','sanitizeTargetEvidence','internalJob','targetId','target','ctx','actMode','ragMode','memMode','logEvent',body);
}
async function invoke(family,prefix,fetcher,decision='ALLOW'){
  const logs=[],row={report_uuid:'report-synthetic',test_id:'case-synthetic',decision,case_observation:{exploit_complete:true}};
  const original=structuredClone(row);
  const result=await branch(family,prefix)(fetcher,DB,{'content-type':'application/json'},row,Date.now(),x=>x,
    (body,status)=>Response.json(body,{status}),new Request('https://request.synthetic.invalid'),{id:'report-synthetic',report_id:jobId},
    ()=> 'sanitized',{error:value=>logs.push(value)},x=>x,true,'target-synthetic',{total_scans:3},{waitUntil:()=>{}},'callback','seeded','session',async()=>{});
  assert.deepEqual(row,original,'persistence must not rewrite observed attack proof');
  return {result,logs};
}
function fakeDatabase(mode,{queued=false}={}){
  const requests=[],retained=[];let state=queued?'queued':'running';
  const fetcher=async(input,init={})=>{
    const url=new URL(String(input));assert.equal(url.origin,DB,'all unexpected network calls fail');
    const method=init.method||'GET',body=init.body?JSON.parse(init.body):null;
    requests.push({path:url.pathname,query:url.search,method,body});
    if(url.pathname==='/rest/v1/red_team_results'&&method==='POST'){
      if(mode==='throw')throw Error('synthetic-private-error-must-not-escape');
      if(mode==='committed-then-threw'){retained.push(...structuredClone(body));throw Error('synthetic-private-error-must-not-escape');}
      if(typeof mode==='number'&&mode>=400)return new Response(null,{status:mode});
      retained.push(...structuredClone(body));return new Response(null,{status:mode});
    }
    if(url.pathname==='/rest/v1/red_team_reports'){
      if(method==='GET')return Response.json([{report_id:jobId,job_state:state,target_id:'target-synthetic'}]);
      assert.equal(method,'PATCH');state=body.job_state||state;
      return Response.json([{target_id:'target-synthetic',job_state:state}]);
    }
    if(url.pathname==='/rest/v1/targets'&&method==='PATCH')return new Response(null,{status:204});
    throw Error('unexpected local fake request');
  };
  return {fetcher,requests,retained,state:()=>state};
}
for(const [family,prefix] of families){
  for(const mode of [400,401,403,409,429,500,'throw','committed-then-threw']){
    test(`${family}: result write ${mode} cannot complete report/Target`,async()=>{
      const db=fakeDatabase(mode);const {result}=await invoke(family,prefix,db.fetcher);
      assert.equal(result.status,500);assert.deepEqual(await result.json(),{success:false,error:`${family}_result_write_failed`});
      assert.equal(db.requests.length,1,'no completion PATCH, Target PATCH, retry or deletion within this extracted seam');
      assert.equal(db.retained.length,mode==='committed-then-threw'?1:0);
      // Real sanitizer behavior is outside this injected seam. Existing redaction
      // tests are separate; this assertion does not cover that inline wrapper.
    });
  }
  for(const status of [201,204])for(const decision of ['ALLOW','BLOCK','ERROR']){
    test(`${family}: successful ${status}/${decision} preserves completion and payload`,async()=>{
      const db=fakeDatabase(status);const {result}=await invoke(family,prefix,db.fetcher,decision);
      assert.equal(result.status,200);assert.deepEqual(await result.json(),{success:true,report_id:jobId,interface:family,decision});
      assert.equal(db.retained.length,1);assert.equal(db.retained[0].decision,decision);
      assert.equal(db.requests.length,3);
      assert.equal(db.requests[0].query,'?on_conflict=report_uuid,test_id');
      assert.equal(db.requests[0].body[0].report_uuid,'report-synthetic');
      assert.equal(db.requests[1].query,'?id=eq.report-synthetic');
      assert.equal(db.requests[2].query,'?id=eq.target-synthetic');
      const completion=db.requests[1].body;
      assert.equal(completion.job_state,'completed');assert.equal(completion.total_tests,1);
      assert.equal(completion.allowed_count,decision==='ALLOW'?1:0);
      assert.equal(completion.blocked_count,decision==='BLOCK'?1:0);
      assert.equal(completion.error_count,decision==='ERROR'?1:0);
      assert.equal(db.requests[2].body.last_scan_status,'completed');
    });
  }
  for(const mode of [400,'throw',201])for(const attempts of [1,3]){
    test(`${family}: existing queue lifecycle for ${mode}, attempt ${attempts}`,{concurrency:false},async()=>{
      const db=fakeDatabase(mode,{queued:true});let ack=0,retry=0,executions=0;
      const originalFetch=globalThis.fetch,originalWorkerFetch=worker.fetch;
      globalThis.fetch=db.fetcher;
      worker.fetch=async()=>{executions++;return (await invoke(family,prefix,db.fetcher)).result;};
      try{
        await worker.queue({messages:[{body:{jobId},attempts,ack(){ack++;},retry(){retry++;}}]},
          {SUPABASE_URL:DB,SUPABASE_SERVICE_ROLE_KEY:'synthetic-local-key',SCAN_JOB_INTERNAL_TOKEN:'synthetic-local-job-token'},{});
        assert.equal(executions,1,'queue does not inline-retry a failed execution');
        const success=mode===201;
        assert.equal(db.state(),success?'completed':attempts===1?'queued':'failed');
        assert.equal(ack,success||attempts===3?1:0);assert.equal(retry,!success&&attempts===1?1:0);
        if(!success){
          assert.ok(!db.requests.some(x=>x.body?.job_state==='completed'||x.body?.last_scan_status==='completed'));
          if(attempts===3)assert.ok(db.requests.some(x=>x.body?.failure_code==='WORKER_RETRY_EXHAUSTED'));
        }
        // The real handler's pre-scan retry cleanup is upstream of this seam.
        // This test makes no assertion about deletion/durability across attempts.
      }finally{globalThis.fetch=originalFetch;worker.fetch=originalWorkerFetch;}
    });
  }
}
