import test from 'node:test';
import assert from 'node:assert/strict';
import {runToolActionScan} from '../action-effect-scan.mjs';
const marker='synthetic-binding-marker';
const cfg={observation_binding:'job-v1',trial_id:'pair-01',source_revision:'a'.repeat(40),policy:'vulnerable'};
const target={id:'qa-target',url:'https://owned.invalid',protected_marker:marker,metadata:{action:cfg},custom_headers:{'X-DefendML-Proof-Assessment-Id':'foreign-job'}};
const proof=action=>({assessment_id:'qa-job',target_id:'qa-target',trial_id:'pair-01',source_revision:'a'.repeat(40),policy:'vulnerable',action});
function transport(tamper){return async (url,init)=>{
  assert.equal(init.headers['x-defendml-proof-assessment-id'],'qa-job');assert.equal(init.headers['X-DefendML-Proof-Assessment-Id'],undefined);
  const action=JSON.parse(init.body).action,p=proof(action);if(tamper)p[tamper]='other';
  return Response.json({content:'observation',action_receipt:{executed:true,effect_token:marker},proof:p});
};}
test('opt-in job context overrides custom headers and accepts only matching proof',async()=>{
 const r=await runToolActionScan({target,reportId:'qa-job',fetchImpl:transport()});assert.equal(r.decision,'ALLOW');
 assert.equal(JSON.stringify(r).includes(marker),false);
});
for(const field of ['assessment_id','target_id','trial_id','source_revision','policy','action'])test(`foreign ${field} cannot qualify`,async()=>{
 const r=await runToolActionScan({target,reportId:'qa-job',fetchImpl:transport(field)});assert.equal(r.decision,'ERROR');assert.equal(r.case_observation.executed,false);
});
test('invalid opt-in configuration fails without dispatch',async()=>{
 let calls=0;const r=await runToolActionScan({target:{...target,metadata:{action:{...cfg,source_revision:'invalid'}}},reportId:'qa-job',fetchImpl:()=>{calls++;}});
 assert.equal(r.decision,'ERROR');assert.equal(calls,0);
});
test('supported persisted Target header selectors choose trial/policy, not job/source overrides',async()=>{
 const t={...target,metadata:{action:{observation_binding:'job-v1',source_revision:cfg.source_revision}},custom_headers:{'X-DefendML-Proof-Trial-Id':'pair-02','x-defendml-proof-policy':'corrected','x-defendml-proof-source-revision':'b'.repeat(40),'x-defendml-proof-assessment-id':'foreign'}};
 const r=await runToolActionScan({target:t,reportId:'qa-job',fetchImpl:async(url,init)=>{
  const p=Object.fromEntries(['assessment_id','target_id','trial_id','source_revision','policy'].map(k=>[k,init.headers[`x-defendml-proof-${k.replaceAll('_','-')}`]]));
  assert.equal(p.assessment_id,'qa-job');assert.equal(p.source_revision,cfg.source_revision);assert.equal(p.trial_id,'pair-02');assert.equal(p.policy,'corrected');
  const action=JSON.parse(init.body).action;
  return Response.json({content:'observation',proof:{...p,action},action_receipt:action==='list_public'?{executed:true}:{executed:false,reason:'scope_denied'}});
 }});assert.equal(r.decision,'BLOCK');
});
