import test from 'node:test';
import assert from 'node:assert/strict';
import { observationEntry, collectSignedRagObservation } from '../rag-signed-observation.mjs';
const id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const entry={target_id:id,enabled:true,key_id:'a'.repeat(64),public_key:{kty:'EC',crv:'P-256',x:'unused',y:'unused'},
  application_digest:'b'.repeat(64),control_answer_digest:'c'.repeat(64),instrumentation:'terminal-store-read-audit-v1',
  source_revisions:['d'.repeat(40)],endpoints:[{digest:'e'.repeat(64),policy_revision:'f'.repeat(40)}],
  observer_url:'https://observer.example/observe'};
const registry=e=>JSON.stringify([e]);
const args={target:{id},reportId:id,jobId:id,challenge:id,query:'query',controlQuery:'control',marker:'synthetic',
  endpoint:'https://target.example/ask',start:Date.now(),row:{report_uuid:id,test_id:'rag-seeded-corpus'}};
test('observer enrollment is operator-only and rejects local, private, token-bearing and insecure URLs',()=>{
  assert.ok(observationEntry(registry(entry),id));
  for(const observer_url of ['http://observer.example/observe','https://localhost/','https://127.0.0.1/',
    'https://10.0.0.1/','https://172.16.0.1/','https://192.168.0.1/','https://100.64.0.1/',
    'https://[::1]/','https://user:pass@observer.example/','https://observer.example/?token=x',
    'https://observer.example/#secret','https://observer.example:8443/'])
    assert.equal(observationEntry(registry({...entry,observer_url}),id),null);
  assert.equal(observationEntry(registry(entry),'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),null);
  assert.equal(observationEntry(registry({...entry,enabled:false}),id),null);
});
test('invalid or missing enrollment performs no observer request',async()=>{
  let calls=0;
  assert.equal(await collectSignedRagObservation({...args,registry:'[]',fetchImpl:()=>{calls++;}}),null);
  assert.equal(calls,0);
});
test('observer transport fails closed and forbids redirects',async()=>{
  for(const response of [new Response('',{status:503}),new Response('',{status:302,headers:{location:'https://untrusted.example/'}}),new Response('{}'),
    new Response('',{headers:{'content-length':'32769'}}),new Response('x'.repeat(32769))]){
    assert.equal(await collectSignedRagObservation({...args,registry:registry(entry),fetchImpl:async(url,init)=>{
      assert.equal(url,entry.observer_url);assert.equal(init.redirect,'manual');
      assert.ok(init.signal);assert.equal(Object.keys(JSON.parse(init.body)).length,4);return response;
    }}),null);
  }
  assert.equal(await collectSignedRagObservation({...args,registry:registry(entry),fetchImpl:async()=>{throw Error('transport');}}),null);
});
test('observer deadline bounds a stalled fetch even if transport ignores abort',async()=>{
  const started=Date.now();
  assert.equal(await collectSignedRagObservation({...args,registry:registry(entry),fetchImpl:()=>new Promise(()=>{})}),null);
  assert.ok(Date.now()-started<6500);
});
