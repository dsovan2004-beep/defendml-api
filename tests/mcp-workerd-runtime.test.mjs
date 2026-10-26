import test from 'node:test';
import assert from 'node:assert/strict';
import {buildSync} from 'esbuild';
import {Miniflare} from 'miniflare';

test('actual workerd accepts MCP requests, rejects redirects without following and bounds bodies',async()=>{
 const script=buildSync({stdin:{resolveDir:process.cwd(),contents:`
 import {createMcpHttpSession} from './mcp-http-client.mjs';
 export default {async fetch(input){
  const mode=new URL(input.url).searchParams.get('mode');let calls=0;
  const fetchImpl=async(url,init)=>{
   // Exercise the actual Workers Request implementation, not Node's enum.
   const request=new Request(url,init);calls++;
   if(request.redirect!=='manual')throw Error('unsafe redirect mode');
   if(mode==='redirect')return new Response(null,{status:302,headers:{location:'https://untrusted.invalid'}});
   if(mode==='stall')return new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('{'));}}),{headers:{'content-type':'application/json'}});
   const m=JSON.parse(await request.text());
   if(m.method==='notifications/initialized')return new Response(null,{status:202});
   const result=m.method==='initialize'?{protocolVersion:'2025-11-25',capabilities:{resources:{}}}
    :m.method==='resources/list'?{resources:[{uri:'urn:owned:public'}]}
    :{contents:[{uri:m.params.uri,text:'synthetic observed resource'}]};
   return Response.json({jsonrpc:'2.0',id:m.id,result});
  };
  const s=createMcpHttpSession({url:'https://owned.invalid/mcp',fetchImpl,requestTimeoutMs:mode==='stall'?20:1000});
  try{await s.initialize();await s.notifyInitialized();await s.listResources();const read=await s.readResource('urn:owned:public',()=>true);return Response.json({disclosed:read.disclosed,calls});}
  catch(e){return Response.json({kind:e.kind,calls});}finally{s.close();}
 }};`},bundle:true,write:false,format:'esm',platform:'neutral',target:'es2022'}).outputFiles[0].text;
 const mf=new Miniflare({modules:true,compatibilityDate:'2025-01-01',compatibilityFlags:['global_fetch_strictly_public'],script});
 try{
  const valid=await(await mf.dispatchFetch('https://local.invalid/?mode=valid')).json();
  assert.deepEqual(valid,{disclosed:true,calls:4});
  const redirect=await(await mf.dispatchFetch('https://local.invalid/?mode=redirect')).json();
  assert.deepEqual(redirect,{kind:'http_status',calls:1});
  const stall=await(await mf.dispatchFetch('https://local.invalid/?mode=stall')).json();
  assert.deepEqual(stall,{kind:'deadline',calls:1});
 }finally{await mf.dispose();}
});
