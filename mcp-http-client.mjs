// Bounded stateless Streamable HTTP resource client, not a general MCP SDK.
export const MCP_PROTOCOL_VERSION = '2025-11-25';
export const MCP_EXECUTABLE_TRANSPORTS = Object.freeze(['STREAMABLE_HTTP']);
const MAX_OPERATIONS=12, MAX_RESPONSE_BYTES=65536, REQUEST_TIMEOUT_MS=8000;
export class McpProtocolError extends Error {
  constructor(kind){super(`MCP ${kind}`);this.kind=kind;}
}
export function parseMcpBody(contentType,rawBody){
  if(typeof rawBody!=='string'||!rawBody.length)throw new McpProtocolError('empty_response');
  if(new TextEncoder().encode(rawBody).length>MAX_RESPONSE_BYTES)throw new McpProtocolError('response_too_large');
  const ct=String(contentType||'').split(';')[0].trim().toLowerCase();
  if(!['application/json','text/event-stream'].includes(ct))throw new McpProtocolError('unsupported_content_type');
  let payloads=[];
  if(ct==='text/event-stream'){
    let current=null;
    for(const line of rawBody.split(/\r?\n/)){
      if(line.startsWith('data:')){const part=line.slice(5).replace(/^ /,'');current=current===null?part:`${current}\n${part}`;}
      else if(line.trim()===''&&current!==null){payloads.push(current);current=null;}
    }
    if(current!==null)payloads.push(current);
  }else payloads=[rawBody];
  const messages=[];
  for(const text of payloads){if(!text.trim())continue;let message;
    try{message=JSON.parse(text);}catch{throw new McpProtocolError('invalid_json');}
    if(Array.isArray(message))throw new McpProtocolError('unexpected_batch');messages.push(message);
  }
  if(messages.length!==1)throw new McpProtocolError('non_single_message');
  return messages[0];
}
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
export function validateJsonRpcResponse(message,id){
  if(!object(message))throw new McpProtocolError('not_an_object');
  if(message.jsonrpc!=='2.0')throw new McpProtocolError('bad_jsonrpc_version');
  if(message.id!==id)throw new McpProtocolError('id_mismatch');
  const result=Object.hasOwn(message,'result'),error=Object.hasOwn(message,'error');
  if(result===error)throw new McpProtocolError('result_error_ambiguous');
  if(error){if(!object(message.error)||!Number.isSafeInteger(message.error.code)||typeof message.error.message!=='string')throw new McpProtocolError('malformed_error');
    return{error:{code:message.error.code}};}
  if(!object(message.result))throw new McpProtocolError('malformed_result');return{result:message.result};
}
async function collect(res,signal){
  if(!res.body?.getReader)throw new McpProtocolError('body_unavailable');
  const reader=res.body.getReader(),chunks=[];let size=0;
  const abort=()=>{reader.cancel().catch(()=>{});};signal.addEventListener('abort',abort,{once:true});
  try{for(;;){if(signal.aborted)throw new McpProtocolError('deadline');const {done,value}=await reader.read();if(done)break;
    size+=value.byteLength;if(size>MAX_RESPONSE_BYTES)throw new McpProtocolError('response_too_large');chunks.push(value);}
    const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
    try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{throw new McpProtocolError('invalid_utf8');}
  }finally{signal.removeEventListener('abort',abort);reader.cancel().catch(()=>{});reader.releaseLock();}
}
export function createMcpHttpSession({url,headers={},fetchImpl=fetch,now=Date.now,requestTimeoutMs=REQUEST_TIMEOUT_MS}){
  if(!Number.isInteger(requestTimeoutMs)||requestTimeoutMs<1||requestTimeoutMs>REQUEST_TIMEOUT_MS)throw new McpProtocolError('invalid_timeout');
  let sequence=0,operations=0,closed=false,initialized=false,ready=false;const started=now(),nonce=crypto.randomUUID();
  const baseHeaders=new Headers(headers);
  for(const name of ['mcp-session-id','mcp-protocol-version'])baseHeaders.delete(name);
  async function rpc(method,params,{notification=false}={}){
    if(closed)throw new McpProtocolError('session_closed');
    if(++operations>MAX_OPERATIONS)throw new McpProtocolError('operation_bound');
    const body=notification?{jsonrpc:'2.0',method,params}:{jsonrpc:'2.0',id:`${nonce}:${++sequence}`,method,params};
    const controller=new AbortController();let timer;
    const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new McpProtocolError('deadline'));},requestTimeoutMs);});
    const exchange=async()=>{
      const h=new Headers(baseHeaders);h.set('content-type','application/json');h.set('accept','application/json, text/event-stream');
      if(initialized)h.set('mcp-protocol-version',MCP_PROTOCOL_VERSION);
      // Workers supports manual/follow, not redirect:error. Never follow an
      // auth-bearing redirect: collect the 3xx and reject it below instead.
      const res=await fetchImpl(url,{method:'POST',headers:Object.fromEntries(h),body:JSON.stringify(body),signal:controller.signal,redirect:'manual'});
      if(controller.signal.aborted)throw new McpProtocolError('deadline');
      if(notification){if(res?.status!==202){res?.body?.cancel?.().catch(()=>{});throw new McpProtocolError('notification_rejected');}
        res.body?.cancel?.().catch(()=>{});return null;}
      if(!res||res.status<200||res.status>=300){res?.body?.cancel?.().catch(()=>{});throw new McpProtocolError('http_status');}
      if(res.headers.get('mcp-session-id')){res.body?.cancel?.().catch(()=>{});throw new McpProtocolError('stateful_session_unsupported');}
      const ct=res.headers.get('content-type');
      if(!['application/json','text/event-stream'].includes(String(ct||'').split(';')[0].trim().toLowerCase())){res.body?.cancel?.().catch(()=>{});throw new McpProtocolError('unsupported_content_type');}
      return validateJsonRpcResponse(parseMcpBody(ct,await collect(res,controller.signal)),body.id);
    };
    try{return await Promise.race([exchange(),deadline]);}
    catch(e){closed=true;throw e instanceof McpProtocolError?e:new McpProtocolError('transport_failure');}
    finally{clearTimeout(timer);}
  }
  const requireReady=()=>{if(!ready)throw new McpProtocolError('initialization_required');};
  return{
    async initialize(){if(initialized)throw new McpProtocolError('already_initialized');
      const out=await rpc('initialize',{protocolVersion:MCP_PROTOCOL_VERSION,capabilities:{},clientInfo:{name:'defendml-redteam',version:'1'}});
      if(out.error)throw new McpProtocolError('initialize_rejected');
      if(out.result.protocolVersion!==MCP_PROTOCOL_VERSION)throw new McpProtocolError('protocol_version_mismatch');
      if(!object(out.result.capabilities)||!object(out.result.capabilities.resources))throw new McpProtocolError('resources_unsupported');
      initialized=true;return{protocolVersion:MCP_PROTOCOL_VERSION,capabilities:{resources:{}}};},
    async notifyInitialized(){if(!initialized||ready)throw new McpProtocolError('initialization_required');await rpc('notifications/initialized',{}, {notification:true});ready=true;},
    async listResources(){requireReady();const out=await rpc('resources/list',{});if(out.error)throw new McpProtocolError('list_rejected');
      if(!Array.isArray(out.result.resources)||out.result.resources.some(r=>!object(r)||typeof r.uri!=='string'))throw new McpProtocolError('malformed_resources');return out.result.resources;},
    async readResource(uri,discloses){requireReady();const out=await rpc('resources/read',{uri});
      // No standard JSON-RPC error independently witnesses authorization enforcement.
      if(out.error)return{kind:'rpc_error',disclosed:false,denial_observed:false,error_code:out.error.code};
      if(!Array.isArray(out.result.contents)||out.result.contents.some(c=>!object(c)||c.uri!==uri||typeof c.text!=='string'))throw new McpProtocolError('malformed_contents');
      const text=out.result.contents.map(c=>c.text).join('');
      return{kind:'contents',disclosed:typeof discloses==='function'?Boolean(discloses(text)):false,denial_observed:false,nonempty:text.length>0};},
    elapsedMs(){return now()-started;},close(){closed=true;},
  };
}
