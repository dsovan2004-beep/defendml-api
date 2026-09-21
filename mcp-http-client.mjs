// Native MCP client over Streamable HTTP (Phase 2).
//
// Why HTTP only: this runs inside a Cloudflare Worker, which cannot spawn
// subprocesses. A customer MCP server declared with transport STDIO is
// therefore unreachable from DefendML's execution environment. Only
// STREAMABLE_HTTP (and the legacy SSE response form) can be executed; any
// other declared transport must be reported as unsupported, never guessed.
//
// Strictness is the point. Every response is checked for JSON-RPC 2.0, an id
// matching the request, and exactly one of result/error. Anything else is a
// protocol failure, which the evidence model treats as ERROR/UNKNOWN — never as
// a security outcome. Transport text is never returned to callers verbatim.

export const MCP_PROTOCOL_VERSION = '2025-11-25';
export const MCP_EXECUTABLE_TRANSPORTS = Object.freeze(['STREAMABLE_HTTP']);

const MAX_OPERATIONS = 12;
const MAX_RESPONSE_BYTES = 65536;
const REQUEST_TIMEOUT_MS = 8000;

export class McpProtocolError extends Error {
  constructor(kind, detail = '') {
    super(`MCP ${kind}${detail ? `: ${detail}` : ''}`);
    this.kind = kind;
  }
}

// Extract the single JSON-RPC message from a Streamable HTTP response body.
// The transport permits either a bare application/json object or a
// text/event-stream carrying `data:` lines. We accept exactly one JSON-RPC
// object; multiple or zero is a protocol failure. Never eval, never partial.
export function parseMcpBody(contentType, rawBody) {
  if (typeof rawBody !== 'string' || rawBody.length === 0) {
    throw new McpProtocolError('empty_response');
  }
  if (rawBody.length > MAX_RESPONSE_BYTES) {
    throw new McpProtocolError('response_too_large');
  }
  const ct = String(contentType || '').toLowerCase();
  let payloads = [];
  if (ct.includes('text/event-stream')) {
    // Collect data: lines; concatenate multi-line data per SSE framing.
    let current = null;
    for (const line of rawBody.split(/\r?\n/)) {
      if (line.startsWith('data:')) {
        const chunk = line.slice(5).replace(/^ /, '');
        current = current === null ? chunk : `${current}\n${chunk}`;
      } else if (line.trim() === '' && current !== null) {
        payloads.push(current);
        current = null;
      }
    }
    if (current !== null) payloads.push(current);
  } else {
    payloads = [rawBody];
  }
  const parsed = [];
  for (const text of payloads) {
    const trimmed = text.trim();
    if (!trimmed) continue;
    let obj;
    try { obj = JSON.parse(trimmed); }
    catch { throw new McpProtocolError('invalid_json'); }
    // A batch is not part of the single-request/single-response contract here.
    if (Array.isArray(obj)) throw new McpProtocolError('unexpected_batch');
    parsed.push(obj);
  }
  if (parsed.length !== 1) throw new McpProtocolError('non_single_message', String(parsed.length));
  return parsed[0];
}

// Validate one JSON-RPC 2.0 response against the id we sent. Exactly one of
// result/error must be present. Returns { result } or throws for a protocol
// violation; a JSON-RPC error object is returned as { error } so the caller can
// distinguish a well-formed scope denial from a broken exchange.
export function validateJsonRpcResponse(message, expectedId) {
  if (!message || typeof message !== 'object') throw new McpProtocolError('not_an_object');
  if (message.jsonrpc !== '2.0') throw new McpProtocolError('bad_jsonrpc_version');
  if (message.id !== expectedId) throw new McpProtocolError('id_mismatch');
  const hasResult = Object.prototype.hasOwnProperty.call(message, 'result');
  const hasError = Object.prototype.hasOwnProperty.call(message, 'error');
  if (hasResult === hasError) throw new McpProtocolError('result_error_ambiguous');
  if (hasError) {
    const e = message.error;
    if (!e || typeof e !== 'object' || typeof e.code !== 'number') throw new McpProtocolError('malformed_error');
    return { error: { code: e.code, message: typeof e.message === 'string' ? e.message.slice(0, 200) : '' } };
  }
  if (!message.result || typeof message.result !== 'object') throw new McpProtocolError('malformed_result');
  return { result: message.result };
}

// A bounded Streamable HTTP MCP session. `fetchImpl` is injected so the Worker's
// fetch (and tests) can supply it; `headers` carries the caller's declared auth.
export function createMcpHttpSession({ url, headers = {}, fetchImpl = fetch, now = Date.now }) {
  let sequence = 0;
  let operations = 0;
  let closed = false;
  const started = now();

  async function rpc(method, params, { notification = false } = {}) {
    if (closed) throw new McpProtocolError('session_closed');
    if (++operations > MAX_OPERATIONS) throw new McpProtocolError('operation_bound');
    const body = notification
      ? { jsonrpc: '2.0', method, params }
      : { jsonrpc: '2.0', id: ++sequence, method, params };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let res;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch {
      throw new McpProtocolError('transport_failure', method);
    } finally {
      clearTimeout(timer);
    }
    if (notification) return null; // notifications expect no response body
    if (!res || res.status < 200 || res.status >= 300) {
      throw new McpProtocolError('http_status', String(res && res.status));
    }
    const raw = await res.text().catch(() => '');
    const message = parseMcpBody(res.headers && res.headers.get ? res.headers.get('content-type') : '', raw);
    return validateJsonRpcResponse(message, body.id);
  }

  return {
    async initialize() {
      const out = await rpc('initialize', {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'defendml-redteam', version: '1' },
      });
      if (out.error) throw new McpProtocolError('initialize_rejected', String(out.error.code));
      const version = out.result.protocolVersion;
      // The server must speak our protocol version exactly; a downgrade means we
      // cannot make scope claims against a contract we did not negotiate.
      if (version !== MCP_PROTOCOL_VERSION) throw new McpProtocolError('protocol_version_mismatch', String(version));
      return { protocolVersion: version, capabilities: out.result.capabilities || {} };
    },
    async notifyInitialized() { await rpc('notifications/initialized', {}, { notification: true }); },
    async listResources() {
      const out = await rpc('resources/list', {});
      if (out.error) throw new McpProtocolError('list_rejected', String(out.error.code));
      return Array.isArray(out.result.resources) ? out.result.resources : [];
    },
    // Returns a normalized outcome, never raw transport text:
    //   { kind: 'contents', disclosed: true }  — the resource was read back
    //   { kind: 'scope_denial', disclosed: false } — server refused, JSON-RPC error
    // `discloses(text)` lets the caller decide disclosure against a marker without
    // this module ever seeing or retaining the secret.
    async readResource(uri, discloses) {
      const out = await rpc('resources/read', { uri });
      if (out.error) return { kind: 'scope_denial', disclosed: false, denial_observed: true, error_code: out.error.code };
      const contents = out.result.contents;
      if (!Array.isArray(contents)) throw new McpProtocolError('malformed_contents');
      const text = contents.map((c) => (c && typeof c.text === 'string' ? c.text : '')).join('');
      return { kind: 'contents', disclosed: typeof discloses === 'function' ? Boolean(discloses(text)) : false, denial_observed: false };
    },
    elapsedMs() { return now() - started; },
    close() { closed = true; },
  };
}
