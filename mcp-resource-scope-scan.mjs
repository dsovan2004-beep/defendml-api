// MCP resource-scope scan (Phase 2). Drives a native Streamable HTTP MCP session
// against an authorized target and produces ONE canonical red_team_results row
// plus a case_observation the app qualifier re-derives from.
//
// The boundary tested: can an out-of-scope resource be read? The customer places
// a synthetic canary (target.protected_marker) in the out-of-scope resource;
// disclosure is deterministic (the canary appears in the read) and is decided by
// a callback so the marker is never handled here beyond the boolean, and never
// retained (the snippet records only the protocol outcome, then is sanitized).
//
//   canary disclosed on the out-of-scope read -> ALLOW (scope not enforced)
//   out-of-scope read denied, nothing disclosed -> BLOCK (scope enforced)
//   reached the server but neither -> ERROR (inconclusive, never a false verdict)
//   protocol/transport failure -> ERROR
//
// Row key set matches the executeBatch row exactly (the PGRST102 key-parity
// invariant). status_code is null: MCP is native, not HTTP.

import { createMcpHttpSession, McpProtocolError } from './mcp-http-client.mjs';

const MARKER_MIN_LENGTH = 8;

export function buildMcpHeaders(target) {
  const headers = {};
  const authToken = target.auth_token || target.api_key;
  const authHeaderName = (target.auth_header_name || 'authorization').toLowerCase();
  const authMethod = target.auth_method || 'none';
  if (authToken && authMethod !== 'none') {
    headers[authHeaderName] = authMethod === 'api_key' ? authToken : `Bearer ${authToken}`;
  }
  if (target.custom_headers && typeof target.custom_headers === 'object') {
    Object.assign(headers, target.custom_headers);
  }
  return headers;
}

export async function runMcpResourceScopeScan({ target, reportId, fetchImpl = fetch, sanitize = (x) => x, now = Date.now }) {
  const marker = typeof target.protected_marker === 'string' && target.protected_marker.length >= MARKER_MIN_LENGTH
    ? target.protected_marker : null;
  const url = `${String(target.url || '')}${String(target.endpoint_path || '')}`;
  const meta = (target.metadata && typeof target.metadata === 'object' && target.metadata.mcp) || {};
  const inScopeUri = typeof meta.in_scope_uri === 'string' ? meta.in_scope_uri : 'fixture://public';
  const outOfScopeUri = typeof meta.out_of_scope_uri === 'string' ? meta.out_of_scope_uri : 'fixture://private';

  const start = now();
  const observation = {
    contract: 'mcp-resource-scope-v1', adapter: 'mcp-http-v1',
    complete: false, boundary_reached: false, legitimate_task: false,
    disclosed: false, denial_observed: false,
  };
  let decision = 'ERROR';
  let snippet = '';
  const session = createMcpHttpSession({ url, headers: buildMcpHeaders(target), fetchImpl, now });
  try {
    await session.initialize();               // throws on version mismatch / rejection
    await session.notifyInitialized();
    const resources = await session.listResources();
    observation.boundary_reached = Array.isArray(resources);
    const inScope = await session.readResource(inScopeUri, () => false);
    observation.legitimate_task = inScope.kind === 'contents';
    const foreign = await session.readResource(outOfScopeUri, (t) => (marker ? String(t).includes(marker) : false));
    observation.disclosed = foreign.disclosed === true;
    observation.denial_observed = foreign.denial_observed === true;
    observation.complete = true;
    if (observation.disclosed) decision = 'ALLOW';
    else if (observation.denial_observed) decision = 'BLOCK';
    else decision = 'ERROR';
    // Protocol outcome only — never the resource contents, so the canary is not
    // handled here; sanitize() is the defence-in-depth redaction pass regardless.
    snippet = sanitize(`MCP resources/read ${outOfScopeUri}: ${foreign.kind}${foreign.denial_observed ? ' (scope denied)' : ''}`);
  } catch (e) {
    decision = 'ERROR';
    observation.complete = false;
    snippet = sanitize(`MCP protocol failure: ${e instanceof McpProtocolError ? e.kind : 'error'}`);
  } finally {
    session.close();
  }

  return {
    report_uuid: reportId,
    test_id: 'mcp-resource-scope',
    category: 'MCP Resource Scope',
    prompt_text: `MCP resources/read of an out-of-scope resource: ${outOfScopeUri}`,
    decision,
    status_code: null,
    detection_method: 'mcp_resource_scope',
    response_snippet: snippet,
    response_text: null,
    reproduction_steps: null,
    case_observation: observation,
    layer_stopped: decision === 'BLOCK' ? 'resource-authorization' : null,
    latency_ms: now() - start,
  };
}
