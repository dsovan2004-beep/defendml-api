import { ragRegistry, ragDigest, verifyRagRows, witnessedRagOutcome } from './rag-witness.mjs';

// Operator-enrolled observer only. Never fetch a Target-supplied observer URL.
export function observationEntry(raw, targetId) {
  const entry = ragRegistry(raw).find(e => e.target_id === targetId);
  if (!entry || typeof entry.observer_url !== 'string') return null;
  try {
    const url = new URL(entry.observer_url);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search
      || (url.port && url.port !== '443') || /^(localhost(?:\.|$)|0\.|127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|\[)/i.test(url.hostname)) return null;
    return entry;
  } catch { return null; }
}
export async function collectSignedRagObservation({ registry, target, reportId, jobId, challenge,
  query, controlQuery, marker, endpoint, start, fetchImpl, row, controlResponse, attackResponse, now = Date.now }) {
  const entry = observationEntry(registry, target.id);
  if (!entry || !jobId) return null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  const bounded = promise => new Promise((resolve, reject) => {
    const abort = () => reject(new Error('observer deadline'));
    if (controller.signal.aborted) return abort();
    controller.signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => controller.signal.removeEventListener('abort', abort));
  });
  try {
    const res = await bounded(fetchImpl(entry.observer_url, {
      // Cloudflare supports manual/follow, not redirect:error. Manual plus
      // the non-2xx rejection below forbids following observer redirects.
      method: 'POST', redirect: 'manual', signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge, target_id: target.id, report_uuid: reportId, job_id: jobId }),
    }));
    if (!res?.ok || Number(res.headers?.get?.('content-length') || 0) > 32768) return null;
    let text;
    if (res.body?.getReader) {
      const reader = res.body.getReader();const chunks=[];let bytes=0;
      try {
        for (;;) { const {done,value}=await bounded(reader.read());if(done)break;
          bytes+=value.byteLength;if(bytes>32768){controller.abort();void reader.cancel().catch(()=>{});return null;}chunks.push(value); }
      } finally { if(controller.signal.aborted)void reader.cancel().catch(()=>{}); reader.releaseLock(); }
      const out=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){out.set(chunk,offset);offset+=chunk.length;}
      text=new TextDecoder().decode(out);
    } else { text=await bounded(res.text());if(new TextEncoder().encode(text).length>32768)return null; }
    const envelope=JSON.parse(text);
    const observed = { ...row, case_observation: { contract:'rag-indirect-v2',
      adapter:'rag-observed-corpus-v2', witness:envelope } };
    // Verify against the actual collection context, including the blind nonce.
    const { verifyRagEnvelope } = await import('./rag-witness.mjs');
    const receipt = await verifyRagEnvelope(envelope, entry, {
      target_id:target.id, report_uuid:reportId, job_id:jobId, challenge,
      endpoint_digest:await ragDigest(endpoint), origin_digest:await ragDigest(new URL(endpoint).origin),
      query_digest:await ragDigest(query), control_digest:await ragDigest(controlQuery),
      marker_digest:await ragDigest(marker), started_at:new Date(start).toISOString(),
      completed_at:new Date(now()).toISOString(),
    });
    if(!receipt)return null;
    if (controlResponse?.requestId && receipt.control.request_id !== controlResponse.requestId) return null;
    if (attackResponse?.requestId && receipt.attack.request_id !== attackResponse.requestId) return null;
    if (controlResponse?.ok && (!controlResponse.requestId
      || receipt.control.answer_digest !== await ragDigest(controlResponse.answer))) return null;
    if (attackResponse?.ok && (!attackResponse.requestId || !attackResponse.retrievalDigest
      || receipt.scope.corpus_digest !== attackResponse.retrievalDigest
      || receipt.source_revision !== attackResponse.sourceRevision)) return null;
    await verifyRagRows([observed],[{id:reportId,report_id:jobId,target_id:target.id,target:endpoint,
      started_at:new Date(start).toISOString(),completed_at:new Date(now()).toISOString()}],registry);
    const outcome=witnessedRagOutcome(observed);
    return { observation: observed.case_observation, outcome,
      limitations: !receipt.attack.complete || !receipt.control.complete };
  } catch { return null; }
  finally {clearTimeout(timeout);}
}
