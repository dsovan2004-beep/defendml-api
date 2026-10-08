// Authoritative bounded receipt journal. Only the scan Worker has the namespace
// binding for arm/read/seal/delete; the public router exposes ingest only.
// A generation change or storage exception invalidates no-proof completeness.
// Proven receipts survive restarts and unrelated control failures.
const TTL = 15 * 60 * 1000;
const LIMIT = 32768;
const NONCE = /^dml-cb-[A-Za-z0-9]{16,64}$/;
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
});

export function carriesProof(value, expected, raw = '') {
  if (raw.includes(expected)) return true;
  const pending = [value];
  while (pending.length) {
    const next = pending.pop();
    if (typeof next === 'string' && next.includes(expected)) return true;
    if (next && typeof next === 'object') {
      for (const [key, child] of Object.entries(next)) {
        if (!Array.isArray(next) && key.includes(expected)) return true;
        pending.push(child);
      }
    } else if (String(next).includes(expected)) return true;
  }
  return false;
}

export class CanaryJournal {
  constructor(ctx) {
    this.ctx = ctx;
    this.epoch = crypto.randomUUID();
    this.failed = false;
  }

  async fetch(request) {
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        const op = new URL(request.url).pathname;
        if (request.method !== 'POST') return json({ ok: false }, 405);
        if (op === '/disarm') {
          await this.ctx.storage.deleteAll();
          await this.ctx.storage.deleteAlarm();
          return json({ ok: true });
        }
        const input = await request.json();
        if (op === '/arm') {
          if (typeof input.expected !== 'string' || input.expected.length < 8 || input.expected.length > 4096) return json({ ok: false }, 400);
          if (await this.ctx.storage.get('attempt')) return json({ ok: false }, 409);
          // Set the cleanup alarm before accepting the arm.
          await this.ctx.storage.setAlarm(Date.now() + TTL);
          await this.ctx.storage.put('attempt', { expected: input.expected, epoch: this.epoch,
            created: Date.now(), proof: false, received: false, count: 0, sealed: false });
          return json({ ok: true, epoch: this.epoch });
        }
        const state = await this.ctx.storage.get('attempt');
        const live = state && Date.now() - state.created < TTL;
        if (op === '/ingest') {
          if (!live || state.sealed) return json({ ok: true });
          if (typeof input.raw !== 'string' || new TextEncoder().encode(input.raw).length > LIMIT) return json({ ok: false }, 400);
          const payload = JSON.parse(input.raw);
          const proved = carriesProof(payload, state.expected, input.raw);
          // Store no callback content, only monotonic proof and a capped count.
          // A failed put sets the in-memory failure flag; a reset changes epoch.
          await this.ctx.storage.put('attempt', { ...state, proof: state.proof || proved,
            received: true, count: Math.min(8, state.count + 1) });
          return json({ ok: true });
        }
        if (op !== '/poll' && op !== '/seal') return json({ ok: false }, 404);
        if (!live) return json({ storeOk: false });
        if (op === '/seal' && !state.sealed) {
          state.sealed = true;
          await this.ctx.storage.put('attempt', state);
        }
        const continuous = !this.failed && input.epoch === this.epoch && state.epoch === this.epoch;
        return json({ storeOk: Boolean(state.proof || continuous), proofObserved: state.proof,
          received: state.received, events: [], collectionComplete: continuous && state.sealed });
      } catch {
        this.failed = true;
        return json({ ok: false, storeOk: false }, 503);
      }
    });
  }

  async alarm() { await this.ctx.storage.deleteAll(); }
}

async function bounded(call, ms = 8000) {
  const controller = new AbortController();
  let timer;
  try { return await Promise.race([Promise.resolve().then(() => call(controller.signal)).catch(() => null),
    new Promise(r => { timer = setTimeout(() => { controller.abort(); r(null); }, ms); })]); }
  finally { clearTimeout(timer); }
}

export function makeJournalStore(namespace, timeoutMs = 8000) {
  const epochs = new Map();
  const call = (nonce, op, body = {}) => bounded(async (signal) => {
    if (!namespace || !NONCE.test(nonce)) return null;
    const stub = namespace.get(namespace.idFromName(nonce));
    const r = await stub.fetch(new Request(`https://journal.internal/${op}`, {
      method: 'POST', body: JSON.stringify(body), signal,
    }));
    return r.ok ? await r.json() : null;
  }, timeoutMs);
  return {
    async arm(nonce, _report, expected) {
      const result = await call(nonce, 'arm', { expected });
      if (!result?.ok || typeof result.epoch !== 'string') return false;
      epochs.set(nonce, result.epoch);
      return true;
    },
    async poll(nonce) { return await call(nonce, 'poll', { epoch: epochs.get(nonce) }) || { storeOk: false }; },
    async seal(nonce) { return await call(nonce, 'seal', { epoch: epochs.get(nonce) }) || { storeOk: false }; },
    async disarm(nonces) {
      for (const nonce of nonces) {
        await call(nonce, 'disarm');
        epochs.delete(nonce);
      }
    },
  };
}

export async function ingestCanary(request, namespace, timeoutMs = 8000) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  try {
    // Read a bounded stream instead of allocating an arbitrarily large body.
    const reader = request.body?.getReader();
    if (!reader) return json({ error: 'Bad request' }, 400);
    const chunks = []; let size = 0;
    const read = await bounded(async (signal) => {
      signal.addEventListener('abort', () => { void reader.cancel().catch(() => {}); }, { once: true });
      while (true) {
        const { value, done } = await reader.read();
        if (done) return true;
        size += value.length;
        if (size > LIMIT) return false;
        chunks.push(value);
      }
    }, timeoutMs);
    if (read !== true) {
      // Cancellation is best-effort and itself bounded; an uncooperative client
      // stream must not keep the public ingress request open indefinitely.
      await bounded(() => reader.cancel(), Math.min(timeoutMs, 100));
      return json({ error: 'Bad request' }, 400);
    }
    const raw = new TextDecoder().decode(Uint8Array.from(chunks.flatMap(c => [...c])));
    const body = JSON.parse(raw);
    if (!body || Array.isArray(body) || typeof body !== 'object' || !NONCE.test(body.scan_nonce || '')) return json({ error: 'Bad request' }, 400);
    const result = await bounded(async (signal) => {
      if (!namespace) return false;
      const stub = namespace.get(namespace.idFromName(body.scan_nonce));
      const response = await stub.fetch(new Request('https://journal.internal/ingest', { method: 'POST', body: JSON.stringify({ raw }), signal }));
      return response.ok;
    }, timeoutMs);
    // Neither success nor unavailability reveals whether a nonce is armed.
    return result ? json({ ok: true }) : json({ error: 'unavailable' }, 503);
  } catch { return json({ error: 'Bad request' }, 400); }
}
