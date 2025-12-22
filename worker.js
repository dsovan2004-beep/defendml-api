export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const started = Date.now();
    const reqIP = request.headers.get("cf-connecting-ip") || "";

    // -------- CORS --------
    const ALLOW_ORIGINS = (env.CORS_ORIGIN || "https://defendml-app.pages.dev,https://app.defendml.com")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const pickOrigin = (origin) => {
      if (!origin) return null;
      if (ALLOW_ORIGINS.includes(origin)) return origin;
      if (
        origin.endsWith(".defendml-app.pages.dev") &&
        ALLOW_ORIGINS.some((o) => o.includes("*.defendml-app.pages.dev"))
      ) return origin;
      return null;
    };

    const withCORS = (resp, req) => {
      const o = pickOrigin(req.headers.get("Origin") || "");
      if (o) {
        resp.headers.set("access-control-allow-origin", o);
        resp.headers.set("access-control-allow-credentials", "true");
      }
      // ADD x-api-key to allowed headers
      resp.headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
      resp.headers.set("access-control-allow-headers", "content-type, authorization, x-ingest-key, x-api-key");
      resp.headers.set("access-control-max-age", "86400");
      return resp;
    };

    const json = (data, status = 200, headers = {}) =>
      new Response(JSON.stringify(data, null, 2), {
        status,
        headers: { "content-type": "application/json", ...headers },
      });

    if (request.method === "OPTIONS") {
      return withCORS(new Response(null, { status: 204 }), request);
    }

    // -------- small utils --------
    const te = new TextEncoder();
    const getFlag = (v, def = false) => {
      const s = String(v ?? "").trim().toLowerCase();
      if (s === "true") return true;
      if (s === "false") return false;
      return def;
    };

    async function sha256Hex(s) {
      const buf = await crypto.subtle.digest("SHA-256", te.encode(s));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    async function logEvent(evt) {
      try {
        if (!env.AUDIT_LOG) return;
        const rec = {
          ts: new Date().toISOString(),
          ipHash: reqIP ? await sha256Hex(reqIP) : undefined,
          path: url.pathname,
          method: request.method,
          status: evt.status,
          action: evt.action || "LOG",
          latencyMs: Date.now() - started,
        };
        const key = `audit:${rec.ts.slice(0, 10)}`;
        const arr = JSON.parse((await env.AUDIT_LOG.get(key)) || "[]");
        arr.push(rec);
        await env.AUDIT_LOG.put(key, JSON.stringify(arr), { expirationTtl: 60 * 60 * 24 * 30 });
      } catch (_) {}
    }

    async function rateLimit(bucket = { capacity: 60, refillRatePerSec: 1 }) {
      if (!env.RATE_LIMIT || !reqIP) return { ok: true, remaining: bucket.capacity };
      const k = `rl:${url.pathname}:${reqIP}`;
      const now = Date.now();
      const raw = await env.RATE_LIMIT.get(k);
      let state = raw ? JSON.parse(raw) : { tokens: bucket.capacity, ts: now };
      const elapsed = Math.max(0, (now - state.ts) / 1000);
      state.tokens = Math.min(bucket.capacity, state.tokens + elapsed * bucket.refillRatePerSec);

      if (state.tokens >= 1) {
        state.tokens -= 1;
        state.ts = now;
        await env.RATE_LIMIT.put(k, JSON.stringify(state), { expirationTtl: 86400 });
        return { ok: true, remaining: Math.floor(state.tokens) };
      }
      state.ts = now;
      await env.RATE_LIMIT.put(k, JSON.stringify(state), { expirationTtl: 86400 });
      return { ok: false, remaining: 0, retryAfter: Math.ceil((1 - state.tokens) / bucket.refillRatePerSec) || 1 };
    }

    // -------- global RL --------
    const rl = await rateLimit();
    if (!rl.ok) {
      const resp = withCORS(json({ success: false, error: "rate_limited", retry_after: rl.retryAfter }, 429), request);
      resp.headers.set("Retry-After", String(rl.retryAfter));
      ctx.waitUntil(logEvent({ status: 429, action: "BLOCKED" }));
      return resp;
    }

    // ======== ROUTES ========

    // Root
    if (url.pathname === "/" && request.method === "GET") {
      const resp = withCORS(json({ status: "DefendML API online 🚀" }), request);
      ctx.waitUntil(logEvent({ status: 200, action: "OK" }));
      return resp;
    }

    // Simple health
    if (url.pathname === "/api/health" && request.method === "GET") {
      const resp = withCORS(
        json({
          status: "ok",
          service: "defendml-api",
          cors: ALLOW_ORIGINS,
          mock_mode: getFlag(env.MOCK_MODE),
          strict_mode: getFlag(env.STRICT_MODE),
          timestamp: new Date().toISOString(),
        }),
        request
      );
      ctx.waitUntil(logEvent({ status: 200, action: "OK" }));
      return resp;
    }

    // Metrics -> Supabase RPC: public.metrics_summary()
    if (url.pathname === "/metrics" && request.method === "GET") {
      try {
        if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) {
          const r = withCORS(json({ success: false, error: "supabase_not_configured" }, 500), request);
          ctx.waitUntil(logEvent({ status: 500, action: "ERROR" }));
          return r;
        }
        const res = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/metrics_summary`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            apikey: env.SUPABASE_ANON_KEY,
            authorization: `Bearer ${env.SUPABASE_ANON_KEY}`,
          },
          body: JSON.stringify({}),
        });

        const txt = await res.text();
        let out; try { out = txt ? JSON.parse(txt) : {}; } catch { out = {}; }
        const r = withCORS(json({ success: res.ok, data: out, status: res.status }), request);
        ctx.waitUntil(logEvent({ status: res.status, action: res.ok ? "ALLOWED" : "ERROR" }));
        return r;
      } catch (e) {
        const r = withCORS(json({ success: false, error: String(e) }, 502), request);
        ctx.waitUntil(logEvent({ status: 502, action: "ERROR" }));
        return r;
      }
    }

    // Ingest -> Supabase RPC (existing)
    if (url.pathname === "/ingest" && request.method === "POST") {
      try {
        const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
        const headerKey = (request.headers.get("x-ingest-key") || "").trim();
        const providedKey = bearer || headerKey;

        if (!env.INGEST_API_KEY || providedKey !== env.INGEST_API_KEY) {
          const r = withCORS(json({ success: false, error: "unauthorized" }, 401), request);
          ctx.waitUntil(logEvent({ status: 401, action: "BLOCKED" }));
          return r;
        }

        const body = await request.json().catch(() => ({}));
        const payload = {
          received_at: new Date().toISOString(),
          risk: String(body.risk || "low"),
          source_ip: request.headers.get("CF-Connecting-IP") || "",
          text: String(body.text || ""),
          user_agent: request.headers.get("User-Agent") || "",
        };

        if (env.SUPABASE_URL && env.SUPABASE_ANON_KEY) {
          const res = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/ingest_detection`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              apikey: env.SUPABASE_ANON_KEY,
              authorization: `Bearer ${env.SUPABASE_ANON_KEY}`,
              prefer: "return=minimal",
            },
            body: JSON.stringify(payload),
          });

          if (!res.ok) {
            const detail = await res.text().catch(() => "");
            const r = withCORS(json({ success: false, status: res.status, detail }), request);
            ctx.waitUntil(logEvent({ status: res.status, action: "ERROR" }));
            return r;
          }

          const r = withCORS(json({ success: true, received: true }), request);
          ctx.waitUntil(logEvent({ status: 200, action: "ALLOWED" }));
          return r;
        }

        if (env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE) {
          const res = await fetch(`${env.SUPABASE_URL}/rest/v1/detection_logs`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              apikey: env.SUPABASE_SERVICE_ROLE,
              authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE}`,
              prefer: "return=minimal",
            },
            body: JSON.stringify({
              received_at: payload.received_at,
              risk_level: payload.risk,
              source_ip: payload.source_ip,
              text: payload.text,
              user_agent: payload.user_agent,
            }),
          });

          if (!res.ok) {
            const detail = await res.text().catch(() => "");
            const r = withCORS(json({ success: false, status: res.status, detail }), request);
            ctx.waitUntil(logEvent({ status: res.status, action: "ERROR" }));
            return r;
          }

          const r = withCORS(json({ success: true, received: true }), request);
          ctx.waitUntil(logEvent({ status: 200, action: "ALLOWED" }));
          return r;
        }

        const r = withCORS(json({ success: false, error: "supabase_not_configured" }, 500), request);
        ctx.waitUntil(logEvent({ status: 500, action: "ERROR" }));
        return r;
      } catch (e) {
        const r = withCORS(json({ success: false, error: String(e) }, 500), request);
        ctx.waitUntil(logEvent({ status: 500, action: "ERROR" }));
        return r;
      }
    }

    // NEW: Audit ingestion -> Supabase REST: public.audit_logs
    if (url.pathname === "/ingest/audit" && request.method === "POST") {
      try {
        // Accept Authorization, x-ingest-key, or x-api-key
        const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
        const k1 = (request.headers.get("x-ingest-key") || "").trim();
        const k2 = (request.headers.get("x-api-key") || "").trim();
        const providedKey = bearer || k1 || k2;

        if (!env.INGEST_API_KEY || providedKey !== env.INGEST_API_KEY) {
          const r = withCORS(json({ success: false, error: "unauthorized" }, 401), request);
          ctx.waitUntil(logEvent({ status: 401, action: "BLOCKED" }));
          return r;
        }

        const body = await request.json().catch(() => ({}));

        const row = {
          org_id: body.org_id,                       // MUST be a real orgs.id
          layer: Number.isFinite(body.layer) ? body.layer : 0,
          category: body.category || "Security",
          response_ms: Number.isFinite(body.response_ms) ? body.response_ms : 0,
          event: body.event ?? {},
        };

        if (!row.org_id) {
          const r = withCORS(json({ success: false, error: "org_id_required" }, 400), request);
          ctx.waitUntil(logEvent({ status: 400, action: "ERROR" }));
          return r;
        }

        if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE) {
          const r = withCORS(json({ success: false, error: "supabase_not_configured" }, 500), request);
          ctx.waitUntil(logEvent({ status: 500, action: "ERROR" }));
          return r;
        }

        // Insert into public.audit_logs
        const res = await fetch(`${env.SUPABASE_URL}/rest/v1/audit_logs`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            apikey: env.SUPABASE_SERVICE_ROLE,
            authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE}`,
            prefer: "return=representation",
          },
          body: JSON.stringify(row),
        });

        const text = await res.text().catch(() => "");
        let data;
        try { data = text ? JSON.parse(text) : null; } catch { data = null; }

        if (!res.ok) {
          const r = withCORS(json({ success: false, status: res.status, detail: text }), request);
          ctx.waitUntil(logEvent({ status: res.status, action: "ERROR" }));
          return r;
        }

        const r = withCORS(json({ success: true, row: Array.isArray(data) ? data[0] : data }), request);
        ctx.waitUntil(logEvent({ status: 200, action: "ALLOWED" }));
        return r;
      } catch (e) {
        const r = withCORS(json({ success: false, error: String(e) }, 500), request);
        ctx.waitUntil(logEvent({ status: 500, action: "ERROR" }));
        return r;
      }
    }

    // 404
    const nf = withCORS(json({ success: false, error: "Not found" }, 404), request);
    ctx.waitUntil(logEvent({ status: 404, action: "NF" }));
    return nf;
  },
};
