export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const _start = Date.now();
    const _ip = request.headers.get("cf-connecting-ip") || "";

    // ========= CORS helpers =========
    const ALLOW_ORIGINS = (env.CORS_ORIGIN || "https://defendml-app.pages.dev")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const pickOrigin = (origin) => {
      if (!origin) return null;
      if (ALLOW_ORIGINS.includes(origin)) return origin;
      if (
        origin.endsWith(".defendml-app.pages.dev") &&
        ALLOW_ORIGINS.some((o) => o.includes("*.defendml-app.pages.dev"))
      ) {
        return origin;
      }
      return null;
    };

    const withCORS = (resp, req) => {
      const o = pickOrigin(req.headers.get("Origin") || "");
      if (o) {
        resp.headers.set("access-control-allow-origin", o);
        resp.headers.set("access-control-allow-credentials", "true");
      }
      resp.headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
      resp.headers.set("access-control-allow-headers", "content-type, authorization, x-api-key");
      resp.headers.set("access-control-max-age", "86400");
      return resp;
    };

    const json = (data, status = 200, extraHeaders = {}) =>
      new Response(JSON.stringify(data, null, 2), {
        status,
        headers: { "content-type": "application/json", ...extraHeaders },
      });

    if (request.method === "OPTIONS") {
      return withCORS(new Response(null, { status: 204 }), request);
    }

    // ========= Auth Utilities =========
    const JWT_SECRET = env.JWT_SECRET || "change-me-in-production";
    const JWT_EXPIRY = 7 * 24 * 60 * 60;

    const te = new TextEncoder();
    const td = new TextDecoder();

    const b64u = (u8) =>
      btoa(String.fromCharCode(...new Uint8Array(u8)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");

    const b64uFromString = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

    const b64uToU8 = (b64url) => {
      const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - (b64url.length % 4)) % 4);
      const bin = atob(b64);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      return u8;
    };

    async function hashPassword(password) {
      const hashBuffer = await crypto.subtle.digest("SHA-256", te.encode(password));
      return [...new Uint8Array(hashBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    async function signHMAC(dataU8) {
      const key = await crypto.subtle.importKey(
        "raw",
        te.encode(JWT_SECRET),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, dataU8);
      return new Uint8Array(sig);
    }

    async function generateJWT(payload) {
      const now = Math.floor(Date.now() / 1000);
      const claims = { ...payload, iat: now, exp: now + JWT_EXPIRY };
      const headerB64 = b64uFromString(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const payloadB64 = b64uFromString(JSON.stringify(claims));
      const data = `${headerB64}.${payloadB64}`;
      const sig = await signHMAC(te.encode(data));
      const sigB64 = b64u(sig);
      return `${data}.${sigB64}`;
    }

    async function verifyJWT(token) {
      try {
        const parts = String(token || "").split(".");
        if (parts.length !== 3) return null;
        const [h, p, s] = parts;
        const dataU8 = te.encode(`${h}.${p}`);
        const key = await crypto.subtle.importKey(
          "raw",
          te.encode(JWT_SECRET),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"]
        );
        const sigU8 = b64uToU8(s);
        const ok = await crypto.subtle.verify("HMAC", key, sigU8, dataU8);
        if (!ok) return null;
        const payload = JSON.parse(td.decode(b64uToU8(p)));
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return null;
        return payload;
      } catch {
        return null;
      }
    }

    const extractToken = (req) => {
      const h = req.headers.get("authorization") || "";
      const theMatch = h.match(/^Bearer\s+(.+)$/i);
      return theMatch ? theMatch[1] : null;
    };

    async function requireAuth(req) {
      const token = extractToken(req);
      if (!token) return { error: "no_token", status: 401 };
      const payload = await verifyJWT(token);
      if (!payload) return { error: "invalid_or_expired", status: 401 };
      return { user: payload };
    }

    const getFlag = (v, def = false) => {
      const s = String(v ?? "").trim().toLowerCase();
      if (s === "true") return true;
      if (s === "false") return false;
      return def;
    };

    async function _sha256Hex(s) {
      const h = await crypto.subtle.digest("SHA-256", te.encode(s));
      return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    async function logEvent(kv, evt) {
      const rec = {
        ts: new Date().toISOString(),
        ipHash: evt.ip ? await _sha256Hex(evt.ip) : undefined,
        route: evt.route,
        method: evt.method,
        channel: evt.channel || "web",
        cloudHost: evt.cloudHost || "native",
        provider: evt.provider,
        model: evt.model,
        latencyMs: evt.latencyMs,
        usage: evt.usage,
        action: evt.action,
        piiRedacted: evt.piiRedacted,
        status: evt.status,
      };
      const key = `audit:${rec.ts.slice(0, 10)}`;
      const arr = JSON.parse((await kv.get(key)) || "[]");
      arr.push(rec);
      await kv.put(key, JSON.stringify(arr), { expirationTtl: 60 * 60 * 24 * 30 });
      console.log("SEC_EVT", rec);
    }

    async function rateLimit(env, ip, route, bucket = { capacity: 60, refillRatePerSec: 1 }) {
      if (!env.RATE_LIMIT || !ip) {
        return { ok: true, remaining: bucket.capacity };
      }
      const key = `rl:${route}:${ip}`;
      const now = Date.now();

      const raw = await env.RATE_LIMIT.get(key);
      let state = raw ? JSON.parse(raw) : { tokens: bucket.capacity, ts: now };

      const elapsedSec = Math.max(0, (now - state.ts) / 1000);
      state.tokens = Math.min(bucket.capacity, state.tokens + elapsedSec * bucket.refillRatePerSec);

      if (state.tokens >= 1) {
        state.tokens -= 1;
        state.ts = now;
        await env.RATE_LIMIT.put(key, JSON.stringify(state), { expirationTtl: 60 * 60 * 24 });
        return { ok: true, remaining: Math.floor(state.tokens) };
      }

      state.ts = now;
      await env.RATE_LIMIT.put(key, JSON.stringify(state), { expirationTtl: 60 * 60 * 24 });
      return { ok: false, remaining: 0, retryAfter: Math.ceil((1 - state.tokens) / bucket.refillRatePerSec) || 1 };
    }

    const source_ip = request.headers.get("CF-Connecting-IP") || "";
    const user_agent = request.headers.get("User-Agent") || "";
    const isRisky = (text) =>
      /ignore safety|print system secrets|exfiltrat|bypass|steal|token|password|key/i.test(text || "");

    const hasSB = !!(env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE);
    const sbHeaders = hasSB
      ? {
          "content-type": "application/json",
          apikey: env.SUPABASE_SERVICE_ROLE,
          authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE}`,
        }
      : null;

    async function sbPost(path, body, prefer = "return=minimal") {
      if (!hasSB) throw new Error("supabase_not_configured");
      const resp = await fetch(`${env.SUPABASE_URL}${path}`, {
        method: "POST",
        headers: { ...sbHeaders, prefer },
        body: JSON.stringify(body),
      });
      return resp;
    }

    async function sbRPC(fnName, args = {}) {
      if (!hasSB) throw new Error("supabase_not_configured");
      const resp = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${fnName}`, {
        method: "POST",
        headers: sbHeaders,
        body: JSON.stringify(args),
      });
      return resp;
    }

    const parsedIngestKeys = String(env.INGEST_API_KEY || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    function requireIngestKey(req) {
      const got = req.headers.get("x-api-key") || "";
      if (!got || parsedIngestKeys.length === 0) return false;
      return parsedIngestKeys.includes(got);
    }

    const rl = await rateLimit(env, _ip, url.pathname, { capacity: 60, refillRatePerSec: 1 });
    if (!rl.ok) {
      const res = withCORS(json({ success: false, error: "rate_limited", retry_after: rl.retryAfter }, 429), request);
      res.headers.set("Retry-After", String(rl.retryAfter));
      ctx.waitUntil(
        logEvent(env.AUDIT_LOG, {
          route: url.pathname,
          method: request.method,
          ip: _ip,
          action: "BLOCKED",
          status: 429,
          latencyMs: Date.now() - _start,
        })
      );
      return res;
    }

    async function logToSupabase(record) {
      try {
        if (!hasSB) return;
        await fetch(`${env.SUPABASE_URL}/rest/v1/scan_events`, {
          method: "POST",
          headers: { ...sbHeaders, prefer: "return=minimal" },
          body: JSON.stringify(record),
        });
      } catch (e) {
        console.error("SUPABASE_LOG_ERROR", e);
      }
    }

    const pathIs = (...pats) => pats.includes(url.pathname);

    // ========= NEW: RED TEAM EXECUTION =========
    if (url.pathname === "/api/red-team/execute" && request.method === "POST") {
      try {
        const startTime = Date.now();
        const body = await request.json().catch(() => ({}));
        const target = String(body?.target || "").trim();

        if (!target) {
          return withCORS(json({ success: false, error: "Missing 'target' URL" }, 400), request);
        }

        if (!hasSB) {
          return withCORS(json({ success: false, error: "supabase_not_configured" }, 500), request);
        }

        const timestamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, "");
        const report_id = `RPT-${timestamp.slice(0, 8)}-${timestamp.slice(8)}-${Math.random()
          .toString(36)
          .slice(2, 6)}`;

        console.log(`[Red Team] Starting scan ${report_id} against ${target}`);

        const promptsResp = await fetch(`${env.SUPABASE_URL}/rest/v1/red_team_tests?status=eq.active&select=*`, {
          headers: sbHeaders,
        });

        if (!promptsResp.ok) {
          return withCORS(json({ success: false, error: "Failed to fetch prompts" }, 502), request);
        }

        const prompts = await promptsResp.json();
        console.log(`[Red Team] Loaded ${prompts.length} prompts`);

        const results = [];
        let blockedCount = 0;
        let flaggedCount = 0;
        let allowedCount = 0;
        const layerBreakdown = { L1: 0, L2: 0, L3: 0, L4: 0 };

        for (const prompt of prompts) {
          const testStart = Date.now();

          try {
            const testResp = await fetch(target, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                text: prompt.prompt_text,
                test_id: prompt.test_id,
              }),
            });

            const testResult = await testResp.json().catch(() => ({}));
            const testLatency = Date.now() - testStart;

            let decision = "ALLOW";
            let layer_stopped = null;

            if (testResp.status === 403 || testResult.blocked || testResult.risk === "high") {
              decision = "BLOCK";
              blockedCount++;
              layer_stopped = testResult.defense_layer || prompt.target_layer || "L1";
              if (layer_stopped) layerBreakdown[layer_stopped]++;
            } else if (testResp.status === 451 || testResult.risk === "medium") {
              decision = "FLAG";
              flaggedCount++;
              layer_stopped = testResult.defense_layer || prompt.target_layer || "L2";
              if (layer_stopped) layerBreakdown[layer_stopped]++;
            } else {
              allowedCount++;
            }

            results.push({
              test_id: prompt.test_id,
              prompt_text: prompt.prompt_text,
              category: prompt.category,
              subcategory: prompt.subcategory || null,
              decision,
              layer_stopped,
              latency_ms: testLatency,
              status_code: testResp.status,
            });
          } catch (err) {
            console.error(`[Red Team] Error testing ${prompt.test_id}:`, err);
          }

          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        const totalLatency = Date.now() - startTime;
        const successRate = ((blockedCount + flaggedCount) / Math.max(1, results.length) * 100).toFixed(1);

        // ========= Phase 2: store report + get report_uuid =========
        const reportInsertResp = await fetch(`${env.SUPABASE_URL}/rest/v1/red_team_reports`, {
          method: "POST",
          headers: { ...sbHeaders, prefer: "return=representation" },
          body: JSON.stringify({
            report_id,
            target,
            total_prompts: results.length,
            blocked_count: blockedCount,
            flagged_count: flaggedCount,
            allowed_count: allowedCount,
            success_rate: parseFloat(successRate),
            layer_breakdown: layerBreakdown,
            started_at: new Date(startTime).toISOString(),
            completed_at: new Date().toISOString(),
            total_latency_ms: totalLatency,
          }),
        });

        if (!reportInsertResp.ok) {
          const txt = await reportInsertResp.text().catch(() => "");
          throw new Error(`failed_to_insert_red_team_report:${txt}`);
        }

        const inserted = await reportInsertResp.json();
        const report_uuid = inserted?.[0]?.id;

        if (!report_uuid) {
          throw new Error("missing_report_uuid_from_insert");
        }

        // ========= Phase 2: upsert all results =========
        // Table expected: public.red_team_results
        // Unique: (report_uuid, test_id)
        const rows = results.map((r) => ({
          report_uuid,
          test_id: r.test_id,
          category: r.category || null,
          subcategory: r.subcategory || null,
          prompt_text: r.prompt_text || null,
          decision: r.decision, // ALLOW/BLOCK/FLAG
          layer_stopped: r.layer_stopped || null,
          latency_ms: r.latency_ms ?? null,
          status_code: r.status_code ?? null,
        }));

        if (rows.length > 0) {
          const upsertResp = await fetch(
            `${env.SUPABASE_URL}/rest/v1/red_team_results?on_conflict=report_uuid,test_id`,
            {
              method: "POST",
              headers: { ...sbHeaders, prefer: "resolution=merge-duplicates,return=minimal" },
              body: JSON.stringify(rows),
            }
          );

          if (!upsertResp.ok) {
            const txt = await upsertResp.text().catch(() => "");
            throw new Error(`failed_to_upsert_red_team_results:${txt}`);
          }
        }

        const res = withCORS(
          json({
            success: true,
            report_id,
            report_uuid,
            summary: {
              total: results.length,
              blocked: blockedCount,
              flagged: flaggedCount,
              allowed: allowedCount,
              success_rate: `${successRate}%`,
              latency_ms: totalLatency,
              layer_breakdown: layerBreakdown,
            },
            results_preview: results.slice(0, 10),
          }),
          request
        );

        ctx.waitUntil(
          logEvent(env.AUDIT_LOG, {
            route: url.pathname,
            method: request.method,
            ip: _ip,
            action: "ALLOWED",
            status: 200,
            latencyMs: totalLatency,
          })
        );

        return res;
      } catch (err) {
        console.error("[Red Team] Failed:", err);
        return withCORS(json({ success: false, error: String(err) }, 500), request);
      }
    }

    // ========= 404 fallback =========
    const nf = withCORS(json({ success: false, error: "Not found" }, 404), request);
    ctx.waitUntil(
      logEvent(env.AUDIT_LOG, {
        route: url.pathname,
        method: request.method,
        ip: _ip,
        action: "ALLOWED",
        status: 404,
        latencyMs: Date.now() - _start,
      })
    );
    return nf;
  },
};
