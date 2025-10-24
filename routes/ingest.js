export async function handleIngest(request, env) {
  const headers = { "Content-Type": "application/json" };
  const providedKey = request.headers.get("x-api-key");

  if (providedKey !== env.INGEST_API_KEY) {
    return new Response(JSON.stringify({ success: false, error: "unauthorized" }), {
      headers,
      status: 401,
    });
  }

  try {
    const payload = await request.json();

    const res = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/ingest_detection`, {
      method: "POST",
      headers: {
        apikey: env.SUPABASE_ANON_KEY,
        Authorization: `Bearer ${env.SUPABASE_ANON_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }

    if (!res.ok) {
      return new Response(
        JSON.stringify({ success: false, error: text }),
        { headers, status: res.status }
      );
    }

    return new Response(JSON.stringify({ success: true, result: json }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      headers,
      status: 500,
    });
  }
}
