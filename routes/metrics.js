export async function handleMetrics(env) {
  const headers = { "Content-Type": "application/json" };

  try {
    const url = `${env.SUPABASE_URL}/rest/v1/rpc/metrics_summary`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        apikey: env.SUPABASE_ANON_KEY,
        Authorization: `Bearer ${env.SUPABASE_ANON_KEY}`,
        "Content-Type": "application/json",
      },
    });

    const data = await res.json();
    return new Response(JSON.stringify({ success: true, data }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, error: err.message }), {
      headers,
      status: 500,
    });
  }
}
