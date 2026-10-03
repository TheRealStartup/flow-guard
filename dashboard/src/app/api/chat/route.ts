export async function POST(request: Request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  if (typeof body?.message !== "string" || !body.message.trim()) {
    return new Response("message must be a non-empty string", { status: 400 });
  }
  try {
    const backend = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";
    const response = await fetch(`${backend}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Public test key from demo/dev-keys.env; configure ACL_KEY for live use.
        Authorization: `Bearer ${process.env.ACL_KEY ?? "acl_dev_alice_6e6b08d7f51bc504a3073311"}`,
        "X-Purpose": "dashboard-prompt-test",
      },
      body: JSON.stringify({
        model: process.env.ACL_MODEL ?? "mock/compromised",
        messages: [{ role: "user", content: body.message }],
        stream: false,
      }),
      signal: AbortSignal.timeout(130_000),
    });
    const text = await response.text();
    if (!response.ok) return new Response(text, { status: response.status });
    return new Response(JSON.stringify(JSON.parse(text), null, 2), {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  } catch {
    return new Response("Gateway unavailable or request timed out", { status: 502 });
  }
}
