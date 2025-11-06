// Cloudflare Pages Function – WHOIS lookup dùng RDAP.org (ổn định cho mọi TLD)

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const domain = url.searchParams.get("domain");

  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  };

  if (request.method === "OPTIONS")
    return new Response(null, { headers });

  if (!domain)
    return new Response(JSON.stringify({ error: "Thiếu domain" }), {
      status: 400, headers
    });

  const clean = domain.replace(/^https?:\/\//, "").replace(/\/$/, "").split("/")[0];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch(`https://rdap.org/domain/${clean}`, { signal: controller.signal });
    clearTimeout(timeout);

    if (!resp.ok)
      throw new Error(`RDAP.org phản hồi lỗi ${resp.status}`);

    const data = await resp.json();
    const getEvent = a => data.events?.find(e => e.eventAction === a)?.eventDate || null;
    const fmt = d => (d ? new Date(d).toISOString().split("T")[0] : "Không có");

    const result = {
      domain: clean,
      registrar:
        data.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(i => i[0] === "fn")?.[3] ||
        "Không xác định",
      created: fmt(getEvent("registration")),
      updated: fmt(getEvent("last changed")),
      expires: fmt(getEvent("expiration")),
      nameservers: data.nameservers?.map(ns => ns.ldhName) || [],
      dnssec: data.secureDNS?.delegationSigned ? "Bật" : "Tắt",
      status: data.status || [],
      source: "https://rdap.org",
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(result, null, 2), { status: 200, headers });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message, note: "Không thể tra RDAP.org" }), {
      status: 500, headers
    });
  }
}
