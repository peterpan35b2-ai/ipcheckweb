// Cloudflare Pages Function – WHOIS lookup (ổn định, có fallback & timeout)

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
      status: 400,
      headers
    });

  const clean = domain.replace(/^https?:\/\//, "").replace(/\/$/, "").split("/")[0];
  const tld = clean.split(".").pop().toLowerCase();

  // RDAP servers phổ biến
  const servers = {
    com: "https://rdap.verisign.com/com/v1/domain/",
    net: "https://rdap.verisign.com/net/v1/domain/",
    org: "https://rdap.publicinterestregistry.net/rdap/org/domain/",
    info: "https://rdap.afilias.net/rdap/info/domain/",
    biz: "https://rdap.neustar.biz/domain/",
    xyz: "https://rdap.nic.xyz/domain/",
    io: "https://rdap.nic.io/domain/",
    dev: "https://rdap.googleapis.com/domain/",
    app: "https://rdap.googleapis.com/domain/",
    me: "https://rdap.nic.me/domain/",
    us: "https://rdap.neustar.biz/domain/",
    uk: "https://rdap.nominet.uk/domain/",
    ca: "https://rdap.ca.fury.ca/domain/",
    jp: "https://rdap.jprs.jp/domain/",
    vn: "https://rdap.vnnic.vn/rdap/domain/"
  };

  const rdapUrl = (servers[tld] || servers["com"]) + clean;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    let resp;
    try {
      resp = await fetch(rdapUrl, {
        signal: controller.signal,
        headers: { "User-Agent": "Mozilla/5.0 (Cloudflare RDAP Lookup)" }
      });
    } catch (e) {
      // Fallback nếu RDAP chính không phản hồi
      resp = await fetch("https://rdap.verisign.com/com/v1/domain/" + clean, {
        headers: { "User-Agent": "Mozilla/5.0 (Fallback RDAP)" }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!resp.ok)
      throw new Error(`RDAP phản hồi lỗi ${resp.status}`);

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
      source: rdapUrl,
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(result, null, 2), { status: 200, headers });
  } catch (e) {
    return new Response(
      JSON.stringify({
        error: e.message,
        note: "Không thể tra RDAP (có thể do chậm hoặc bị chặn)"
      }),
      { status: 500, headers }
    );
  }
}
