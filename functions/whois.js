// Cloudflare Pages Function - RDAP WHOIS lookup

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const domain = url.searchParams.get("domain");

  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  };

  if (request.method === "OPTIONS")
    return new Response(null, { headers: cors });

  if (!domain)
    return new Response(JSON.stringify({ error: "Thiếu domain" }), { status: 400, headers: cors });

  const clean = domain.replace(/^https?:\/\//, "").replace(/\/$/, "").split("/")[0];
  const tld = clean.split(".").pop().toLowerCase();

  // RDAP servers theo từng TLD
  const rdapServers = {
    com: "https://rdap.verisign.com/com/v1/domain/",
    net: "https://rdap.verisign.com/net/v1/domain/",
    org: "https://rdap.publicinterestregistry.net/rdap/org/domain/",
    dev: "https://rdap.googleapis.com/domain/",
    vn: "https://rdap.vnnic.vn/rdap/domain/",
  };
  const rdapUrl = (rdapServers[tld] || "https://rdap.org/domain/") + clean;

  try {
    const resp = await fetch(rdapUrl);
    if (!resp.ok) throw new Error("RDAP phản hồi lỗi " + resp.status);

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
      source: rdapUrl,
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(result, null, 2), { status: 200, headers: cors });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message, note: "Không thể tra RDAP" }), {
      status: 500,
      headers: cors
    });
  }
}
