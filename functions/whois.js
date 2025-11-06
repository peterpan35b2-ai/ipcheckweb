// Cloudflare Pages Function – WHOIS lookup (ổn định, dùng Vercel proxy RDAP, timeout + fallback)

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
  if (!/^[a-z0-9-]+\.[a-z.]{2,}$/i.test(clean)) {
    return new Response(JSON.stringify({ error: "Domain không hợp lệ", domain: clean }), {
      status: 400,
      headers
    });
  }

  // Proxy RDAP (Vercel) — đổi nếu dùng URL proxy khác
  const proxyBase = "https://rdap-proxy1.vercel.app/api/rdap?domain=";
  const proxyUrl = proxyBase + encodeURIComponent(clean);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000); // 15s

    let resp;
    try {
      resp = await fetch(proxyUrl, {
        signal: controller.signal,
        headers: { "User-Agent": "Mozilla/5.0 (Cloudflare -> RDAP Proxy)" }
      });
    } catch (fetchErr) {
      clearTimeout(timeout);
      // nếu call tới proxy thất bại, trả lỗi rõ ràng
      return new Response(
        JSON.stringify({
          error: "Không thể liên lạc proxy RDAP",
          detail: fetchErr.message || String(fetchErr),
          note: "Kiểm tra proxy (Vercel) hoặc mạng."
        }),
        { status: 502, headers }
      );
    } finally {
      clearTimeout(timeout);
    }

    // Nếu proxy trả 404 (registry không có dữ liệu)
    if (resp.status === 404) {
      return new Response(
        JSON.stringify({
          domain: clean,
          message: "Tên miền chưa đăng ký hoặc RDAP không có dữ liệu (404)",
          source: proxyUrl,
          timestamp: new Date().toISOString()
        }),
        { status: 200, headers }
      );
    }

    // Nếu proxy trả lỗi khác
    if (!resp.ok) {
      return new Response(
        JSON.stringify({
          error: `Proxy RDAP trả lỗi ${resp.status}`,
          source: proxyUrl,
          timestamp: new Date().toISOString()
        }),
        { status: 502, headers }
      );
    }

    const body = await resp.json().catch(() => ({}));
    // Proxy format: { domain, status, source, data }
    const data = body.data || body; // trong trường hợp proxy trả thẳng json RDAP

    // Nếu registry trả 404 bên trong data (một vài proxy có thể báo trong data)
    if (body.status === 404) {
      return new Response(
        JSON.stringify({
          domain: clean,
          message: "Tên miền chưa đăng ký hoặc RDAP không có dữ liệu (registry 404)",
          source: body.source || proxyUrl,
          timestamp: new Date().toISOString()
        }),
        { status: 200, headers }
      );
    }

    // Hỗ trợ lấy các trường cơ bản từ response RDAP (data)
    const getEvent = a => data.events?.find(e => e.eventAction === a)?.eventDate || null;
    const fmt = d => {
      try {
        return d ? new Date(d).toISOString().split("T")[0] : "Không có";
      } catch {
        return "Không có";
      }
    };

    const registrar =
      data.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(i => i[0] === "fn")?.[3] ||
      (data.registrar && data.registrar) ||
      "Không xác định";

    const result = {
      domain: clean,
      registrar,
      created: fmt(getEvent("registration")),
      updated: fmt(getEvent("last changed")),
      expires: fmt(getEvent("expiration")),
      nameservers: data.nameservers?.map(ns => ns.ldhName) || data.name_servers || [],
      dnssec: data.secureDNS?.delegationSigned ? "Bật" : (data.secureDNS?.delegationSigned === false ? "Tắt" : "Không xác định"),
      status: data.status || [],
      raw: data, // trả luôn dữ liệu gốc để debug / hiển thị chi tiết
      source: body.source || proxyUrl,
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(result, null, 2), { status: 200, headers });
  } catch (e) {
    return new Response(
      JSON.stringify({
        error: e.message || String(e),
        note: "Không thể tra RDAP (có thể do proxy chậm hoặc bị chặn)",
        timestamp: new Date().toISOString()
      }),
      { status: 500, headers }
    );
  }
}
