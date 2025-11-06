// Cloudflare Pages Function - WHOIS Lookup (pure RDAP, no API limit)

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  if (!domain) {
    return new Response(
      JSON.stringify({ error: 'Thiếu domain', message: 'Hãy dùng ?domain=example.com' }),
      { status: 400, headers: corsHeaders }
    );
  }

  const cleanDomain = domain
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .split('/')[0];

  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$/;
  if (!domainRegex.test(cleanDomain)) {
    return new Response(
      JSON.stringify({ error: 'Domain không hợp lệ', domain: cleanDomain }),
      { status: 400, headers: corsHeaders }
    );
  }

  try {
    const rdapUrl = `https://rdap.org/domain/${cleanDomain}`;
    const rdapResp = await fetch(rdapUrl, { signal: AbortSignal.timeout(10000) });

    if (!rdapResp.ok) {
      throw new Error(`Không truy cập được RDAP (${rdapResp.status})`);
    }

    const rdapData = await rdapResp.json();

    // Lấy thông tin cơ bản
    const getEvent = action =>
      rdapData.events?.find(e => e.eventAction === action)?.eventDate || null;

    const formatDate = d =>
      d ? new Date(d).toISOString().split('T')[0] : 'Không xác định';

    const result = {
      domain: cleanDomain,
      registrar:
        rdapData.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find(
          i => i[0] === 'fn'
        )?.[3] || 'Không xác định',
      created: formatDate(getEvent('registration')),
      updated: formatDate(getEvent('last changed')),
      expires: formatDate(getEvent('expiration')),
      status: rdapData.status || [],
      nameservers: rdapData.nameservers?.map(ns => ns.ldhName) || [],
      dnssec: rdapData.secureDNS?.delegationSigned ? 'Bật' : 'Tắt',
      source: 'rdap.org',
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: corsHeaders
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: err.message,
        message: 'Không thể tra RDAP cho domain này',
        note: 'Có thể domain không tồn tại hoặc RDAP registry chưa hỗ trợ.'
      }),
      { status: 500, headers: corsHeaders }
    );
  }
}
