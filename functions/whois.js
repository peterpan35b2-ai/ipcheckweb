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

  if (request.method === 'OPTIONS')
    return new Response(null, { headers: corsHeaders });

  if (!domain)
    return new Response(JSON.stringify({ error: 'Missing domain parameter' }), { status: 400, headers: corsHeaders });

  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').split('/')[0];

  try {
    // --- WHOIS API ---
    const whoisResp = await fetch(`https://whoisjson.com/api/v1/whois?domain=${cleanDomain}`, { signal: AbortSignal.timeout(10000) });
    let whoisData = whoisResp.ok ? await whoisResp.json() : {};

    // Nếu dữ liệu thiếu -> fallback RDAP
    if (!whoisData.created && !whoisData.creation_date) {
      const rdapResp = await fetch(`https://rdap.org/domain/${cleanDomain}`, { signal: AbortSignal.timeout(10000) });
      if (rdapResp.ok) {
        const rdapData = await rdapResp.json();
        whoisData = {
          registrar: rdapData.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.[1]?.[3],
          created: rdapData.events?.find(e => e.eventAction === 'registration')?.eventDate,
          updated: rdapData.events?.find(e => e.eventAction === 'last changed')?.eventDate,
          expires: rdapData.events?.find(e => e.eventAction === 'expiration')?.eventDate,
          status: rdapData.status,
          nameservers: rdapData.nameservers?.map(ns => ns.ldhName),
          dnssec: rdapData.secureDNS?.delegationSigned ? 'Enabled' : 'Disabled',
          source: 'rdap.org'
        };
      }
    }

    return new Response(
      JSON.stringify({
        domain: cleanDomain,
        registrar: whoisData.registrar || 'Không xác định',
        created: whoisData.created || whoisData.creation_date || 'Không xác định',
        updated: whoisData.updated || whoisData.updated_date || 'Không xác định',
        expires: whoisData.expires || whoisData.expiration_date || 'Không xác định',
        status: Array.isArray(whoisData.status) ? whoisData.status : [whoisData.status].filter(Boolean),
        nameservers: whoisData.nameservers || whoisData.name_servers || [],
        dnssec: whoisData.dnssec || 'Không xác định',
        source: whoisData.source || 'whoisjson.com',
        timestamp: new Date().toISOString()
      }),
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message, message: 'Không thể tra cứu WHOIS' }),
      { status: 500, headers: corsHeaders }
    );
  }
}
