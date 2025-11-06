// Cloudflare Pages Function - WHOIS Lookup API
// Endpoint: /whois?domain=example.com

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
      JSON.stringify({ 
        error: 'Missing domain parameter',
        message: 'Vui lòng cung cấp ?domain=example.com'
      }), 
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
      JSON.stringify({ 
        error: 'Invalid domain',
        message: 'Domain không hợp lệ',
        domain: cleanDomain
      }), 
      { status: 400, headers: corsHeaders }
    );
  }

  try {
    // Use WHOIS API service - whoisjson.com (free tier available)
    const whoisResponse = await fetch(
      `https://whoisjson.com/api/v1/whois?domain=${cleanDomain}`,
      { 
        signal: AbortSignal.timeout(10000)
      }
    );

    if (!whoisResponse.ok) {
      // Fallback to rdap.org
      try {
        const rdapResponse = await fetch(
          `https://rdap.org/domain/${cleanDomain}`,
          { signal: AbortSignal.timeout(10000) }
        );

        if (rdapResponse.ok) {
          const rdapData = await rdapResponse.json();
          
          return new Response(
            JSON.stringify({
              domain: cleanDomain,
              registrar: rdapData.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]?.[1]?.[3] || 'Unknown',
              created: rdapData.events?.find(e => e.eventAction === 'registration')?.eventDate || null,
              updated: rdapData.events?.find(e => e.eventAction === 'last changed')?.eventDate || null,
              expires: rdapData.events?.find(e => e.eventAction === 'expiration')?.eventDate || null,
              status: rdapData.status || [],
              nameservers: rdapData.nameservers?.map(ns => ns.ldhName) || [],
              dnssec: rdapData.secureDNS?.delegationSigned ? 'Enabled' : 'Disabled',
              source: 'rdap.org',
              timestamp: new Date().toISOString()
            }),
            { status: 200, headers: corsHeaders }
          );
        }
      } catch (rdapError) {
        console.error('RDAP failed:', rdapError);
      }

      throw new Error('WHOIS lookup failed');
    }

    const whoisData = await whoisResponse.json();
    
    return new Response(
      JSON.stringify({
        domain: cleanDomain,
        registrar: whoisData.registrar || 'Unknown',
        created: whoisData.created || whoisData.creation_date || null,
        updated: whoisData.updated || whoisData.updated_date || null,
        expires: whoisData.expires || whoisData.expiration_date || null,
        status: Array.isArray(whoisData.status) ? whoisData.status : [whoisData.status],
        nameservers: whoisData.nameservers || whoisData.name_servers || [],
        registrant: whoisData.registrant || null,
        admin: whoisData.admin || null,
        tech: whoisData.tech || null,
        dnssec: whoisData.dnssec || 'Unknown',
        raw: whoisData.raw_text || null,
        source: 'whoisjson.com',
        timestamp: new Date().toISOString()
      }),
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({ 
        error: err.message,
        message: 'Không thể tra cứu WHOIS cho domain này',
        domain: cleanDomain,
        note: 'WHOIS API có thể bị giới hạn rate limit. Thử lại sau vài phút.'
      }),
      { status: 500, headers: corsHeaders }
    );
  }
}