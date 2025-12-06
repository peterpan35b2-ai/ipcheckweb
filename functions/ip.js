// /functions/ip.js - Main IP API endpoint
export async function onRequest(context) {
  const { request } = context;
  
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=60'
  };

  // Handle OPTIONS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Collect all possible IP headers
    const ipHeaders = {
      'cf-connecting-ip': request.headers.get('cf-connecting-ip'),
      'x-real-ip': request.headers.get('x-real-ip'),
      'x-forwarded-for': request.headers.get('x-forwarded-for'),
      'true-client-ip': request.headers.get('true-client-ip'),
    };
    
    // Detect IPv4 and IPv6 separately
    let ipv4 = null;
    let ipv6 = null;
    let primaryIp = request.headers.get('cf-connecting-ip') || 'Unknown';
    
    // Check all headers for IP addresses
    Object.entries(ipHeaders).forEach(([header, value]) => {
      if (!value) return;
      
      // Handle comma-separated lists (x-forwarded-for)
      const ips = value.split(',').map(ip => ip.trim()).filter(ip => ip && ip !== '');
      
      ips.forEach(ip => {
        if (isIPv4(ip) && !ipv4) {
          ipv4 = ip;
        } else if (isIPv6(ip) && !ipv6) {
          ipv6 = ip;
        }
      });
    });
    
    // If only one IP found, determine if it's v4 or v6
    if (primaryIp && primaryIp !== 'Unknown') {
      if (isIPv4(primaryIp)) {
        ipv4 = primaryIp;
      } else if (isIPv6(primaryIp)) {
        ipv6 = primaryIp;
      }
    }
    
    // Get Cloudflare data
    const cf = request.cf || {};
    const userAgent = request.headers.get('user-agent') || '';
    
    // Determine ISP information
    let ispInfo = {
      name: cf.asOrganization || 'Không xác định',
      organization: cf.asOrganization || '',
      asn: cf.asn || null
    };
    
    // Try to get more detailed info from external API if needed
    if (!ispInfo.name || ispInfo.name === 'Không xác định') {
      try {
        const testIp = ipv4 || ipv6 || primaryIp;
        if (testIp && testIp !== 'Unknown') {
          const externalResponse = await fetch(`https://ipapi.co/${testIp}/json/`, {
            headers: { 'User-Agent': 'CheckTools/1.0' },
            signal: AbortSignal.timeout(3000)
          });
          
          if (externalResponse.ok) {
            const externalData = await externalResponse.json();
            
            // Update ISP info
            ispInfo.name = externalData.org || externalData.asn || 'Không xác định';
            ispInfo.organization = externalData.org || '';
            ispInfo.asn = externalData.asn ? externalData.asn.replace('AS', '') : cf.asn;
            
            // Update location if Cloudflare doesn't have it
            if (!cf.country && externalData.country) {
              cf.country = externalData.country;
              cf.region = externalData.region;
              cf.city = externalData.city;
              cf.postalCode = externalData.postal;
              cf.timezone = externalData.timezone;
              cf.latitude = externalData.latitude;
              cf.longitude = externalData.longitude;
            }
          }
        }
      } catch (e) {
        console.log('External API lookup failed:', e.message);
      }
    }
    
    // Detect Vietnamese ISP
    const vnISP = detectVNISP(ispInfo.name, ipv4 || ipv6 || primaryIp);
    
    // Process Vietnamese province names
    let province = cf.region || '';
    if (cf.country === 'VN' && province) {
      province = convertVNProvince(province);
    }
    
    // Prepare response data
    const responseData = {
      ip: {
        primary: primaryIp,
        ipv4: ipv4,
        ipv6: ipv6,
        version: primaryIp.includes(':') ? 'IPv6' : 'IPv4',
        hasIPv4: !!ipv4,
        hasIPv6: !!ipv6
      },
      location: {
        countryCode: cf.country || 'N/A',
        country: getCountryName(cf.country) || 'N/A',
        province: province,
        city: cf.city || '',
        postalCode: cf.postalCode || '',
        timezone: cf.timezone || '',
        latitude: cf.latitude || null,
        longitude: cf.longitude || null
      },
      network: {
        isp: vnISP,
        organization: ispInfo.organization,
        asn: ispInfo.asn,
        asnName: ispInfo.asn ? `AS${ispInfo.asn}` : null,
        connectionType: getConnectionType(cf),
        mobileCarrier: cf.mobileCarrier || null
      },
      client: {
        userAgent: userAgent,
        browser: parseBrowser(userAgent),
        device: parseDevice(userAgent)
      },
      cloudflare: {
        colo: cf.colo || null,
        regionCode: cf.regionCode || null,
        metroCode: cf.metroCode || null,
        continent: cf.continent || null,
        isIPv6: cf.isIPv6 || primaryIp.includes(':')
      },
      headers: Object.fromEntries(
        Object.entries(ipHeaders).filter(([_, v]) => v !== null)
      ),
      timestamp: new Date().toISOString(),
      source: 'Cloudflare Pages'
    };
    
    return new Response(
      JSON.stringify(responseData, null, 2),
      { status: 200, headers: corsHeaders }
    );
    
  } catch (error) {
    console.error('Error in /ip endpoint:', error);
    return new Response(
      JSON.stringify({ 
        error: error.message,
        message: 'Cannot get IP information'
      }),
      { 
        status: 500, 
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*' 
        } 
      }
    );
  }
}

// Helper Functions
function isIPv4(ip) {
  if (!ip) return false;
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

function isIPv6(ip) {
  if (!ip) return false;
  // Basic IPv6 check
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.length >= 2 && parts.length <= 8;
  }
  return false;
}

function detectVNISP(isp, ip) {
  if (!isp || isp === 'Không xác định') {
    // Try to predict from IP ranges
    if (ip) {
      if (ip.startsWith('14.') || ip.startsWith('113.') || ip.startsWith('117.') || ip.startsWith('118.') || ip.startsWith('180.')) {
        return 'VNPT';
      }
      if (ip.startsWith('27.') || ip.startsWith('42.') || ip.startsWith('115.') || ip.startsWith('116.') || 
          ip.startsWith('125.') || ip.startsWith('175.') || ip.startsWith('183.') || ip.startsWith('210.') || 
          ip.startsWith('222.') || ip.startsWith('171.') || ip.startsWith('2405:4800')) {
        return 'Viettel';
      }
      if (ip.startsWith('58.') || ip.startsWith('123.') || ip.startsWith('2405:8a00')) {
        return 'FPT';
      }
      if (ip.startsWith('240.') || ip.startsWith('2405:9700')) {
        return 'MobiFone';
      }
      if (ip.startsWith('2405:9800')) {
        return 'Vinaphone';
      }
    }
    return 'Không xác định';
  }
  
  // Normalize existing ISP name
  const ispLower = isp.toLowerCase();
  if (ispLower.includes('viettel')) return 'Viettel';
  if (ispLower.includes('vnpt')) return 'VNPT';
  if (ispLower.includes('fpt')) return 'FPT';
  if (ispLower.includes('mobifone')) return 'MobiFone';
  if (ispLower.includes('vinaphone')) return 'Vinaphone';
  if (ispLower.includes('cmc')) return 'CMC';
  if (ispLower.includes('vietnamobile')) return 'Vietnamobile';
  if (ispLower.includes('gtelecom')) return 'GTelecom';
  if (ispLower.includes('netnam')) return 'Netnam';
  
  return isp;
}

function convertVNProvince(provinceCode) {
  if (!provinceCode) return '';
  
  const provinces = {
    'HN': 'Hà Nội',
    'HP': 'Hải Phòng',
    'DN': 'Đà Nẵng',
    'HCM': 'TP Hồ Chí Minh',
    'CT': 'Cần Thơ',
    'QN': 'Quảng Ninh',
    'BG': 'Bắc Giang',
    'BN': 'Bắc Ninh',
    'VP': 'Vĩnh Phúc',
    'TB': 'Thái Bình',
    'ND': 'Nam Định',
    'NB': 'Ninh Bình',
    'TH': 'Thanh Hóa',
    'NA': 'Nghệ An',
    'HT': 'Hà Tĩnh',
    'QB': 'Quảng Bình',
    'QT': 'Quảng Trị',
    'HUE': 'Thừa Thiên Huế',
    'QNM': 'Quảng Nam',
    'QNG': 'Quảng Ngãi',
    'BD': 'Bình Định',
    'PY': 'Phú Yên',
    'KH': 'Khánh Hòa',
    'NT': 'Ninh Thuận',
    'BT': 'Bình Thuận',
    'DNA': 'Đồng Nai',
    'VT': 'Bà Rịa - Vũng Tàu',
    'BP': 'Bình Phước',
    'BDU': 'Bình Dương',
    'TNI': 'Tây Ninh',
    'LA': 'Long An',
    'TG': 'Tiền Giang',
    'BTE': 'Bến Tre',
    'TV': 'Trà Vinh',
    'VL': 'Vĩnh Long',
    'DD': 'Đồng Tháp',
    'AG': 'An Giang',
    'KG': 'Kiên Giang',
    'HG': 'Hậu Giang',
    'ST': 'Sóc Trăng',
    'BL': 'Bạc Liêu',
    'CM': 'Cà Mau'
  };
  
  return provinces[provinceCode] || provinceCode;
}

function getCountryName(countryCode) {
  if (!countryCode || countryCode === 'N/A') return 'N/A';
  
  const countries = {
    'VN': 'Việt Nam',
    'US': 'United States',
    'GB': 'United Kingdom',
    'JP': 'Japan',
    'KR': 'South Korea',
    'CN': 'China',
    'SG': 'Singapore',
    'TH': 'Thailand',
    'ID': 'Indonesia',
    'MY': 'Malaysia',
    'PH': 'Philippines',
    'FR': 'France',
    'DE': 'Germany',
    'CA': 'Canada',
    'AU': 'Australia',
    'IN': 'India',
    'RU': 'Russia',
    'BR': 'Brazil',
    'TW': 'Taiwan',
    'HK': 'Hong Kong',
    'MO': 'Macao'
  };
  
  return countries[countryCode] || countryCode;
}

function getConnectionType(cf) {
  if (cf.mobileCarrier) return 'Mobile';
  if (cf.clientTcpRtt && cf.clientTcpRtt < 50) return 'Wired/Fiber';
  if (cf.clientTcpRtt) return 'Wired';
  if (cf.isIPv6) return 'IPv6 Connection';
  return 'IPv4 Connection';
}

function parseBrowser(userAgent) {
  if (!userAgent) return 'Unknown';
  
  if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) return 'Chrome';
  if (userAgent.includes('Firefox')) return 'Firefox';
  if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
  if (userAgent.includes('Edg')) return 'Edge';
  if (userAgent.includes('Opera')) return 'Opera';
  if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) return 'Internet Explorer';
  
  return 'Unknown';
}

function parseDevice(userAgent) {
  if (!userAgent) return 'Desktop';
  
  if (userAgent.includes('Mobile')) return 'Mobile';
  if (userAgent.includes('Tablet')) return 'Tablet';
  if (userAgent.includes('Android')) return 'Android Mobile';
  if (userAgent.includes('iPhone')) return 'iPhone';
  if (userAgent.includes('iPad')) return 'iPad';
  if (userAgent.includes('Windows')) return 'Windows PC';
  if (userAgent.includes('Mac')) return 'Mac';
  if (userAgent.includes('Linux')) return 'Linux PC';
  
  return 'Desktop';
}
