// ip.js — API: GET /ip
export async function onRequest(context) {
  const { request } = context;
  
  // Handle OPTIONS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      }
    });
  }

  try {
    const ip = request.headers.get('CF-Connecting-IP') || 
               request.headers.get('x-real-ip') || 
               request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
               '127.0.0.1';
    
    const cf = request.cf || {};
    const ua = request.headers.get('User-Agent') || '';
    
    // Xác định phiên bản IP
    const ipVersion = ip.includes(':') ? 'IPv6' : 'IPv4';
    
    // Xử lý thông tin ISP
    let isp = cf.asOrganization || 'Không xác định';
    let org = cf.asOrganization || '';
    
    // Fallback to ipapi.co nếu cần
    if (!isp || isp === 'Không xác định') {
      try {
        const resp = await fetch(`https://ipapi.co/${ip}/json/`, {
          headers: { 'User-Agent': 'CheckTools/1.0' },
          signal: AbortSignal.timeout(3000)
        });
        
        if (resp.ok) {
          const data = await resp.json();
          isp = data.org || data.asn || 'Không xác định';
          org = data.org || '';
          
          // Nếu có dữ liệu vị trí từ ipapi.co, ưu tiên sử dụng
          if (data.country && !cf.country) {
            cf.country = data.country;
            cf.city = data.city;
            cf.region = data.region;
            cf.postalCode = data.postal;
            cf.timezone = data.timezone;
          }
        }
      } catch (e) {
        console.log('ipapi.co lookup failed:', e.message);
      }
    }
    
    // Xác định ISP Việt Nam nếu có thể
    const ispVN = detectVNISP(isp, ip);
    
    // Chuẩn hóa tên tỉnh/thành cho Việt Nam
    let province = cf.region || '';
    if (cf.country === 'VN' && province) {
      province = convertVNProvince(province);
    }

    return new Response(
      JSON.stringify({
        ip: ip,
        version: ipVersion,
        countryCode: cf.country || 'N/A',
        country: getCountryName(cf.country) || 'N/A',
        province: province,
        city: cf.city || '',
        postal: cf.postalCode || '',
        timezone: cf.timezone || '',
        isp: ispVN,
        org: org || '',
        asn: cf.asn || null,
        latitude: cf.latitude || null,
        longitude: cf.longitude || null,
        userAgent: ua,
        timestamp: new Date().toISOString(),
        source: 'Cloudflare Pages'
      }, null, 2),
      {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Cache-Control': 'public, max-age=60'
        }
      }
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

// Helper functions
function detectVNISP(isp, ip) {
  if (!isp || isp === 'Không xác định') {
    // Dự đoán từ IP ranges
    if (ip.startsWith('14.') || ip.startsWith('113.') || ip.startsWith('117.') || ip.startsWith('118.')) {
      return 'VNPT';
    }
    if (ip.startsWith('27.') || ip.startsWith('42.') || ip.startsWith('115.') || ip.startsWith('116.') || 
        ip.startsWith('125.') || ip.startsWith('175.') || ip.startsWith('183.') || ip.startsWith('210.') || 
        ip.startsWith('222.')) {
      return 'Viettel';
    }
    if (ip.startsWith('58.') || ip.startsWith('123.')) {
      return 'FPT';
    }
    if (ip.startsWith('171.')) {
      return 'CMC';
    }
    if (ip.startsWith('240.')) {
      return 'MobiFone';
    }
    // IPv6
    if (ip.startsWith('2405:4800')) return 'Viettel';
    if (ip.startsWith('2405:8a00')) return 'VNPT';
    if (ip.startsWith('2405:9700')) return 'MobiFone';
  }
  
  // Nếu đã có ISP, chuẩn hóa tên
  const ispLower = isp.toLowerCase();
  if (ispLower.includes('viettel')) return 'Viettel';
  if (ispLower.includes('vnpt')) return 'VNPT';
  if (ispLower.includes('fpt')) return 'FPT';
  if (ispLower.includes('mobifone')) return 'MobiFone';
  if (ispLower.includes('vinaphone')) return 'Vinaphone';
  if (ispLower.includes('cmc')) return 'CMC';
  if (ispLower.includes('vietnamobile')) return 'Vietnamobile';
  
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
    'BR': 'Brazil'
  };
  
  return countries[countryCode] || countryCode;
}
