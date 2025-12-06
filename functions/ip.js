// API: /ip
export async function onRequest(context) {
  const { request } = context;
  
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Ưu tiên lấy IP từ Cloudflare headers
    let ip = request.headers.get('cf-connecting-ip') || 'Unknown';
    
    // Nếu là IPv6 localhost hoặc test, thử lấy từ header khác
    if (ip === '::1' || ip.startsWith('fe80:') || ip === 'Unknown') {
      ip = request.headers.get('x-real-ip') || 
           request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
           ip;
    }
    
    const country = request.headers.get('cf-ipcountry') || 'Unknown';
    const userAgent = request.headers.get('user-agent') || 'Unknown';
    
    // Sử dụng dữ liệu từ Cloudflare (có sẵn và miễn phí)
    const cf = request.cf || {};
    
    // Xác định phiên bản IP
    const ipVersion = getIPVersion(ip);
    
    // Lấy thông tin ISP từ ASN của Cloudflare
    let ispInfo = await getISPFromASN(cf.asn, ip);
    
    // Chuẩn hóa tên tỉnh/thành phố cho Việt Nam
    let province = cf.region || null;
    let city = cf.city || null;
    
    if (cf.country === 'VN' || country === 'VN') {
      province = convertVNProvince(province);
      city = convertVNCity(city, province);
      
      // Nếu có ISP từ ASN nhưng chưa rõ, thử dự đoán từ IP
      if (!ispInfo.name || ispInfo.name === 'Unknown') {
        ispInfo = predictVNISP(ip, ispInfo);
      }
    }
    
    // Tạo response data
    const responseData = {
      ip: {
        address: ip,
        version: ipVersion,
        type: cf.ipVersion || ipVersion
      },
      location: {
        country: cf.country || country,
        countryName: getCountryName(cf.country || country),
        province: province,
        city: city,
        latitude: cf.latitude || null,
        longitude: cf.longitude || null,
        timezone: cf.timezone || null,
        postalCode: cf.postalCode || null
      },
      network: {
        isp: ispInfo.name,
        organization: ispInfo.organization,
        asn: cf.asn || ispInfo.asn,
        asnName: ispInfo.asnName,
        connectionType: getConnectionType(cf),
        mobileCarrier: cf.mobileCarrier || null
      },
      client: {
        userAgent: userAgent,
        browser: parseUserAgent(userAgent)
      },
      cloudflare: {
        colo: cf.colo || null,
        regionCode: cf.regionCode || null,
        metroCode: cf.metroCode || null,
        continent: cf.continent || null
      },
      timestamp: new Date().toISOString(),
      source: 'Cloudflare Worker'
    };
    
    return new Response(
      JSON.stringify(responseData),
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    console.error('Error in IP API:', err);
    return new Response(
      JSON.stringify({ 
        error: err.message,
        message: 'Cannot get IP information'
      }),
      { status: 500, headers: corsHeaders }
    );
  }
}

// Helper Functions
function getIPVersion(ip) {
  if (!ip || ip === 'Unknown') return 'Unknown';
  
  if (ip.includes(':')) {
    // Kiểm tra IPv6
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    return ipv6Regex.test(ip) ? 'IPv6' : 'Unknown';
  }
  
  // Kiểm tra IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip) ? 'IPv4' : 'Unknown';
}

async function getISPFromASN(asn, ip) {
  if (!asn) {
    return {
      name: 'Unknown',
      organization: 'Unknown',
      asn: null,
      asnName: null
    };
  }
  
  // ASN mapping cho các nhà mạng phổ biến
  const asnMap = {
    // Việt Nam
    'AS45899': { name: 'VNPT', organization: 'Vietnam Posts and Telecommunications Group', country: 'VN' },
    'AS7552': { name: 'Viettel', organization: 'Viettel Corporation', country: 'VN' },
    'AS18403': { name: 'FPT', organization: 'FPT Telecom', country: 'VN' },
    'AS45543': { name: 'MobiFone', organization: 'MobiFone Corporation', country: 'VN' },
    'AS38731': { name: 'Vinaphone', organization: 'Vinaphone', country: 'VN' },
    'AS55378': { name: 'CMC', organization: 'CMC Telecom', country: 'VN' },
    'AS131414': { name: 'Vietnamobile', organization: 'Vietnamobile', country: 'VN' },
    
    // Quốc tế
    'AS15169': { name: 'Google', organization: 'Google LLC', country: 'US' },
    'AS16509': { name: 'Amazon', organization: 'Amazon.com, Inc.', country: 'US' },
    'AS8075': { name: 'Microsoft', organization: 'Microsoft Corporation', country: 'US' },
    'AS13335': { name: 'Cloudflare', organization: 'Cloudflare, Inc.', country: 'US' },
    'AS14061': { name: 'DigitalOcean', organization: 'DigitalOcean, LLC', country: 'US' },
    'AS63949': { name: 'Linode', organization: 'Linode, LLC', country: 'US' },
    'AS16276': { name: 'OVH', organization: 'OVH SAS', country: 'FR' },
    'AS45102': { name: 'Alibaba', organization: 'Alibaba (US) Technology Co., Ltd.', country: 'CN' },
    'AS132203': { name: 'Tencent', organization: 'Tencent Cloud Computing', country: 'CN' }
  };
  
  const asnKey = `AS${asn}`;
  if (asnMap[asnKey]) {
    return {
      name: asnMap[asnKey].name,
      organization: asnMap[asnKey].organization,
      asn: asn,
      asnName: asnKey
    };
  }
  
  // Nếu không có trong map, thử query từ API
  try {
    const response = await fetch(`https://api.bgpview.io/asn/${asn}`, {
      signal: AbortSignal.timeout(2000)
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.data) {
        return {
          name: data.data.name || 'Unknown',
          organization: data.data.description || 'Unknown',
          asn: asn,
          asnName: `AS${asn}`
        };
      }
    }
  } catch (e) {
    console.log('BGPView API failed');
  }
  
  return {
    name: 'Unknown',
    organization: 'Unknown',
    asn: asn,
    asnName: `AS${asn}`
  };
}

function predictVNISP(ip, currentISP) {
  const ipRanges = {
    '14.': 'VNPT',
    '27.': 'Viettel',
    '42.': 'Viettel',
    '58.': 'FPT',
    '113.': 'VNPT',
    '115.': 'Viettel',
    '116.': 'Viettel',
    '117.': 'VNPT',
    '118.': 'VNPT',
    '123.': 'FPT',
    '125.': 'Viettel',
    '171.': 'CMC',
    '175.': 'Viettel',
    '180.': 'VNPT',
    '183.': 'Viettel',
    '210.': 'Viettel',
    '222.': 'Viettel',
    '240.': 'MobiFone',
    '27.64.': 'Viettel',
    '27.65.': 'Viettel',
    '27.66.': 'Viettel',
    '27.67.': 'Viettel',
    // IPv6 Việt Nam
    '2405:4800': 'Viettel',
    '2405:8a00': 'VNPT',
    '2405:8a00': 'FPT',
    '2405:9700': 'MobiFone',
    '2405:9800': 'Vinaphone'
  };
  
  for (const [range, isp] of Object.entries(ipRanges)) {
    if (ip.startsWith(range)) {
      return {
        name: isp,
        organization: currentISP.organization || isp,
        asn: currentISP.asn,
        asnName: currentISP.asnName
      };
    }
  }
  
  return currentISP;
}

function convertVNProvince(provinceCode) {
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

function convertVNCity(city, province) {
  if (!city) return null;
  
  // Nếu đã có tên tỉnh trong city, không cần thêm
  if (city.includes(province)) return city;
  
  // Thêm tỉnh cho các thành phố nhỏ
  const majorCities = ['Hà Nội', 'Hải Phòng', 'Đà Nẵng', 'Cần Thơ', 'TP Hồ Chí Minh'];
  if (!majorCities.includes(province)) {
    return `${city}, ${province}`;
  }
  
  return city;
}

function getCountryName(countryCode) {
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
    'AU': 'Australia'
  };
  
  return countries[countryCode] || countryCode;
}

function getConnectionType(cf) {
  if (cf.mobileCarrier) return 'Mobile';
  if (cf.clientTcpRtt && cf.clientTcpRtt < 50) return 'Wired/Fiber';
  if (cf.clientTcpRtt) return 'Wired';
  return 'Unknown';
}

function parseUserAgent(ua) {
  if (!ua) return {};
  
  const browserInfo = {
    name: 'Unknown',
    version: 'Unknown',
    os: 'Unknown',
    device: 'Desktop'
  };
  
  // Đơn giản hóa - trong thực tế có thể dùng library như ua-parser-js
  if (ua.includes('Chrome')) browserInfo.name = 'Chrome';
  else if (ua.includes('Firefox')) browserInfo.name = 'Firefox';
  else if (ua.includes('Safari')) browserInfo.name = 'Safari';
  else if (ua.includes('Edge')) browserInfo.name = 'Edge';
  else if (ua.includes('Opera')) browserInfo.name = 'Opera';
  
  if (ua.includes('Windows')) browserInfo.os = 'Windows';
  else if (ua.includes('Mac OS')) browserInfo.os = 'macOS';
  else if (ua.includes('Linux')) browserInfo.os = 'Linux';
  else if (ua.includes('Android')) {
    browserInfo.os = 'Android';
    browserInfo.device = 'Mobile';
  } else if (ua.includes('iPhone') || ua.includes('iPad')) {
    browserInfo.os = 'iOS';
    browserInfo.device = ua.includes('iPad') ? 'Tablet' : 'Mobile';
  }
  
  return browserInfo;
}
