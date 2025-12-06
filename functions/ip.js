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
    // Lấy IP từ nhiều nguồn khác nhau
    const ip = request.headers.get('cf-connecting-ip') || 
                request.headers.get('x-real-ip') ||
                request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
                'Unknown';

    const country = request.headers.get('cf-ipcountry') || 'Unknown';
    const userAgent = request.headers.get('user-agent') || 'Unknown';
    
    // Kiểm tra phiên bản IP
    const ipVersion = detectIPVersion(ip);
    
    // Sử dụng dữ liệu địa lý từ Cloudflare nếu có
    const cfData = request.cf || {};
    
    try {
      if (ip && ip !== 'Unknown' && isValidIP(ip)) {
        let geoData = {};
        let providerData = {};
        
        // Thử dịch vụ GeoIP đầu tiên (ipapi.co)
        try {
          const geoResponse = await fetch(`https://ipapi.co/${ip}/json/`, {
            headers: { 'User-Agent': 'CheckTools/1.0' },
            signal: AbortSignal.timeout(3000)
          });

          if (geoResponse.ok) {
            geoData = await geoResponse.json();
          }
        } catch (e) {
          console.log('ipapi.co failed, trying fallback...');
        }
        
        // Nếu không có đủ thông tin, thử dịch vụ thứ hai (ipwho.is)
        if (!geoData.city || !geoData.region) {
          try {
            const ipwhoResponse = await fetch(`https://ipwho.is/${ip}`, {
              signal: AbortSignal.timeout(3000)
            });
            
            if (ipwhoResponse.ok) {
              const ipwhoData = await ipwhoResponse.json();
              if (ipwhoData.success) {
                // Kết hợp dữ liệu
                geoData = {
                  ...geoData,
                  city: geoData.city || ipwhoData.city,
                  region: geoData.region || ipwhoData.region,
                  region_code: geoData.region_code || ipwhoData.region_code,
                  country_name: geoData.country_name || ipwhoData.country,
                  country_code: geoData.country_code || ipwhoData.country_code,
                  latitude: geoData.latitude || ipwhoData.latitude,
                  longitude: geoData.longitude || ipwhoData.longitude,
                  timezone: geoData.timezone || ipwhoData.timezone?.id,
                  org: geoData.org || ipwhoData.connection?.org,
                  isp: geoData.isp || ipwhoData.connection?.isp,
                  asn: geoData.asn || ipwhoData.connection?.asn
                };
              }
            }
          } catch (e) {
            console.log('ipwho.is failed');
          }
        }
        
        // Thử lấy thông tin nhà cung cấp từ IPInfo
        if (!geoData.org && !geoData.isp) {
          try {
            const ipinfoResponse = await fetch(`https://ipinfo.io/${ip}/json?token=free`, {
              signal: AbortSignal.timeout(2000)
            });
            
            if (ipinfoResponse.ok) {
              const ipinfoData = await ipinfoResponse.json();
              providerData = {
                org: ipinfoData.org || geoData.org,
                hostname: ipinfoData.hostname,
                anycast: ipinfoData.anycast
              };
            }
          } catch (e) {
            console.log('ipinfo.io failed');
          }
        }
        
        // Xác định tỉnh/thành phố từ dữ liệu có sẵn
        let province = geoData.region || cfData.region || null;
        let city = geoData.city || cfData.city || null;
        
        // Xử lý đặc biệt cho Việt Nam
        if ((geoData.country_code === 'VN' || country === 'VN') && province) {
          // Chuyển đổi region thành tên tỉnh/thành phố tiếng Việt
          province = convertVNProvince(province);
          if (city) {
            city = convertVNCity(city, province);
          }
        }
        
        // Xác định nhà cung cấp dịch vụ
        let isp = determineISP(geoData.org || geoData.isp || providerData.org, ip);
        
        return new Response(
          JSON.stringify({
            ip: ip,
            version: ipVersion,
            country: geoData.country_name || cfData.country || country,
            countryCode: geoData.country_code || cfData.country || country,
            province: province,
            city: city,
            district: geoData.district || null,
            latitude: geoData.latitude || cfData.latitude || null,
            longitude: geoData.longitude || cfData.longitude || null,
            timezone: geoData.timezone || cfData.timezone || null,
            postalCode: geoData.postal || cfData.postalCode || null,
            isp: isp,
            organization: geoData.org || providerData.org || null,
            asn: geoData.asn || providerData.asn || null,
            connectionType: cfData.clientTcpRtt ? 'Wired' : null,
            mobileCarrier: cfData.mobileCarrier || null,
            userAgent: userAgent,
            cloudflareData: {
              colo: cfData.colo || null,
              region: cfData.region || null,
              city: cfData.city || null,
              metroCode: cfData.metroCode || null
            },
            timestamp: new Date().toISOString()
          }),
          { status: 200, headers: corsHeaders }
        );
      }
    } catch (geoError) {
      console.error('GeoIP lookup failed:', geoError);
    }

    // Fallback response với dữ liệu cơ bản
    return new Response(
      JSON.stringify({
        ip: ip,
        version: ipVersion,
        country: cfData.country || country,
        countryCode: cfData.country || country,
        province: cfData.region || null,
        city: cfData.city || null,
        isp: determineISP(null, ip),
        userAgent: userAgent,
        timestamp: new Date().toISOString(),
        note: 'Limited information available'
      }),
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({ 
        error: err.message,
        message: 'Cannot get IP information'
      }),
      { status: 500, headers: corsHeaders }
    );
  }
}

// Helper functions
function detectIPVersion(ip) {
  if (!ip || ip === 'Unknown') return 'Unknown';
  
  // IPv6 có chứa dấu :
  if (ip.includes(':')) {
    // Kiểm tra IPv6 đầy đủ
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))/;
    return ipv6Regex.test(ip) ? 'IPv6' : 'Unknown';
  }
  
  // IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip) ? 'IPv4' : 'Unknown';
}

function isValidIP(ip) {
  const ipVersion = detectIPVersion(ip);
  return ipVersion === 'IPv4' || ipVersion === 'IPv6';
}

function convertVNProvince(provinceCode) {
  const provinceMap = {
    // Miền Bắc
    'HN': 'Hà Nội',
    'HP': 'Hải Phòng',
    'QN': 'Quảng Ninh',
    'BG': 'Bắc Giang',
    'BN': 'Bắc Ninh',
    'HB': 'Hòa Bình',
    'HND': 'Hà Nam', // Thêm code giả định
    'ND': 'Nam Định',
    'TB': 'Thái Bình',
    'NB': 'Ninh Bình',
    'LC': 'Lào Cai',
    'YB': 'Yên Bái',
    'PT': 'Phú Thọ',
    'VP': 'Vĩnh Phúc',
    'TQ': 'Tuyên Quang',
    'HG': 'Hà Giang',
    'CB': 'Cao Bằng',
    'BK': 'Bắc Kạn',
    'TN': 'Thái Nguyên',
    'LS': 'Lạng Sơn',
    
    // Miền Trung
    'TH': 'Thanh Hóa',
    'NA': 'Nghệ An',
    'HT': 'Hà Tĩnh',
    'QB': 'Quảng Bình',
    'QT': 'Quảng Trị',
    'HUE': 'Thừa Thiên Huế',
    'DN': 'Đà Nẵng',
    'QN': 'Quảng Nam',
    'QNG': 'Quảng Ngãi',
    'BD': 'Bình Định',
    'PY': 'Phú Yên',
    'KH': 'Khánh Hòa',
    'NT': 'Ninh Thuận',
    'BT': 'Bình Thuận',
    
    // Miền Nam
    'HCM': 'Thành phố Hồ Chí Minh',
    'DN': 'Đồng Nai',
    'VT': 'Bà Rịa - Vũng Tàu',
    'BT': 'Bình Thuận', // Trùng, cần kiểm tra
    'BP': 'Bình Phước',
    'BD': 'Bình Dương',
    'TNI': 'Tây Ninh',
    'LA': 'Long An',
    'TG': 'Tiền Giang',
    'BT': 'Bến Tre',
    'TV': 'Trà Vinh',
    'VL': 'Vĩnh Long',
    'DD': 'Đồng Tháp',
    'AG': 'An Giang',
    'KG': 'Kiên Giang',
    'CT': 'Cần Thơ',
    'HG': 'Hậu Giang',
    'ST': 'Sóc Trăng',
    'BL': 'Bạc Liêu',
    'CM': 'Cà Mau'
  };
  
  return provinceMap[provinceCode.toUpperCase()] || provinceCode;
}

function convertVNCity(cityName, province) {
  // Thêm hậu tố cho các thành phố thuộc tỉnh
  const citySuffixes = {
    'Hà Nội': 'Thủ đô',
    'Hải Phòng': 'Thành phố',
    'Đà Nẵng': 'Thành phố',
    'Cần Thơ': 'Thành phố',
    'Thành phố Hồ Chí Minh': 'Thành phố'
  };
  
  if (citySuffixes[province]) {
    return `${cityName} (${citySuffixes[province]})`;
  }
  
  return cityName;
}

function determineISP(org, ip) {
  if (!org) {
    // Dự đoán ISP từ IP range (cho Việt Nam)
    if (ip.startsWith('14.')) return 'VNPT';
    if (ip.startsWith('27.')) return 'Viettel';
    if (ip.startsWith('42.')) return 'Viettel';
    if (ip.startsWith('58.')) return 'FPT';
    if (ip.startsWith('113.')) return 'VNPT';
    if (ip.startsWith('115.')) return 'Viettel';
    if (ip.startsWith('116.')) return 'Viettel';
    if (ip.startsWith('117.')) return 'VNPT';
    if (ip.startsWith('118.')) return 'VNPT';
    if (ip.startsWith('123.')) return 'FPT';
    if (ip.startsWith('125.')) return 'Viettel';
    if (ip.startsWith('171.')) return 'CMC';
    if (ip.startsWith('175.')) return 'Viettel';
    if (ip.startsWith('180.')) return 'VNPT';
    if (ip.startsWith('183.')) return 'Viettel';
    if (ip.startsWith('210.')) return 'Viettel';
    if (ip.startsWith('222.')) return 'Viettel';
    if (ip.startsWith('240.')) return 'MobiFone';
    if (ip.startsWith('27.64.')) return 'Viettel';
    if (ip.startsWith('27.65.')) return 'Viettel';
    if (ip.startsWith('27.66.')) return 'Viettel';
    if (ip.startsWith('27.67.')) return 'Viettel';
    
    // IPv6 ranges cho Việt Nam
    if (ip.startsWith('2405:4800')) return 'Viettel';
    if (ip.startsWith('2405:8a00')) return 'VNPT';
    if (ip.startsWith('2405:8a00')) return 'FPT';
    
    return 'Unknown';
  }
  
  org = org.toLowerCase();
  
  // Phát hiện ISP Việt Nam
  if (org.includes('viettel')) return 'Viettel';
  if (org.includes('vnpt')) return 'VNPT';
  if (org.includes('fpt')) return 'FPT';
  if (org.includes('mobifone')) return 'MobiFone';
  if (org.includes('vinaphone')) return 'Vinaphone';
  if (org.includes('cmc')) return 'CMC';
  if (org.includes('vietnamobile')) return 'Vietnamobile';
  if (org.includes('gtelecom')) return 'GTelecom';
  if (org.includes('netnam')) return 'Netnam';
  
  // Phát hiện ISP quốc tế
  if (org.includes('google')) return 'Google Cloud';
  if (org.includes('amazon')) return 'AWS';
  if (org.includes('microsoft')) return 'Microsoft Azure';
  if (org.includes('cloudflare')) return 'Cloudflare';
  if (org.includes('digitalocean')) return 'DigitalOcean';
  if (org.includes('linode')) return 'Linode';
  if (org.includes('ovh')) return 'OVH';
  if (org.includes('alibaba')) return 'Alibaba Cloud';
  if (org.includes('tencent')) return 'Tencent Cloud';
  
  return org;
}

