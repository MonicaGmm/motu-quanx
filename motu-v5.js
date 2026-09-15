/*************************************************************
 * 摩途 会员解锁 / 去广告 —— Quantumult X 重写脚本
 *
 * 适用版本：摩途 motumap 4.2.0+（2026-07 之后启用加密通道的版本）
 * 抓包时间：2026-09-15
 *
 * 【为什么旧脚本失效】
 * 旧脚本改的是明文接口 /v3/user/info。
 * 4.2.0 起「我的」「会员中心」等页面改为调用加密接口
 *   POST /v1/user/infoSec        （用户信息，含 isPro / memEndTime）
 *   POST /v1/user/userCarListSec （车辆列表）
 *   POST /v1/poi/mapShowAreaSec  （地图 POI）
 * 服务端 RSA 下发密钥 + AES-GCM 会话密钥加密，明文接口不再被调用，
 * 所以只改响应体的旧写法完全打不中了。
 *
 * 【本脚本原理】(安全信道中间人)
 *   1. 改写 /api/security/public-key，把服务端 RSA 公钥换成脚本内置的公钥；
 *   2. App 于是把「本次会话的 AES 密钥」用我们的公钥加密后发出，
 *      请求脚本用内置私钥解出该 AES 会话密钥，并把它重新用「服务端真公钥」
 *      加密后原样转发（服务端照常工作，其它接口不受影响）；
 *   3. 响应脚本用该 AES 密钥解密服务端响应 -> 修改会员字段 -> 重新
 *      AES-GCM 加密并重新签名返回。
 *
 *   密钥长度、填充方式、AES 模式、AAD、签名算法均采用「运行时自校准」：
 *   用抓到的真实请求做零知识验证（GCM 认证标签本身就是校验器），
 *   命中后写入持久化缓存，后续请求不再重复试探。
 *
 * 【安全说明】
 *   内置 RSA 私钥仅用于本机中间人，不涉及任何第三方账号凭据。
 *   脚本不会上传、上报任何用户数据。
 *
 * 仅供学习交流，请于下载后 24 小时内删除，请勿转载贩卖。
 *
 * ---------------------------- QX 配置 ----------------------------
 * [rewrite_local]
 * # 摩途 · 安全信道中间人（顺序不能颠倒）
 * ^https:\/\/motu\.motumap\.com\/api\/security\/public-key url script-response-body https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu-v5.js
 * ^https:\/\/motu\.motumap\.com\/v\d+\/.*Sec url script-request-body  https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu-v5.js
 * ^https:\/\/motu\.motumap\.com\/v\d+\/.*Sec url script-response-body https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu-v5.js
 * # 摩途 · 去广告（穿山甲 Pangle / 优量汇 GDT）
 * ^https?:\/\/api-access\.pangolin-sdk-toutiao\.com\/api\/ad\/ url reject-dict
 * ^https?:\/\/api-access\.pangolin-sdk-toutiao\d?\.com\/api\/ad\/ url reject-dict
 * ^https?:\/\/mi\.gdt\.qq\.com url reject-dict
 *
 * [mitm]
 * hostname = motu.motumap.com
 * ----------------------------------------------------------------
 *************************************************************/

'use strict';

var CFG = {
  // 解锁会员
  enableVip: true,
  // 是否在首次自动校准时发通知（调试用，可关）
  notifyCalibrate: true,
  // 会员到期时间：4102415999 = 2099-12-31
  memEndTime: 4102415999
};

var PREF_KEY = 'motu_sec_state_v1';
var SCRIPT_VER = 'motu-qx-5';      // 版本水印（会写进 /api/security/public-key 响应，抓包里可核对）

/* 2026-09 实测确认的加密方案（由抓包 + 客户端二进制字符串双重验证）：
     RSA   : RSA/ECB/OAEPWithSHA-256AndMGF1Padding（App 报错文案亦为
             "RSA key does not support OAEP-SHA256 encryption."）
             encryptedKey = RSA( base64 文本 )，该文本解码后即 AES 密钥
     AES   : AES-256-GCM（CryptoKit AES.GCM.seal(_:using:nonce:authenticating:)）
             iv   = base64 解码后 12 字节
             AAD  = /api/security/public-key 返回的 salt 字符串 ★关键
             data = base64( 密文 ‖ 16 字节 tag )
   明文即业务参数 JSON（infoSec 无参时为 "{}"，2 字节 -> 16+2=18 字节，与抓包一致）
   另外服务端会校验 sign（伪造会被 400 "sign invalid"），但我们的改写
   不动 data/iv/nonce/timestamp，App 自己算好的 sign 依然有效，故原样保留。 */
var KNOWN_SALT_B64 = 'TW90dVNlY3VyZUFwaVYyU2FsdDIwMjYwNzIy';   // salt 兜底值

/* ============================================================
 * 0. 内置密钥
 * ============================================================ */

// 我们自己的 RSA-2048 公钥（X.509 / SPKI，base64），将替换服务端下发的公钥
var OUR_PUBLIC_KEY_B64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuWt35akS2Bp1AuqLCz4/ACu/0KQcSBYudaIzJBufDIK59ZAVlLD437N5M1174/AEE9+QcdkF/olLpuDC0UYgkLVOdm+Oe8jDi0CqjIdAmvQ7LQwbULn0eAQNIV+pjNKI17pfnnVc6vPjQia48/fTwb/A3pQTs0Sb6OhcikfoAlh3oKsSxGovEyMb7qp78YAMoT6E3REjOOEoGtzfmnFGBDebx4XFP6M58TvfqYiNsCV3cS7+92BG+m1qtpykxup5UlX3STNCiwysW0n8Xp7H1nMme0seZOnRt3NTvg8RJoGN+aCm4Vdb9zggtwRze8jYemd6HYpsi2VURFDfo1hcMQIDAQAB';
var OUR_N = 'b96b77e5a912d81a7502ea8b0b3e3f002bbfd0a41c48162e75a233241b9f0c82b9f5901594b0f8dfb379335d7be3f00413df9071d905fe894ba6e0c2d1462090b54e766f8e7bc8c38b40aa8c87409af43b2d0c1b50b9f478040d215fa98cd288d7ba5f9e755ceaf3e34226b8f3f7d3c1bfc0de9413b3449be8e85c8a47e8025877a0ab12c46a2f13231beeaa7bf1800ca13e84dd112338e1281adcdf9a714604379bc785c53fa339f13bdfa9888db02577712efef76046fa6d6ab69ca4c6ea795255f74933428b0cac5b49fc5e9ec7d673267b4b1e64e9d1b77353be0f1126818df9a0a6e1575bf73820b704737bc8d87a677a1d8a6c8b65544450dfa3585c31';
var OUR_D = '4ee8260fc0d5a7afd38db1427acd829048f182e6feb0596adddd8c7434db3385fc9d3cfb0e93251d633506435ebce8e77dff5ef9141b4e453bc1f3564a472a22dccc957de3fa3b67a6b07ac76f72399b99934af73871b16d28bdfbf5e49533e6ebe772ad439a1c9b91293218838190550e3730817e5284d1d4afb8792075ff337b9a97194cf07465315d678d4aa3b6b74275ec16758eb89665316cb3f0ec1cd6c70c432cc29649e4d54ce7c3d127ecf2b4c39c4460c96b6b874e44f1881e9b63688202f50d352b6a9fb77e0bc078d4f00350ddb642b822d35ac498435fd117d22ed9b5e5054f658477ba1f0ac2a4564d8a476ab377e4e99d6e7c00a8666bbb';

// 服务端真公钥（keyId=1），用于把请求按原样转回服务端
var SRV_KEY = {
  '1': { n: 'cce0846d1b87d473954f6db44b937f7244b0637a70f32fb05c6dbceb4e6322ca8af400fa814b4dac002e8dc8e60f530ef105cbe113e252fca4ae96555c728972e015feb219e53aad148272e77c563b501929f124f97c335929bdce152f437008128b3e3246104a349d994971b2929a8ae83d3bd97c09dceb337c12f91d92a55772532074ca366cbdf14ccc8cc3eda0b9c749b5e3c2abcf41d609a46f62451f8c24ea882f760c13c8d0ea7929a26811ff6aea323c91056ed59e586f5b2799ef3051aa1757fee75052b919f70635c79c3bcc8891b9cff50658461d3740954e471241dae5da9ebf862573810eebe71ca98273863016f47f00f2d183cb111ded12db', e: '10001' }
};

/* ============================================================
 * 1. 基础编解码
 * ============================================================ */

var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64Decode(str) {
  str = String(str == null ? '' : str).replace(/[^A-Za-z0-9+/=]/g, '');
  var out = [], buf = 0, bits = 0, i, v;
  for (i = 0; i < str.length; i++) {
    if (str.charAt(i) === '=') break;
    v = B64C.indexOf(str.charAt(i));
    if (v < 0) continue;
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); buf &= (1 << bits) - 1; }
  }
  return new Uint8Array(out);
}

function b64Encode(bytes) {
  var out = '', buf = 0, bits = 0, i, v;
  for (i = 0; i < bytes.length; i++) {
    buf = (buf << 8) | (bytes[i] & 0xff); bits += 8;
    while (bits >= 6) { bits -= 6; out += B64C.charAt((buf >> bits) & 0x3f); }
    buf &= (1 << bits) - 1;
  }
  if (bits > 0) out += B64C.charAt((buf << (6 - bits)) & 0x3f);
  while (out.length % 4) out += '=';
  return out;
}

function b64Url(bytes) {
  return b64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function strToBytes(s) {                       // UTF-8 编码
  var out = [], i, c;
  s = String(s);
  for (i = 0; i < s.length; i++) {
    c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      var c2 = s.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        var u = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        out.push(0xf0 | (u >> 18), 0x80 | ((u >> 12) & 0x3f), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f));
        i++; continue;
      }
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
  }
  return new Uint8Array(out);
}

function bytesToStr(b) {                       // UTF-8 解码
  var out = '', i = 0, c, c2, c3, c4;
  while (i < b.length) {
    c = b[i++];
    if (c < 0x80) out += String.fromCharCode(c);
    else if (c >= 0xc0 && c < 0xe0) { c2 = b[i++]; out += String.fromCharCode(((c & 0x1f) << 6) | (c2 & 0x3f)); }
    else if (c >= 0xe0 && c < 0xf0) { c2 = b[i++]; c3 = b[i++]; out += String.fromCharCode(((c & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f)); }
    else { c2 = b[i++]; c3 = b[i++]; c4 = b[i++]; var u = ((c & 0x07) << 18) | ((c2 & 0x3f) << 12) | ((c3 & 0x3f) << 6) | (c4 & 0x3f); u -= 0x10000; out += String.fromCharCode(0xd800 + (u >> 10), 0xdc00 + (u & 0x3ff)); }
  }
  return out;
}

function hexToBytes(h) {
  var out = new Uint8Array(h.length >> 1), i;
  for (i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) {
  var out = '', i;
  for (i = 0; i < b.length; i++) out += (b[i] < 16 ? '0' : '') + b[i].toString(16);
  return out;
}
function concatBytes() {                       // concatBytes(a, b, c ...)
  var total = 0, i, j, k = 0, out;
  for (i = 0; i < arguments.length; i++) total += arguments[i] ? arguments[i].length : 0;
  out = new Uint8Array(total);
  for (i = 0; i < arguments.length; i++) { var a = arguments[i]; if (!a) continue; for (j = 0; j < a.length; j++) out[k++] = a[j]; }
  return out;
}
function eqBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function randBytes(n) {
  var out = new Uint8Array(n), i;
  for (i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

/* ============================================================
 * 2. 哈希：SHA-256 / SHA-1 / HMAC-SHA256
 * ============================================================ */

var K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

function sha256(bytes) {
  var H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  var len = bytes.length, padLen = ((len + 9 + 63) >> 6) << 6;
  var msg = new Uint8Array(padLen); msg.set(bytes); msg[len] = 0x80;
  var bits = len * 8, hi = Math.floor(bits / 4294967296), lo = (bits >>> 0);
  msg[padLen - 8] = (hi >>> 24) & 255; msg[padLen - 7] = (hi >>> 16) & 255; msg[padLen - 6] = (hi >>> 8) & 255; msg[padLen - 5] = hi & 255;
  msg[padLen - 4] = (lo >>> 24) & 255; msg[padLen - 3] = (lo >>> 16) & 255; msg[padLen - 2] = (lo >>> 8) & 255; msg[padLen - 1] = lo & 255;
  var W = new Uint32Array(64), i, t;
  for (t = 0; t < padLen; t += 64) {
    for (i = 0; i < 16; i++) W[i] = (msg[t + i * 4] << 24) | (msg[t + i * 4 + 1] << 16) | (msg[t + i * 4 + 2] << 8) | msg[t + i * 4 + 3];
    for (i = 16; i < 64; i++) {
      var w15 = W[i - 15], w2 = W[i - 2];
      var s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      var s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var t1 = (h + S1 + ch + K256[i] + W[i]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  var out = new Uint8Array(32);
  for (i = 0; i < 8; i++) { out[i * 4] = (H[i] >>> 24) & 255; out[i * 4 + 1] = (H[i] >>> 16) & 255; out[i * 4 + 2] = (H[i] >>> 8) & 255; out[i * 4 + 3] = H[i] & 255; }
  return out;
}

function sha1(bytes) {
  var H = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
  var len = bytes.length, padLen = ((len + 9 + 63) >> 6) << 6;
  var msg = new Uint8Array(padLen); msg.set(bytes); msg[len] = 0x80;
  var bits = len * 8, hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
  msg[padLen - 8] = (hi >>> 24) & 255; msg[padLen - 7] = (hi >>> 16) & 255; msg[padLen - 6] = (hi >>> 8) & 255; msg[padLen - 5] = hi & 255;
  msg[padLen - 4] = (lo >>> 24) & 255; msg[padLen - 3] = (lo >>> 16) & 255; msg[padLen - 2] = (lo >>> 8) & 255; msg[padLen - 1] = lo & 255;
  var W = new Uint32Array(80), i, t;
  var rotl = function (x, n) { return ((x << n) | (x >>> (32 - n))) | 0; };
  for (t = 0; t < padLen; t += 64) {
    for (i = 0; i < 16; i++) W[i] = (msg[t + i * 4] << 24) | (msg[t + i * 4 + 1] << 16) | (msg[t + i * 4 + 2] << 8) | msg[t + i * 4 + 3];
    for (i = 16; i < 80; i++) W[i] = rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f, k, tmp;
    for (i = 0; i < 80; i++) {
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      tmp = (rotl(a, 5) + f + e + k + W[i]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0;
  }
  var out = new Uint8Array(20);
  for (i = 0; i < 5; i++) { out[i * 4] = (H[i] >>> 24) & 255; out[i * 4 + 1] = (H[i] >>> 16) & 255; out[i * 4 + 2] = (H[i] >>> 8) & 255; out[i * 4 + 3] = H[i] & 255; }
  return out;
}

function hmacSha256(key, msg) {
  var k = key.length > 64 ? sha256(key) : key;
  var ipad = new Uint8Array(64), opad = new Uint8Array(64), i;
  for (i = 0; i < 64; i++) { ipad[i] = 0x36; opad[i] = 0x5c; }
  for (i = 0; i < k.length; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
  return sha256(concatBytes(opad, sha256(concatBytes(ipad, msg))));
}

function digestByName(name, key, msg) {
  if (name === 'sha256') return sha256(msg);
  if (name === 'sha1') return sha1(msg);
  if (name === 'hmac-sha256') return hmacSha256(key, msg);
  return null;
}

/* ============================================================
 * 3. AES（128/192/256）+ GCM
 * ============================================================ */

var SBOX = new Uint8Array(256);
(function () {
  function mul(a, b) { var p = 0, i; for (i = 0; i < 8; i++) { if (b & 1) p ^= a; var hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1; } return p; }
  var i, j, x, y, inv;
  var invTab = new Uint8Array(256);
  for (i = 1; i < 256; i++) for (j = 1; j < 256; j++) if (mul(i, j) === 1) { invTab[i] = j; break; }
  invTab[0] = 0;
  for (i = 0; i < 256; i++) {
    x = invTab[i]; y = x;
    y ^= ((x << 1) | (x >>> 7)) & 0xff;
    y ^= ((x << 2) | (x >>> 6)) & 0xff;
    y ^= ((x << 3) | (x >>> 5)) & 0xff;
    y ^= ((x << 4) | (x >>> 4)) & 0xff;
    y ^= 0x63;
    SBOX[i] = y & 0xff;
  }
})();

function xt(a) { a <<= 1; return (a & 0x100) ? ((a ^ 0x1b) & 0xff) : (a & 0xff); }
function mul2(a) { return xt(a); }
function mul3(a) { return xt(a) ^ a; }

function aesKeySchedule(key) {
  var Nk = key.length >> 2, Nr = Nk + 6;
  var w = new Uint8Array(16 * (Nr + 1));
  w.set(key);
  var rcon = 1, i, t0, t1, t2, t3, tmp;
  for (i = Nk; i < 4 * (Nr + 1); i++) {
    t0 = w[4 * (i - 1)]; t1 = w[4 * (i - 1) + 1]; t2 = w[4 * (i - 1) + 2]; t3 = w[4 * (i - 1) + 3];
    if (i % Nk === 0) {
      tmp = t0; t0 = SBOX[t1] ^ rcon; t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[tmp];
      rcon = xt(rcon);
    } else if (Nk > 6 && i % Nk === 4) {
      t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
    }
    w[4 * i] = w[4 * (i - Nk)] ^ t0;
    w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ t1;
    w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ t2;
    w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ t3;
  }
  return { rk: w, Nr: Nr };
}

function aesEncryptBlock(ks, inp) {
  var s = new Uint8Array(16), t = new Uint8Array(16), out = new Uint8Array(16);
  var rk = ks.rk, Nr = ks.Nr, i, r, c, a0, a1, a2, a3;
  for (i = 0; i < 16; i++) s[i] = inp[i] ^ rk[i];
  for (r = 1; r < Nr; r++) {
    for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];
    s[0] = t[0]; s[4] = t[4]; s[8] = t[8]; s[12] = t[12];
    s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
    s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
    for (c = 0; c < 4; c++) {
      a0 = s[4 * c]; a1 = s[4 * c + 1]; a2 = s[4 * c + 2]; a3 = s[4 * c + 3];
      s[4 * c] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
      s[4 * c + 1] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
      s[4 * c + 2] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
      s[4 * c + 3] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
    for (i = 0; i < 16; i++) s[i] ^= rk[16 * r + i];
  }
  for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];
  s[0] = t[0]; s[4] = t[4]; s[8] = t[8]; s[12] = t[12];
  s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
  s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
  s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
  for (i = 0; i < 16; i++) out[i] = s[i] ^ rk[16 * Nr + i];
  return out;
}

/* --- GF(2^128) 乘法 / GHASH --- */
function gfMul(X, Y) {
  var Z = new Uint8Array(16), V = new Uint8Array(16), i, j, lsb;
  V.set(Y);
  for (i = 0; i < 128; i++) {
    if (X[i >> 3] & (0x80 >> (i & 7))) for (j = 0; j < 16; j++) Z[j] ^= V[j];
    lsb = V[15] & 1;
    for (j = 15; j > 0; j--) V[j] = ((V[j] >> 1) | ((V[j - 1] & 1) << 7)) & 0xff;
    V[0] = V[0] >> 1;
    if (lsb) V[0] ^= 0xe1;
  }
  return Z;
}
function ghash(H, data) {
  var Y = new Uint8Array(16), i, j, X;
  for (i = 0; i < data.length; i += 16) {
    X = new Uint8Array(16);
    for (j = 0; j < 16; j++) X[j] = Y[j] ^ data[i + j];
    Y = gfMul(X, H);
  }
  return Y;
}

// 64 位大端写入（>>> 位移量取模 32，不能直接做 64 位写入）
function putU64Be(buf, off, v) {
  var hi = Math.floor(v / 4294967296), lo = v % 4294967296;
  buf[off] = (hi >>> 24) & 255; buf[off + 1] = (hi >>> 16) & 255; buf[off + 2] = (hi >>> 8) & 255; buf[off + 3] = hi & 255;
  buf[off + 4] = (lo >>> 24) & 255; buf[off + 5] = (lo >>> 16) & 255; buf[off + 6] = (lo >>> 8) & 255; buf[off + 7] = lo & 255;
}

/**
 * GCM 核心。input 经 CTR 变换后输出；tag 始终对「密文」计算。
 * 加密时密文 = 输出，解密时密文 = 输入，故由 tagOver 指定。
 */
function gcmCore(ks, iv, aad, cipher, tagOver) {
  var H = aesEncryptBlock(ks, new Uint8Array(16));
  var J0 = new Uint8Array(16), i;
  if (iv.length === 12) { J0.set(iv); J0[15] = 1; }
  else {
    // 非 12 字节 IV：GHASH 构造
    var pad = (16 - (iv.length % 16)) % 16;
    var blk = concatBytes(iv, new Uint8Array(pad + 8 + 8));
    blk[blk.length - 8] = ((iv.length * 8) >>> 8) & 255; blk[blk.length - 7] = (iv.length * 8) & 255;
    J0 = ghash(H, blk);
  }
  // CTR 加密
  var ct = new Uint8Array(cipher.length), ctr = new Uint8Array(16);
  ctr.set(J0);
  var off = 0, n, c;
  while (off < cipher.length) {
    // inc32
    for (i = 15; i >= 12; i--) { ctr[i] = (ctr[i] + 1) & 0xff; if (ctr[i] !== 0) break; }
    var ksBlock = aesEncryptBlock(ks, ctr);
    n = Math.min(16, cipher.length - off);
    for (i = 0; i < n; i++) ct[off + i] = cipher[off + i] ^ ksBlock[i];
    off += 16;
  }
  // GHASH 计算 tag
  var aadPad = (16 - (aad.length % 16)) % 16;
  var dataPad = (16 - (cipher.length % 16)) % 16;
  var tail = new Uint8Array(16);
  // 注意：JS 的 >>> 位移量会取模 32，不能直接用来做 64 位大端写入
  putU64Be(tail, 0, aad.length * 8);      // len(A) 比特
  putU64Be(tail, 8, cipher.length * 8);   // len(C) 比特
  var authCt = tagOver || ct;             // 参与认证的密文
  var S = ghash(H, concatBytes(aad, new Uint8Array(aadPad), authCt, new Uint8Array(dataPad), tail));
  var E = aesEncryptBlock(ks, J0);
  var tag = new Uint8Array(16);
  for (i = 0; i < 16; i++) tag[i] = S[i] ^ E[i];
  return { ct: ct, tag: tag };
}

// 返回 {ct, tag}；plaintext 为明文字节
function gcmEncrypt(key, iv, aad, plaintext) {
  return gcmCore(aesKeySchedule(key), iv, aad || new Uint8Array(0), plaintext);
}
// 成功返回明文字节，失败（认证不通过）返回 null
function gcmDecrypt(key, iv, aad, ct, tag) {
  try {
    // 解密时输入即密文，认证对象也是它
    var r = gcmCore(aesKeySchedule(key), iv, aad || new Uint8Array(0), ct, ct);
    return eqBytes(r.tag, tag) ? r.ct : null;
  } catch (e) { return null; }
}

/* ============================================================
 * 4. RSA（BigInt 实现，仅需解密/加密各一次）
 * ============================================================ */

var _bi = null;
function BI() { if (_bi === null) _bi = (typeof BigInt === 'function') ? BigInt : null; return _bi; }
function hexToBig(h) { return BI()('0x' + h); }
function bytesToBig(b) { return hexToBig(bytesToHex(b)); }
function bigToBytes(x, len) {
  var h = x.toString(16);
  if (h.length % 2) h = '0' + h;
  while (h.length < len * 2) h = '00' + h;
  return hexToBytes(h);
}
function modPow(base, exp, mod) {
  var r = BI()(1), b = base % mod, e = exp;
  while (e > BI()(0)) {
    if (e & BI()(1)) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= BI()(1);
  }
  return r;
}
function rsaRawDecrypt(cBytes) {
  // m = c^d mod n  （PKCS#1 解密的第一步）
  var n = hexToBig(OUR_N), d = hexToBig(OUR_D);
  var m = modPow(bytesToBig(cBytes), d, n);
  return bigToBytes(m, 256);
}
function rsaRawEncryptTo(nHex, eHex, mBytes) {
  var n = hexToBig(nHex), e = hexToBig(eHex);
  var c = modPow(bytesToBig(mBytes), e, n);
  return bigToBytes(c, 256);
}

/* --- MGF1 --- */
function mgf1(seed, maskLen, hashName) {
  var out = new Uint8Array(maskLen), counter = 0, off = 0, d;
  while (off < maskLen) {
    var cb = new Uint8Array(4);
    cb[0] = (counter >>> 24) & 255; cb[1] = (counter >>> 16) & 255; cb[2] = (counter >>> 8) & 255; cb[3] = counter & 255;
    d = digestByName(hashName, null, concatBytes(seed, cb));
    for (var i = 0; i < d.length && off < maskLen; i++) out[off++] = d[i];
    counter++;
  }
  return out;
}

/* --- PKCS#1 v1.5 解填充：00 02 PS 00 M --- */
function pkcs1Unpad(m) {
  if (m[0] !== 0x00 || m[1] !== 0x02) return null;
  var i = 2;
  while (i < m.length && m[i] !== 0) i++;
  if (i >= m.length - 1) return null;
  if (i - 2 < 8) return null;            // PKCS#1 要求 PS 至少 8 字节（也顺带压掉误判）
  return m.slice(i + 1);
}
function pkcs1Pad(msg, k) {
  if (msg.length > k - 11) return null;
  var ps = new Uint8Array(k - msg.length - 3), i;
  for (i = 0; i < ps.length; i++) { var v; do { v = Math.floor(Math.random() * 256); } while (v === 0); ps[i] = v; }
  return concatBytes(new Uint8Array([0, 2]), ps, new Uint8Array([0]), msg);
}

/* --- OAEP 解填充（hash 与 MGF1 可为不同摘要：Java 的
       OAEPWithSHA-256AndMGF1Padding 默认 MGF1 用 SHA-1） --- */
function oaepUnpad(m, hashName, mgfHashName, label) {
  var hLen = (hashName === 'sha1') ? 20 : 32;
  var k = m.length;
  if (m[0] !== 0x00) return null;
  var maskedSeed = m.slice(1, 1 + hLen);
  var maskedDB = m.slice(1 + hLen);
  var seedMask = mgf1(maskedDB, hLen, mgfHashName);
  var seed = new Uint8Array(hLen), i;
  for (i = 0; i < hLen; i++) seed[i] = maskedSeed[i] ^ seedMask[i];
  var dbMask = mgf1(seed, k - hLen - 1, mgfHashName);
  var DB = new Uint8Array(maskedDB.length);
  for (i = 0; i < DB.length; i++) DB[i] = maskedDB[i] ^ dbMask[i];
  var lHash = digestByName(hashName, null, strToBytes(label || ''));
  for (i = 0; i < hLen; i++) if (DB[i] !== lHash[i]) return null;
  i = hLen;
  while (i < DB.length && DB[i] === 0) i++;
  if (i >= DB.length || DB[i] !== 0x01) return null;
  return DB.slice(i + 1);
}
function oaepPad(msg, k, hashName, mgfHashName, label) {
  var hLen = (hashName === 'sha1') ? 20 : 32;
  if (msg.length > k - 2 * hLen - 2) return null;
  var lHash = digestByName(hashName, null, strToBytes(label || ''));
  var ps = new Uint8Array(k - msg.length - 2 * hLen - 2);
  var DB = concatBytes(lHash, ps, new Uint8Array([0x01]), msg);
  var seed = randBytes(hLen);
  var dbMask = mgf1(seed, k - hLen - 1, mgfHashName);
  var maskedDB = new Uint8Array(DB.length), i;
  for (i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];
  var seedMask = mgf1(maskedDB, hLen, mgfHashName);
  var maskedSeed = new Uint8Array(hLen);
  for (i = 0; i < hLen; i++) maskedSeed[i] = seed[i] ^ seedMask[i];
  return concatBytes(new Uint8Array([0]), maskedSeed, maskedDB);
}

/* 按方案名补填充（方案名取自候选 tag 的 : 前部分） */
function padScheme(tag) { return String(tag).split(':')[0]; }
function padBytes(scheme, bytes) {
  if (scheme === 'oaep-sha256') return oaepPad(bytes, 256, 'sha256', 'sha256', '');
  if (scheme === 'oaep-sha256-mgf1sha1') return oaepPad(bytes, 256, 'sha256', 'sha1', '');
  if (scheme === 'oaep-sha1') return oaepPad(bytes, 256, 'sha1', 'sha1', '');
  return pkcs1Pad(bytes, 256);            // 兜底按最常见的 PKCS#1 v1.5
}

/* --- 解出所有可能的「会话密钥」候选（顺序即优先级） ---
   注意：每个候选都同时带 key（真正用于 AES 的密钥字节）和 payload
   （客户端塞进 RSA 里的原始明文）。改写请求时必须重新加密 payload ——
   实测服务端要的是原样明文（本项目是 base64 文本），不是解码后的裸密钥。 */
function keyCandidates(m) {
  var out = [];
  function push(tag, bytes, payload) {
    if (!bytes || !bytes.length) return;
    if (!(bytes.length === 16 || bytes.length === 24 || bytes.length === 32)) return;
    for (var i = 0; i < out.length; i++) if (out[i].tag === tag) return;
    out.push({ tag: tag, key: bytes, payload: payload || bytes });
  }
  // 解填充后的明文不一定是裸密钥：可能是 base64/hex 文本，或 key||iv 拼接
  function expand(tag, p) {
    if (!p || !p.length) return;
    push(tag, p, p);
    if (p.length <= 32) return;
    push(tag + ':head16', p.slice(0, 16), p);
    push(tag + ':head24', p.slice(0, 24), p);
    push(tag + ':head32', p.slice(0, 32), p);
    push(tag + ':tail16', p.slice(p.length - 16), p);
    push(tag + ':tail24', p.slice(p.length - 24), p);
    push(tag + ':tail32', p.slice(p.length - 32), p);
    var s = bytesToStr(p);
    if (/^[0-9a-fA-F]{32,64}$/.test(s)) push(tag + ':hex', hexToBytes(s), p);
    if (/^[A-Za-z0-9+/=_-]{16,}$/.test(s)) {
      var d = b64Decode(s);
      push(tag + ':b64', d, p);
      if (d.length > 32) {
        push(tag + ':b64:head16', d.slice(0, 16), p);
        push(tag + ':b64:head32', d.slice(0, 32), p);
        push(tag + ':b64:tail16', d.slice(d.length - 16), p);
        push(tag + ':b64:tail32', d.slice(d.length - 32), p);
      }
    }
  }
  var p = pkcs1Unpad(m); if (p) expand('pkcs1', p);
  p = oaepUnpad(m, 'sha256', 'sha256', ''); if (p) expand('oaep-sha256', p);
  p = oaepUnpad(m, 'sha256', 'sha1', ''); if (p) expand('oaep-sha256-mgf1sha1', p);
  p = oaepUnpad(m, 'sha1', 'sha1', ''); if (p) expand('oaep-sha1', p);
  // 最后才是「无填充/未知填充」的兜底猜测（拿不到 payload，只能猜密钥）
  push('raw:tail16', m.slice(m.length - 16));
  push('raw:tail24', m.slice(m.length - 24));
  push('raw:tail32', m.slice(m.length - 32));
  push('raw:head16', m.slice(0, 16));
  push('raw:head32', m.slice(0, 32));
  return out;
}

/* ============================================================
 * 5. 签名自校准
 * ============================================================ */

// 待签字段的排列组合（用抓包里的真实数据反推服务端/客户端签名算法）
function signCandidatesFor(f) {
  var fields = ['data', 'iv', 'nonce', 'timestamp', 'keyId', 'encryptedKey', 'plain'];
  var seps = ['', '|', '&', ',', ':'];
  var perm2 = [];                       // 单字段 + 双字段
  var i, j, k, si;
  for (i = 0; i < fields.length; i++) perm2.push([fields[i]]);
  for (i = 0; i < fields.length; i++) for (j = 0; j < fields.length; j++) if (i !== j) perm2.push([fields[i], fields[j]]);
  // 三元/四元只取常见顺序，控制规模
  var three = [['data', 'iv', 'nonce'], ['data', 'nonce', 'iv'], ['iv', 'nonce', 'data'], ['data', 'iv', 'timestamp'], ['data', 'timestamp', 'nonce'],
    ['timestamp', 'nonce', 'data'], ['nonce', 'timestamp', 'data'], ['iv', 'data', 'nonce'], ['data', 'nonce', 'timestamp'], ['data', 'iv', 'nonce', 'timestamp'], ['data', 'iv', 'nonce', 'timestamp', 'keyId'], ['timestamp', 'nonce', 'iv', 'data'],
    ['data', 'iv', 'nonce', 'timestamp', 'encryptedKey'], ['encryptedKey', 'data', 'iv', 'nonce', 'timestamp'], ['data', 'iv', 'nonce', 'timestamp', 'keyId', 'encryptedKey'],
    ['encryptedKey', 'nonce'], ['encryptedKey', 'timestamp'], ['data', 'encryptedKey', 'nonce'], ['iv', 'encryptedKey', 'nonce'], ['nonce', 'keyId', 'data']];
  var orders = perm2.concat(three);
  var out = [];
  for (si = 0; si < seps.length; si++) {
    for (i = 0; i < orders.length; i++) {
      var parts = [], ok = true;
      for (j = 0; j < orders[i].length; j++) {
        var v = f[orders[i][j]];
        if (v === undefined || v === null) { ok = false; break; }
        parts.push(String(v));
      }
      if (!ok) continue;
      out.push({ order: orders[i], sep: seps[si] });
    }
  }
  return out;
}

function buildSignMessage(order, sep, f) {
  var parts = [];
  for (var i = 0; i < order.length; i++) parts.push(String(f[order[i]]));
  return strToBytes(parts.join(sep));
}

function signKeyVariants(K, saltB64) {
  var out = [{ tag: 'K', key: K }];
  out.push({ tag: 'K-hex', key: strToBytes(bytesToHex(K)) });
  out.push({ tag: 'K-b64', key: strToBytes(b64Encode(K)) });
  if (saltB64) {
    out.push({ tag: 'salt', key: strToBytes(saltB64) });
    out.push({ tag: 'sha256(salt)', key: sha256(strToBytes(saltB64)) });
  }
  return out;
}

// 返回 {order, sep, algo, keyTag} 或 null
function calibrateSign(f, expectedSignBytes, K, saltB64) {
  var orders = signCandidatesFor(f);
  var keys = signKeyVariants(K, saltB64);
  var algos = ['hmac-sha256', 'sha256'];
  var i, j, a, m;
  for (a = 0; a < algos.length; a++) {
    for (i = 0; i < orders.length; i++) {
      m = buildSignMessage(orders[i].order, orders[i].sep, f);
      if (algos[a] === 'sha256') {
        if (eqBytes(sha256(m), expectedSignBytes)) return { order: orders[i].order, sep: orders[i].sep, algo: 'sha256', keyTag: null };
      } else {
        for (j = 0; j < keys.length; j++) {
          if (eqBytes(hmacSha256(keys[j].key, m), expectedSignBytes)) {
            return { order: orders[i].order, sep: orders[i].sep, algo: 'hmac-sha256', keyTag: keys[j].tag };
          }
        }
      }
    }
  }
  return null;
}

function applySign(rule, f, K) {
  var msg = buildSignMessage(rule.order, rule.sep, f);
  if (rule.algo === 'sha256') return sha256(msg);
  var key = K;
  if (rule.keyTag === 'K-hex') key = strToBytes(bytesToHex(K));
  else if (rule.keyTag === 'K-b64') key = strToBytes(b64Encode(K));
  return hmacSha256(key, msg);
}

/* ============================================================
 * 6. GCM 参数自校准（AAD 约定）
 * ============================================================ */
function aadCandidates(env) {
  var out = [];
  // salt 是实测确认的 AAD，放最前面
  if (env.saltB64) out.push({ tag: 'saltB64', aad: strToBytes(env.saltB64) });
  out.push({ tag: 'knownSalt', aad: strToBytes(KNOWN_SALT_B64) });
  out.push({ tag: 'none', aad: new Uint8Array(0) });
  if (env.saltB64) out.push({ tag: 'saltRaw', aad: b64Decode(env.saltB64) });
  if (env.nonce) out.push({ tag: 'nonce', aad: strToBytes(env.nonce) });
  if (env.timestamp !== undefined && env.timestamp !== null) out.push({ tag: 'ts', aad: strToBytes(String(env.timestamp)) });
  if (env.keyId) out.push({ tag: 'keyId', aad: strToBytes(String(env.keyId)) });
  if (env.nonce && env.timestamp !== undefined) out.push({ tag: 'nonce+ts', aad: strToBytes(env.nonce + String(env.timestamp)) });
  if (env.ivB64) out.push({ tag: 'ivB64', aad: strToBytes(env.ivB64) });
  if (env.keyId && env.nonce) out.push({ tag: 'keyId+nonce', aad: strToBytes(String(env.keyId) + env.nonce) });
  out.push({ tag: 'motu', aad: strToBytes('motu') });
  return out;
}

/* 把原 body 按「字节数完全对齐」的方式重建。
   JSON 里 / 与 \/ 完全等价，每把一个 / 写成 \/ 就多 1 字节，于是可以在
   [无转义长度, 全转义长度] 区间内精确命中原 body 的字节数。
   这样即使宿主没有按我们给的 Content-Length 重算，服务端读到的长度也是对的。 */
function buildRequestBody(orig, obj) {
  var plain = JSON.stringify(obj);
  var full = plain.replace(/\//g, '\\/');
  var total = (plain.match(/\//g) || []).length;
  var target = orig ? byteLen(orig) : byteLen(full);
  var need = target - byteLen(plain);
  if (need < 0) need = 0;
  if (need > total) need = total;
  if (need === 0) return plain;
  if (need === total) return full;
  var n = 0;
  return plain.replace(/\//g, function () { n++; return n <= need ? '\\/' : '/'; });
}
function byteLen(s) { return strToBytes(s).length; }
function mergeHeaders(h, add) {
  var out = {}, k, e;
  for (k in (h || {})) if (Object.prototype.hasOwnProperty.call(h, k)) out[k] = h[k];
  for (k in add) if (Object.prototype.hasOwnProperty.call(add, k)) {
    for (e in out) if (e.toLowerCase() === k.toLowerCase()) delete out[e];
    out[k] = add[k];
  }
  return out;
}
/* 取密文/tag 的两种拼接顺序：0 = ct||tag，1 = tag||ct */
function splitCtTag(buf, order) {
  if (order === 1) return { ct: buf.slice(16), tag: buf.slice(0, 16) };
  return { ct: buf.slice(0, buf.length - 16), tag: buf.slice(buf.length - 16) };
}
function joinCtTag(ct, tag, order) {
  return order === 1 ? concatBytes(tag, ct) : concatBytes(ct, tag);
}

/* ============================================================
 * 7. 持久化状态
 * ============================================================ */
function loadState() {
  try {
    var raw = $prefs.valueForKey(PREF_KEY);
    if (!raw) return {};
    return JSON.parse(raw) || {};
  } catch (e) { return {}; }
}
function saveState(st) {
  try { $prefs.setValueForKey(JSON.stringify(st), PREF_KEY); } catch (e) { }
}

/* ============================================================
 * 8. 三种模式
 * ============================================================ */

function notify(title, sub, body) {
  try { $notify(title, sub, body); } catch (e) { }
}

/* ---- A. 替换服务端公钥 ---- */
function serveOurPublicKey() {
  var out = { body: $response.body };
  try {
    var o = JSON.parse($response.body);
    if (o && o.data && o.data.publicKey) {
      var st = loadState();
      if (o.data.salt) st.saltB64 = o.data.salt;
      if (o.data.keyId) st.keyId = o.data.keyId;
      st.pubKeyAt = Date.now();
      st.ver = SCRIPT_VER;
      saveState(st);
      o.data.publicKey = OUR_PUBLIC_KEY_B64;              // 换成我们的公钥
      o.data.keyId = o.data.keyId || '1';
      o._v = SCRIPT_VER;                                  // 版本水印：抓包里能看到跑的是哪一版
      out.body = JSON.stringify(o);
    }
  } catch (e) { }
  $done(out);
}

/* ---- B. 请求改写：解出会话密钥，再用真公钥转回服务端 ---- */
function handleRequest() {
  var st = loadState();
  var out = {};
  try {
    var body = $request.body;
    if (!body) { $done(out); return; }
    var j = JSON.parse(body);
    if (!j || !j.encryptedKey) { $done(out); return; }

    var env = { data: j.data, iv: j.iv, ivB64: j.iv, nonce: j.nonce, timestamp: j.timestamp, keyId: j.keyId, encryptedKey: j.encryptedKey, saltB64: st.saltB64 };
    var ctBytes = b64Decode(j.data || '');
    var ivBytes = b64Decode(j.iv || '');

    var m, cands, i, k, a, oi, plain, found = null, foundAad = { tag: 'saltB64', aad: new Uint8Array(0) }, foundOrder = 0, verified = false;
    m = rsaRawDecrypt(b64Decode(j.encryptedKey));
    cands = keyCandidates(m);

    var structural = null;

    /* ---------- 已知方案直通：OAEP-SHA256 → base64 文本 → AES-256 ---------- */
    var saltAad = strToBytes(st.saltB64 || KNOWN_SALT_B64);
    var fp = oaepUnpad(m, 'sha256', 'sha256', '');
    if (fp && fp.length) {
      var kk = null;
      var txt = bytesToStr(fp);
      if (/^[A-Za-z0-9+/=]{16,}$/.test(txt)) {                  // 明文是一段 base64 文本（实测如此）
        var dec = b64Decode(txt);
        if (dec.length === 16 || dec.length === 24 || dec.length === 32) kk = dec;
      }
      if (!kk && (fp.length === 16 || fp.length === 24 || fp.length === 32)) kk = fp;   // 明文就是裸密钥
      if (kk) {
        // 结构性填充成立 ⇒ 这段密文一定是用我们公钥加的 ⇒ 必须改写，否则服务端解不开
        // payload 必须是 App 塞进 RSA 的原始明文（这里是 base64 文本），不能换成解码后的裸密钥
        structural = { tag: 'oaep-sha256:known', key: kk, payload: fp };
        if (ctBytes.length >= 16) {
          plain = gcmDecrypt(kk, ivBytes, saltAad, ctBytes.slice(0, ctBytes.length - 16), ctBytes.slice(ctBytes.length - 16));
          if (plain) { found = structural; foundAad = { tag: 'saltB64', aad: saltAad }; foundOrder = 0; verified = true; }
        }
      }
    }

    /* 依次找其它结构性填充候选作为兜底（在没有直通结果时） */
    if (!structural) {
      for (i = 0; i < cands.length; i++) {
        if (padScheme(cands[i].tag) === 'raw') continue;
        if (cands[i].tag.indexOf(':') >= 0) continue;
        if (cands[i].key.length !== 16 && cands[i].key.length !== 32) continue;
        structural = cands[i]; break;
      }
      if (!structural) for (i = 0; i < cands.length; i++) if (padScheme(cands[i].tag) !== 'raw') { structural = cands[i]; break; }
    }

    /* 若直通未通过，再用 GCM 认证标签穷举「密钥 × AAD × 拼接顺序」 */
    if (!found) {
      var aads = aadCandidates(env);
      for (i = 0; i < cands.length && !found; i++) {
        if (ctBytes.length < 16) break;
        for (oi = 0; oi < 2 && !found; oi++) {
          var sp = splitCtTag(ctBytes, oi);
          for (a = 0; a < aads.length; a++) {
            plain = gcmDecrypt(cands[i].key, ivBytes, aads[a].aad, sp.ct, sp.tag);
            if (plain) { found = cands[i]; foundAad = aads[a]; foundOrder = oi; verified = true; break; }
          }
        }
      }
    }
    if (!found && structural) plain = null;        // 未证实，但仍按结构性候选改写

    if (!found && !structural) {
      // 填充都解不出来 => 这包不是给我们公钥的，原样放行（服务端可正常处理）
      st.lastError = 'blob-not-for-our-key';
      st.lastErrorAt = Date.now();
      saveState(st);
      $done(out);
      return;
    }
    if (!found) found = structural;

    // --- 校准签名算法（一次性） ---
    if (!st.signRule && !st.signCalibFailed && verified) {
      var f = env;
      if (plain) f.plain = bytesToStr(plain);
      var rule = calibrateSign(f, b64Decode(j.sign || ''), found.key, st.saltB64);
      if (rule) {
        st.signRule = rule;
        if (CFG.notifyCalibrate) notify('摩途脚本', '✅ 安全信道已校准', '填充=' + found.tag + ' AAD=' + foundAad.tag + ' 拼接=' + (foundOrder === 0 ? '密文+tag' : 'tag+密文') + '\n签名=' + rule.algo + '[' + rule.order.join(',') + '] sep="' + rule.sep + '" key=' + rule.keyTag);
      } else {
        st.signCalibFailed = Date.now();   // 未识别则不反复试探
        if (CFG.notifyCalibrate) notify('摩途脚本', '会话密钥已获取', '填充=' + found.tag + ' AAD=' + foundAad.tag + '\n但响应签名算法未识别（不影响解密，仅响应签名可能不被校验）');
      }
    }
    st.padTag = found.tag;
    st.keyHex = bytesToHex(found.key);
    st.aadTag = foundAad.tag;
    st.keyAt = Date.now();
    saveState(st);

    // --- 把会话密钥用「服务端真公钥」重新加密，请求照常发给服务端 ---
    var srv = SRV_KEY[String(j.keyId)] || SRV_KEY['1'];
    // ★ 关键：重新加密的是 App 的原始 RSA 明文（payload），不是解码后的密钥
    var padded = padBytes(padScheme(found.tag), found.payload || found.key);
    if (!padded) { $done(out); return; }
    j.encryptedKey = b64Encode(rsaRawEncryptTo(srv.n, srv.e, padded));
    // 重新签名（若已校准出算法；签名可能覆盖 encryptedKey，所以必须在替换之后再算）
    if (st.signRule) {
      var f2 = { data: j.data, iv: j.iv, nonce: j.nonce, timestamp: j.timestamp, keyId: j.keyId, encryptedKey: j.encryptedKey };
      if (plain) f2.plain = bytesToStr(plain);
      j.sign = b64Encode(applySign(st.signRule, f2, found.key));
    }
    /* 关键：按原 body 的转义风格重建（原 body 把 / 写成 \/），
       并显式带上 Content-Length —— 长度对不上服务端会直接 400 Bad Request */
    var newBody = buildRequestBody(body, j);
    out.body = newBody;
    out.headers = mergeHeaders($request.headers, { 'Content-Length': String(byteLen(newBody)) });
    $done(out);
  } catch (e) {
    $done({});
  }
}

/* ---- C. 响应改写：解密 -> 改会员 -> 重新加密 ---- */
function findKey(st) {
  var list = [];
  try { list = JSON.parse($prefs.valueForKey(PREF_KEY + '_keys') || '[]'); } catch (e) { list = []; }
  if (st.keyHex) list.unshift({ hex: st.keyHex, at: st.keyAt || 0 });
  var seen = {}, out = [];
  for (var i = 0; i < list.length; i++) {
    if (!list[i] || !list[i].hex || seen[list[i].hex]) continue;
    seen[list[i].hex] = 1;
    out.push({ key: hexToBytes(list[i].hex), hex: list[i].hex, at: list[i].at });
    if (out.length >= 6) break;
  }
  return out;
}
function rememberKey(hex) {
  var list = [];
  try { list = JSON.parse($prefs.valueForKey(PREF_KEY + '_keys') || '[]'); } catch (e) { list = []; }
  list = list.filter(function (x) { return x && x.hex !== hex; });
  list.unshift({ hex: hex, at: Date.now() });
  if (list.length > 6) list = list.slice(0, 6);
  try { $prefs.setValueForKey(JSON.stringify(list), PREF_KEY + '_keys'); } catch (e) { }
}

function aadFor(tag, env) {
  var list = aadCandidates(env);
  for (var i = 0; i < list.length; i++) if (list[i].tag === tag) return list[i].aad;
  return new Uint8Array(0);
}

function patchVip(o) {
  if (!o || !o.data || typeof o.data !== 'object') return false;
  if (!('isPro' in o.data)) return false;                 // 只改带会员字段的响应
  o.data.isPro = 1;
  o.data.memStartTime = Math.floor(Date.now() / 1000);
  o.data.memEndTime = CFG.memEndTime;
  o.data.type = 2;
  // 注意：不要动 hld*（硬件设备）字段，语义不明，改了容易显示异常
  return true;
}

function handleResponse() {
  var st = loadState();
  var out = { body: $response.body };
  try {
    var rj = JSON.parse($response.body);
    if (!rj || !rj.data || !rj.iv) { $done(out); return; }
    var ctBytes = b64Decode(rj.data);
    if (ctBytes.length < 16) { $done(out); return; }
    var ivBytes = b64Decode(rj.iv);
    var env = { data: rj.data, ivB64: rj.iv, nonce: rj.nonce, timestamp: rj.timestamp, keyId: st.keyId, saltB64: st.saltB64 };

    // 逐个尝试缓存里的会话密钥 × AAD × 拼接顺序，GCM 认证标签就是校验器
    var keys = findKey(st), i, a, oi, plain = null, used = null, usedAadTag = 'none', usedOrder = 0;
    var aads = aadCandidates(env);
    for (i = 0; i < keys.length && !plain; i++) {
      for (oi = 0; oi < 2 && !plain; oi++) {
        var sp = splitCtTag(ctBytes, oi);
        for (a = 0; a < aads.length; a++) {
          plain = gcmDecrypt(keys[i].key, ivBytes, aads[a].aad, sp.ct, sp.tag);
          if (plain) { used = keys[i]; usedAadTag = aads[a].tag; usedOrder = oi; break; }
        }
      }
    }
    if (!plain) { $done(out); return; }
    rememberKey(used.hex);
    st.aadTag = usedAadTag; saveState(st);

    var o = JSON.parse(bytesToStr(plain));
    var changed = CFG.enableVip && patchVip(o);
    var newPlain = strToBytes(JSON.stringify(o));

    // 重新加密：只换 data，iv / nonce / timestamp 原样保留 ——
    // 尽量不动可能被 sign 覆盖的字段，App 端校验最容易通过
    var newEnv = { ivB64: rj.iv, nonce: rj.nonce, timestamp: rj.timestamp, keyId: st.keyId, saltB64: st.saltB64 };
    var enc = gcmEncrypt(used.key, ivBytes, aadFor(usedAadTag, newEnv), newPlain);

    var res = {
      data: b64Encode(joinCtTag(enc.ct, enc.tag, usedOrder)),
      iv: rj.iv,
      nonce: rj.nonce,
      sign: rj.sign,
      timestamp: rj.timestamp
    };
    if (st.signRule) {
      var f = {
        data: res.data, iv: res.iv, nonce: res.nonce, timestamp: res.timestamp,
        keyId: st.keyId, plain: JSON.stringify(o)
      };
      res.sign = b64Encode(applySign(st.signRule, f, used.key));
    }
    out.body = JSON.stringify(res);
    if (changed && CFG.notifyCalibrate && st.notified !== 1) {
      st.notified = 1; saveState(st);
      notify('摩途', '会员已解锁', 'isPro=1 / 到期 2099-12-31');
    }
    $done(out);
  } catch (e) {
    $done(out);
  }
}

/* ============================================================
 * 9. 入口
 * ============================================================ */
(function main() {
  var url = (typeof $request !== 'undefined' && $request && $request.url) ? $request.url : '';
  if (typeof $response !== 'undefined' && $response && typeof $response.body === 'string') {
    if (url.indexOf('public-key') >= 0) { serveOurPublicKey(); return; }
    handleResponse();
    return;
  }
  if (typeof $request !== 'undefined' && $request) {
    handleRequest();
    return;
  }
  $done({});
})();
