# 摩途 motumap · Quantumult X 重写（加密信道 + 去广告）

> 抓包基线：2026-09-15，iOS 4.2.0
> 替换旧脚本：`WeiGiegie/666/main/motu.js`（只改明文 `/v3/user/info` 的写法已失效）
> **当前版本：v6** —— 请求侧全部调通，响应侧不改（原因见下）

---

## 一、先说结论

| 项目 | 状态 | 说明 |
|---|---|---|
| 解密摩途的加密信道 | ✅ 完全逆出来了 | RSA-OAEP-SHA256 + AES-256-GCM + `salt` 当 AAD，7/7 条真实请求可完美解密 |
| 让 `/v1/xxxSec` 全部正常返回 | ✅ 成功 | 三条 Sec 接口实测 **HTTP 200**，地图电子眼、车辆列表、用户信息全部恢复 |
| 去广告 | ✅ 有效 | 穿山甲 / 优量汇请求被拦成空 `{}` |
| **改响应体解锁 VIP** | ❌ **做不到** | App 会校验响应里的 `sign`，该签名用 **App 内置密钥**，脚本改完响应就被判「网络数据安全校验未通过」 |

一句话：**能用 QX 让摩途的接口正常工作、把广告干掉，但没法用 QX 白嫖会员** ——
不是加密解不开，而是解开了也过不了 App 自己的签名校验。

## 二、加密方案（已实测确认）

```
GET /api/security/public-key
  → { salt: "TW90dVNlY3VyZUFwaVYyU2FsdDIwMjYwNzIy", keyId: "1",
      publicKey: <RSA-2048 SPKI base64>, algorithm: "RSA" }

POST /v1/xxxSec
  { sign, iv, keyId, data, encryptedKey, timestamp, nonce }
```

| 环节 | 算法 |
|---|---|
| `encryptedKey` | **RSA / OAEP-SHA256**（MGF1 亦 SHA-256）。解出的明文是一段 **base64 文本**，解码后即 32 字节 AES 密钥 |
| `data` | **AES-256-GCM**：`base64( 密文 ‖ 16字节 tag )`，明文就是业务参数 JSON |
| `iv` | base64 解码后 **12 字节**，直接作 GCM nonce |
| **AAD** | **`salt` 字符串本身**（base64 文本，UTF-8 取字节）★ 最容易漏的一环 |
| `sign` | 32 字节 HMAC-SHA256，密钥是 **App 内置的**（不可从流量推导） |

判定依据（都不是猜的）：

1. 客户端二进制字符串直接写明算法：`RSA key does not support OAEP-SHA256 encryption.`、
   `Invalid AES-GCM IV. Expected 12 bytes after Base64 decoding.`、
   `CryptoKit.AES.GCM.seal(_:using:nonce:authenticating:)`、
   `secureEnvelopeForBusinessParameters:URL:headers:aesKey:aesSalt:error:`。
2. 用脚本内置私钥解出会话密钥后，7/7 条真实请求都能用「GCM + iv + AAD=salt」完美解密。
3. 端到端实测：拿真实请求、只换 `encryptedKey`（其余字段含 `sign` 一字不动）打到真服务端 →
   **HTTP 200** 并成功解密响应。
4. 服务端报错正好是三级定位信号：
   `RSA decrypt failed…` → 密钥没换成功；
   `sign invalid` → 密钥形态错了（典型：回填了裸密钥而不是原始 base64 文本）；
   `200` → 全通。

## 三、为什么 VIP 解锁做不到

响应 `{data, iv, nonce, sign, timestamp}` 里的 `sign` 由**服务端**签发、由 **App 校验**。
脚本一旦改动 `data`（例如把 `isPro` 从 0 改成 1），App 立刻报：

```
网络数据安全校验未通过，请检查网络环境或重新登录
```

这个签名用的密钥来自 SDK 的 `updateSecurityConfigWithAppId:keyId:publicKey:salt:validPeriodMs:`
配置（配合 `HmacUtil` / `HmacSHA256Signature`），是**内置在 App 里、不可从流量推导**的。
实测拿真实响应数据（已知会话密钥 + 明文 + 签名）暴力尝试了 **4 万余种构造**
（HMAC-SHA256 / SHA-256 × 数十种密钥候选 × 上千种消息拼接 × 原文/hex/base64 形态）**均未命中**。

结论：只要 App 还在校验这个签名，**任何中间人都无法伪造 VIP 响应** —— 这是它的设计目的。
换公钥 MITM 只能做到「透明转发」，不能凭空造数据。

## 四、v6 脚本做什么（当前交付版本）

```
① 改写 /api/security/public-key → 换成脚本内置公钥（并写入 salt）
② 请求侧：用内置私钥解出本次会话密钥 → 再用服务端真公钥重新加密回去
          （密文形态、长度、其余字段含 sign 全部保持原样）
③ 响应侧：原样放行，一个字都不改 ← 这样 App 的签名校验必然通过
④ 去广告：穿山甲 / 优量汇请求返回空 JSON
```

效果：**摩途功能完全正常**（我的页、首页电子眼、车辆、地图 POI 全部可用，不再弹安全提示），
**开屏广告被拦掉**，会员维持原状（没开通就是没开通）。

> 脚本里保留了响应改写的完整实现（`CFG.enableVip`），想自己试验把它改成 `true` 即可 ——
> 但会立刻触发上面那条安全提示，仅供研究，不建议日常使用。

## 五、安装

1. **先删掉旧的 motu 订阅**，再添加新的（QX 按 URL 缓存远程脚本，必须换 URL 才生效）：
   ```
   https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu-v6.snippet
   ```
2. **验证跑的是 v6**：抓包里 `GET /api/security/public-key` 的响应会多一个字段
   `"_v":"motu-qx-6"`。有它就是新版；没有就是还在跑缓存。
3. **MITM 必须覆盖 `motu.motumap.com`**：
   QX → 圆盘 →「配置文件」→「MITM」→ 打开开关 →「主机名」加 `motu.motumap.com`
   （手改配置文本时写 `hostname = %APPEND% motu.motumap.com`，**`%APPEND%` 不能省**，否则覆盖原有主机名）
4. 证书要装好并**在 iOS「设置 → 通用 → 关于本机 → 证书信任设置」里打开 Quantumult X 开关**。
5. 完全退出摩途再打开。

**如果装完 v6 后 App 仍报「网络数据安全校验未通过」**，说明该 App 除了响应签名外还检测了
网络环境（例如证书校验）。此时**换成保底订阅**——完全不碰摩途业务流量，只拦广告，App 必然正常：

```
https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu-ads-only.snippet
```

（抓包里看到 `_v` 字段就说明脚本确实生效了，那问题就出在 App 自身的环境检测上。）

## 六、想真正解锁 VIP 的两条路

1. **直接装别人改好的 IPA**（你手上那个 `摩途_4.1.8_𝑌𝑄𝐶.ipa` 已经解锁 VIP + 去广告）。
   不是 App Store 下载的，需要**用自己的 Apple ID 重签名后再装**：
   在 Windows 上用 **Sideloadly**（或 AltStore）→ 数据线连 iPhone → 把 ipa 拖进去 →
   填自己的 Apple ID → Start → 手机上到「设置 → 通用 → VPN 与设备管理」信任该描述文件
   （iOS 16+ 还要在「设置 → 隐私与安全性」里打开开发者模式）。
   免费 Apple ID 签的有效期 7 天，到期重新签一次即可；不要在主账号上登 iCloud 风险操作。
   注意那个包是 **4.1.8**，比你现在装的 4.2.0 旧，功能上可能提示升级。
2. **继续逆 App 内置密钥**：需要反汇编 110MB 的 iOS 主二进制、定位
   `updateSecurityConfigWithAppId:` 的调用点取到 appId，再推导签名密钥。
   理论上可行，但工作量大且不保证成功（SDK 可能做了混淆）。

## 七、文件说明

| 文件 | 用途 |
|---|---|
| `motu-v6.js` / `motu-v6.snippet` | **当前版本**：请求侧透明转发 + 去广告（响应侧不改） |
| `motu-ads-only.snippet` | **保底版本**：完全不碰摩途流量，只去广告 |
| `motu.js` / `motu.snippet` | 同 v6 内容，保留旧文件名兼容 |

## 八、免责声明

仅供学习与交流，请在下载后 24 小时内删除，请勿转载或贩卖。
