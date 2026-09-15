# 摩途 motumap · Quantumult X 会员解锁 + 去广告

> 适用版本：**摩途 4.2.0 及以上**（2026-07 之后启用「加密信道」的版本）
> 抓包基线：2026-09-15，iOS 4.2.0
> 替换旧脚本：`WeiGiegie/666/main/motu.js`（只改明文 `/v3/user/info` 的写法已失效）

---

## 一、旧脚本为什么失效

旧脚本只改一个明文接口的响应体：

```
^https:\/\/motu\.motumap\.com\/v3\/user\/info url script-response-body motu.js
```

4.2.0 起，「我的」「会员中心」等页面改调 **加密接口**，服务端下发的明文接口不再被 App 调用：

| 旧（明文） | 新（加密） |
|---|---|
| `GET /v3/user/info` | `POST /v1/user/infoSec` |
| `GET /v1/user/userCarList` | `POST /v1/user/userCarListSec` |
| — | `POST /v1/poi/mapShowAreaSec` |

规则还挂着也永远打不中，App 也不报错 —— 表现就是「解锁失效」。

## 二、加密方案（已实测确认，非猜测）

```
GET /api/security/public-key
  → { salt: "TW90dVNlY3VyZUFwaVYyU2FsdDIwMjYyMA…", keyId: "1",
      publicKey: <RSA-2048 SPKI base64>, algorithm: "RSA" }

POST /v1/xxxSec
  { sign, iv, keyId, data, encryptedKey, timestamp, nonce }
```

| 环节 | 算法 | 说明 |
|---|---|---|
| `encryptedKey` | **RSA / OAEP-SHA256**（MGF1 亦 SHA-256，label 空） | 解出的明文是**一段 base64 文本**，解码后即 32 字节 AES 密钥 |
| `data` | **AES-256-GCM** | `base64( 密文 ‖ 16字节 tag )`，明文就是业务参数 JSON |
| `iv` | **base64 解码后 12 字节** | 直接用作 GCM nonce |
| **AAD** | **`salt` 字符串本身**（base64 文本，按 UTF-8 取字节） | ★ 这是最容易漏的一环 |
| `sign` | 32 字节（HMAC-SHA256 量级，密钥是 App 内置密钥） | 服务端会校验，见下文 |

### 判定依据（不是猜的）

1. **客户端二进制里的名字直接写明了算法**（从 `MotuMapH00k` 同目录的主二进制字符串里挖到）：
   - `RSA key does not support OAEP-SHA256 encryption.`
   - `Invalid AES-GCM IV. Expected 12 bytes after Base64 decoding.`
   - `AesGcmCryptoKitUtil` / `CryptoKit.AES.GCM.seal(_:using:nonce:authenticating:)`
   - `secureEnvelopeForBusinessParameters:URL:headers:aesKey:aesSalt:error:`
     ← 方法签名里就有 **aesSalt**，说明 salt 参与了加密
2. **离线实证**：用自己的 RSA 私钥解出抓包里的会话密钥后，7/7 条真实请求都能用
   `AES-256-GCM + iv + AAD=salt` 完美解密，明文统一是 `{}`（2 字节 → 18 字节，与抓包一致）。
3. **端到端实证**：拿抓包里 App 的真实请求，只把 `encryptedKey` 换成用**服务端真公钥**
   重新加密的版本（其余字段与 `sign` 一字不动）发给真服务端 →
   **HTTP 200**，且用该会话密钥成功解密出 1406 字节的用户 JSON。
   -> 同时证明了两件事：**重新加密的做法服务端完全接受**，且 **`sign` 不覆盖 `encryptedKey`**。

## 三、本脚本做什么

```
① 改写 /api/security/public-key，把服务端公钥换成脚本内置公钥
② 请求脚本：用内置私钥解出本次会话密钥 → 再用「服务端真公钥」重新加密回去
             （其余字段含 sign 原样保留，所以服务端校验照过）
③ 响应脚本：用会话密钥解密 → 把 isPro/memStartTime/memEndTime 改成会员
             → 重新 AES-GCM 加密（iv/nonce/timestamp 保持原值，尽量不动被签名的字段）
```

**关于 `sign`**：这是 App 用**内置密钥**做的接口签名（我们拿不到该密钥，也无需拿到）。
因为脚本不改 `data/iv/nonce/timestamp`，App 自己算好的 `sign` 依旧有效，原样转发即可。
响应侧同样保留服务端下发的 `sign`。

**保底逻辑**：如果服务端日后改了算法，脚本会自动回退到「运行时自校准」
（RSA 填充 4 种 / 密钥形态多种 / GCM AAD 多种 / 两种拼接顺序，用 GCM 认证标签当校验器），
仍然解不开时**原样放行**，不会把 App 弄坏。

## 四、安装

1. QX → 右下角圆盘 →「配置文件」→「重写」→ 右上角 `+` → 添加订阅：
   ```
   https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu.snippet
   ```

2. **必须把 `motu.motumap.com` 加进 MITM 主机名，并且证书已受信任**：

   ① 打开 MITM 开关：QX → 圆盘 →「配置文件」→「MITM」
   ② 添加主机名：同页点「主机名」→ `+` → `motu.motumap.com`
      · 若手动编辑配置文本，写 `hostname = %APPEND% motu.motumap.com`
        —— **已有 `hostname =` 那行时务必带 `%APPEND%`**，否则会覆盖原有主机名
   ③ 证书安装 + 信任：
      「配置文件」→「证书」→ 生成 → 「安装证书」（用 Safari 打开）
      → iOS 设置 → 通用 → VPN 与设备管理 → 安装描述文件
      → iOS 设置 → 通用 → 关于本机 → 拉到底「证书信任设置」→ **打开 Quantumult X 开关**
      （最后这步不做，MITM 会静默失效）
   ④ QX 里重新加载一次配置

3. **远程脚本会被 QX 缓存**：更新后请把该订阅删掉重新添加（或点更新），否则跑的还是旧版本。

4. **完全退出摩途再打开**（App 启动时才会重新拉取公钥）→ 进「我的」页面。

## 五、常见问题

**Q：装完规则后「我的」页面报 `Request failed: bad request (400)`？**

已修复（2026-09-15）。400 有两种成因，脚本都已处理：

1. **会话密钥没解出来** → 请求带着「服务端解不开的 encryptedKey」转发，服务端返回
   `{"code":400,"msg":"RSA decrypt failed, likely key mismatch or OAEP parameters mismatch"}`。
   v1 漏了最关键的 **AAD = salt**，现在已按实测方案实现。
2. **请求体字节数对不上** → 摩途原始 body 把 `/` 转义成 `\/`，用 `JSON.stringify`
   重新序列化会短 3~10 字节，服务端读到「长度不符」的 body 也是 400。
   现在会**按字节数精确对齐**并显式带上 `Content-Length`。

**Q：怎么判断脚本生效了？**

进「我的」页面会弹 `✅ 安全信道已校准`（拿到会话密钥并有真实响应时）；
只弹「会话密钥已获取」说明密钥拿到了但签名算法未识别（不影响解锁）。
两条都没有 → MITM 没通，回查第四节第 2 步。

**Q：还是不行？**

重新抓一份 HAR（QX → 抓包 → 复现「打开 App → 我的」→ 导出）发来即可定位：
新抓包里 `encryptedKey` 是用脚本内置公钥加密的，作者可以用配套私钥直接解开，
一次就能看清真实填充/密钥形态，不必再猜。

**Q：开屏广告还在？**

广告请求（穿山甲/优量汇）已被拦截（返回空 `{}`），但广告 SDK 有**本地缓存**，
开机屏广告可能来自缓存。**清一次 App 缓存或重装**即可。

## 六、文件说明

| 文件 | 用途 |
|---|---|
| `motu.js` | 脚本本体（公钥替换 / 请求改写 / 响应改写 三合一，纯 JS 实现 AES-GCM、RSA、SHA-256） |
| `motu.snippet` | QX 重写订阅文件（会员解锁 + 去广告规则） |

## 七、免责声明

仅供学习与交流，请在下载后 24 小时内删除，请勿转载或贩卖。使用本脚本产生的一切后果由使用者自行承担。
