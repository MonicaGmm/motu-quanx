# 摩途 motumap · Quantumult X 会员解锁 + 去广告

> 适用版本：**摩途 4.2.0 及以上**（2026-07 之后启用「加密信道」的版本）
> 抓包基线：2026-09-15，iOS 4.2.0
> 替换旧脚本：`WeiGiegie/666/main/motu.js`（只改 `/v3/user/info` 的写法已失效）

---

## 一、旧脚本为什么失效

旧脚本只改一个明文接口的响应体：

```
^https:\/\/motu\.motumap\.com\/v3\/user\/info url script-response-body motu.js
```

4.2.0 起，「我的」「会员中心」等页面改调 **加密接口**，服务端下发的明文接口不再被 App 调用：

| 旧（明文） | 新（加密） | 说明 |
|---|---|---|
| `GET  /v3/user/info` | `POST /v1/user/infoSec` | 用户信息，含 `isPro` / `memEndTime` |
| `GET  /v1/user/userCarList` | `POST /v1/user/userCarListSec` | 车辆列表 |
| — | `POST /v1/poi/mapShowAreaSec` | 地图 POI |

所以哪怕规则还挂着，也永远打不中，App 也不报错——表现就是「解锁失效」。

> 顺带一提：旧接口 `/v3/user/info` 服务端**仍然可用且仍是明文**，只是 App 不再调用它。

## 二、加密信道的结构（逆向结论）

```
GET /api/security/public-key
  -> { salt: base64("MotuSecureApiV2Salt20260722"), keyId: "1",
       publicKey: <RSA-2048 SPKI base64>, algorithm: "RSA" }

POST /v1/xxxSec
  { data: base64( AES-GCM 密文 || 16字节 tag ),
    iv: base64(12字节 nonce),
    keyId: "1",
    encryptedKey: base64( RSA-2048( 本次会话的 AES 密钥 ) ),   // 256 字节
    timestamp, nonce, sign }
```

判定依据（非猜测）：

1. **`data` 长度 = 明文长度 + 16**，是 GCM 的典型特征。
   实测 `/v1/user/userCarList` 的明文 JSON 压缩后**恰好 338 字节**，而对应的
   `userCarListSec` 响应 `data` 解出 **354 字节**，`354 - 16 = 338` —— 完全吻合。
2. 用 Node 的 `crypto`（OpenSSL）对 `salt`、`hldAk`、`deviceId`、`token`、公钥
   等 **24402 个**候选派生密钥做 GCM 认证试探，**全部失败**：
   `sign` 是 32 字节（SHA-256 量级），`nonce` 是 16 字节随机数。
   → 会话密钥是**每请求随机**、由 RSA 包裹的，无法离线推出。

结论：**没有服务端私钥，就不可能解密响应**，只能做真正的中间人。

## 三、本脚本的原理

```
App ──① GET /api/security/public-key ──> 脚本把公钥换成「我们的公钥」
     ──② POST /v1/user/infoSec ────────> 脚本用「我们的私钥」解出本次 AES 密钥
                                          再用「服务端真公钥」把该密钥重新加密
                                          请求原样转发给服务端（其它接口不受影响）
     <──③ 服务端加密响应 ────────────── 脚本用该 AES 密钥解密
                                          → 把 isPro / memEndTime 改成会员
                                          → 重新 AES-GCM 加密 + 重新签名 → 返回
```

**关键点：脚本不改请求内容，只换「钥匙的包装」，所以服务端业务逻辑完全正常。**

### 运行时自校准

由于无法离线确认客户端的加密细节，脚本在第一次请求时用**抓到的真实请求**做零知识校验
（GCM 的认证标签本身就是校验器），命中后写入 QX 持久化缓存，之后不再试探：

- **RSA 填充**：PKCS#1 v1.5、OAEP-SHA256、OAEP-SHA1、**OAEP-SHA256 + MGF1-SHA1**（Java 默认组合）
- **密钥形态**：裸密钥 / base64 文本 / `key||iv` 拼接，长度 16·24·32
- **GCM AAD**：空、`nonce`、`timestamp`、`keyId` 等
- **签名算法**：`HMAC-SHA256` / `SHA-256`，消息为 data/iv/nonce/timestamp/明文的多种排列组合

首次校准成功会弹一条通知，形如：

```
摩途脚本  ✅ 安全信道已校准
填充=oaep-sha256  AAD=none
签名=hmac-sha256[data,iv,nonce,timestamp] sep="" key=K
```

### 出错时的自保

- 解不出会话密钥（例如 App 仍缓存着旧公钥）→ **原样放行**，绝不改坏请求；
- 若「填充识别成功但 GCM 校验失败」（说明加密方式与假设不符）→ 会弹一次告警，
  此时请**先关掉本脚本的重写规则**，避免 App 报错。

## 四、安装

1. QX → 右下角圆盘 →「配置文件」→「重写」→ 右上角 `+` → 添加订阅：
   ```
   https://raw.githubusercontent.com/MonicaGmm/motu-quanx/main/motu.snippet
   ```
   （或手动把 `motu.snippet` 里的规则粘贴到自己的配置里）

2. **必须把 `motu.motumap.com` 加进 MITM 主机名，并且证书已受信任**（这一步最容易漏，漏了脚本会静默不生效）：

   ① 打开 MITM 开关
      QX → 右下角圆盘 →「配置文件」→「MITM」→ 打开开关

   ② 添加主机名
      同一页点「主机名」→ 右上角 `+` → 填 `motu.motumap.com`（或 `*.motumap.com`）
      · 也可以用订阅方式导入，`motu.snippet` 末尾的 `hostname = ...` 会自动注册；
      · 若手动编辑配置文本，在 `[mitm]` 段写 `hostname = %APPEND% motu.motumap.com`
        —— **已有 `hostname = ` 那行时务必带 `%APPEND%`**，否则会把原有主机名全部覆盖。

   ③ 证书安装 + 信任
      · 「配置文件」→「证书」→ 生成证书（已有则跳过）→ 点「安装证书」，**用 Safari** 打开该链接
      · iOS 设置 → 通用 → VPN 与设备管理 → 安装描述文件
      · iOS 设置 → 通用 → 关于本机 → 拉到最底「证书信任设置」→ **打开 Quantumult X 的开关**
      （最后这步不做，MITM 会静默失效）

   ④ 在 QX 里重新加载一次配置

3. **完全退出摩途再重新打开**（App 启动时才会重新拉取公钥）。

4. 进入「我的」页面，应收到「✅ 安全信道已校准」通知；再看「会员中心」，会员已生效。
   没收到通知就先回查第 2 步的三项是否都到位。注意：**去广告不需要 MITM**，
   所以「广告没了」不能作为 MITM 已通的证据。

> 第一次打开「我的」页面时脚本要跑一次 RSA 解算与签名校准（约几百毫秒），无感。

## 五、注意事项

- **去广告**部分不依赖 MITM，即使会员解锁失败，广告拦截也照常生效。
- 广告 SDK 有本地缓存，若开屏广告仍在，**清一次 App 缓存或重装**即可。
- 不要把 `motu.js` 里的内置 RSA 私钥当成敏感信息：它只用于**你自己设备上**的中间人，
  与任何账号凭据无关。脚本不采集、不上传任何数据。
- 服务端随时可能升级（换 `keyId`、换加密方式）。届时脚本会弹告警并自动降级为
  「只去广告、不解锁会员」，不会把 App 弄坏。重新抓一份 HAR 即可迭代。

## 六、文件说明

| 文件 | 用途 |
|---|---|
| `motu.js` | 脚本本体（公钥替换 / 请求改写 / 响应改写 三合一，纯 JS 实现 AES-GCM、RSA、SHA-256） |
| `motu.snippet` | QX 重写订阅文件（会员解锁 + 去广告规则） |

## 七、免责声明

仅供学习与交流，请在下载后 24 小时内删除，请勿转载或贩卖。使用本脚本产生的一切后果由使用者自行承担。
