# PandaLink — 自建 iOS 车机投屏客户端

对标 `top.shareway.pandaplayplus.ios`（PandaPlay+）的 CarLink 通道，
从安卓包 `pandaplay.apk` v1.0.10 的 smali 逆向复原协议后重写。

- 目标系统：**iOS 16.1+**（`MinimumOSVersion` 写死 16.1，专为 iOS 16.1 + TrollStore 场景）
- 架构：arm64 / 纯 Swift / 零第三方依赖 / 零网络回连
- 授权：**没有授权层**。不注册、不登录、不请求 `pandaplus.shareway.top`，不校验任何 JWT。

---

## 一、为什么是重写而不是改原包

原 IPA 的可执行段是 FairPlay 密文（`LC_ENCRYPTION_INFO_64.cryptid = 1`，
`cryptoff 0x4000 / cryptsize 0x4E8000`）。TrollStore 的 CoreTrust 绕过只伪造代码签名，
**不提供 FairPlay 内容密钥**。改 `MinimumOSVersion` / `LC_BUILD_VERSION.minos` 只能让包装进去，
`__text` 依然是密文，dyld 解不出来必然崩。

验证命令（本仓库 `..\..\check_ipa.py`）：

```
python check_ipa.py "top.shareway.pandaplayplus.ios(1).ipa"
→ verdict NEED_DECRYPT
```

所以只有两条路：拿到 cryptid=0 的砸壳包，或者按协议重写。这里走第二条。

---

## 二、协议复原结果（全部逐行核对过 smali）

### 1. 端口

车机主动连手机的六个 TCP 端口，全部由手机侧 `NWListener` 监听：

| 角色 | 端口 | 十六进制 | 用途 |
|---|---|---|---|
| auth | 57209 | 0xDF79 | ECDH 握手，绑不上就整组放弃 |
| control | 57219 | 0xDF83 | 心跳 / 端口协商 / 车机配置 |
| sensor | 57239 | 0xDF97 | 触摸与传感器事件 |
| media | 57229 | 0xDF8D | 音频流 |
| cert | 57249 | 0xDFA1 | 证书交换 |
| video | 57259 | 0xDFAB | H.264 视频流 |

另外 `getPortRequest` 里 UIBC 走 **4321 (0x10E1)**，不在上表内。

### 2. 帧格式（20 字节头，全大端）

```
off  0  u32  totalLength        整帧长度（含 20 字节头）
off  4  u32  sequence           序号，手机侧从 1 起
off  8  u32  unixSeconds        秒级时间戳
off 12  u8   flags              (direction & 1) | ((encoding & 3) << 1) | ((role & 3) << 3)
off 13  u8   channel            NONE=0 CONTROL=1 SENSOR=2 AUTH=3 AUDIO=4 VIDEO=5 CERT=6 ACK=7
off 14  u16  param              子类型（AUTH 里是 authMethod，CONTROL 里是命令号）
off 16  u16  reserved           恒 0
off 18  u16  crc16              CRC-16/ARC，覆盖前 18 字节
off 20  ...  body
```

`direction`：CAR=0 / PHONE=1。`encoding`：RAW=0 / PB3=1 / RAW_NO_ENCRYPTED=2。
`role`：SEND=0 / REQ=1 / RES=2 / SEND_SYNC=3。手机侧发出的帧写死 `direction=CAR, encoding=RAW, role=RES`。

**CRC 是 CRC-16/ARC（poly 0xA001，init 0x0000，不 xor-out），不是 MODBUS。**
标准向量 `crc16("123456789") == 0xBB3D`。按 MODBUS（init 0xFFFF）算会得 0x4B37，全帧校验必错。

### 3. AUTH 握手（param=1 请求 / param=3 确认）

车机发 `AuthRequest`（protobuf `AuthIndex.field1`）：

```
1 version:int32   2 authPk:bytes   3 authPkHmac:bytes   4 agreementPk:bytes
5 agreementPkSig:bytes   6 random:bytes   7 id:bytes   8 model:string
9 userConfirmed:bool   10 workModes:int32   11 productName:string
```

手机侧处理：

1. 保存 `id` / `model` / `workModes`；生成 32 字节 `ownRandom`。
2. `agreementPk` 必须 **65 字节且首字节 `0x04`**（未压缩 P-256 点），否则放弃。
3. ECDH：自己的 `agreementKey` 私钥 × 车机 `agreementPk` → `sharedSecret`。
4. 会话密钥（16 字节）：
   ```
   salt = carRandom || ownRandom
   prk  = HMAC-SHA256(key = SHA256(salt), data = sharedSecret)
   key  = HMAC-SHA256(key = prk, data = "session_key" || 0x01)[0..16]
   ```
5. `pin` 长度 ≥ 6 时额外产两件（本客户端默认无 PIN，两项为空字节）：
   - `authPkHmac = HMAC-SHA256(key = SHA256(ownRandom || pin), data = authPk)`
   - `agreementPkSig = ECDSA-SHA256(authSigningKey, authPk || ownRandom || carRandom)`
6. 回 `AuthResponse`（protobuf `AuthIndex.field2`）：
   `version=0x701`、`result=0`、`workModes`、`dayOrNightMode=1`、
   `screenInfo="1280_720_240_1280_720"`、`authPk`、`agreementPk`、`random=ownRandom`。

车机再发 `AuthConfirm`（param=3，`field3.cipher`），用会话密钥 **AES-256-GCM** 解出手机 IP。
解密失败则回落到 socket 对端地址。

### 4. 通道加密封装

AUTH 之后，control / sensor / media / cert / video 五条通道的 body 都由同一会话密钥加密：

```
[u32 BE ivLen][iv][u32 BE ctLen][ct]
```

`ct` 尾部 16 字节是 GCM tag（Java `Cipher.doFinal` 的输入格式）。

### 5. CONTROL 命令（param 即子类型）

| param | 方向 | 内容 |
|---|---|---|
| 1 | 双向 | `heartbeat{timestamp}`，原样回带 |
| 2 | 车机→手机 | `getPortRequest{type}`，type 1=SENSOR→57239、2=AUDIO→57229、3=UIBC→4321 |
| 3 | 手机→车机 | `getPortResponse{result=SUCCESS, port}` |
| 23 | 车机→手机 | `disconnect` |
| 24 | 车机→手机 | `getUCarConfigRequest` |
| 25 | 手机→车机 | `getUCarConfigResponse` |

`GetUCarConfigResponse` 填充值：`screenWidth=1280`、`screenHeight=720`、`dpi=240`、
`videoDisplayWidth=1280`、`videoDisplayHeight=720`、`fps=30`、`isSupportP2P=true`、
`isSupportSoftAP=true`、`isDataTransMode=false`、`default5GChannel=149`、
`isSupportCamera=false`、`isSupportMic=true`、`isSupportLowLatencyDecodingMode=true`、
`isSupportVoiceWaken=true`、`isSupportHevc=true`、`workModes=0`。

---

## 三、工程结构

```
PandaLink/
├── project.yml                     XcodeGen 描述（deploymentTarget 16.1）
├── Info.plist                      MinimumOSVersion 16.1
├── scripts/make_ipa.sh             产物打包成 Payload/PandaLink.app → .ipa
├── .github/workflows/build.yml     macOS CI，出未签名 IPA
└── Sources/
    ├── App/
    │   ├── PandaLinkApp.swift      @main
    │   ├── CarLinkSession.swift    ObservableObject，状态与日志
    │   └── ContentView.swift       SwiftUI 界面（四卡片 + 底部启停）
    ├── Net/
    │   ├── CarlinkListener.swift   六端口 NWListener + 角色分派
    │   ├── CarlinkChannel.swift    单通道读写（序号、拆包、加解密钩子）
    │   └── ECPTransport.swift      ECP 客户端连接（CarLife 链路备用）
    └── Protocol/
        ├── CarlinkFrame.swift      20 字节头帧编解码 + CRC-16/ARC + 流拆包
        ├── CarlinkAuthChannel.swift ECDH/SessionKey/AuthResponse/AuthConfirm
        ├── CarlinkControlChannel.swift  心跳 / 端口协商 / UCarConfig
        ├── CarLinkPorts.swift      六端口常量 + 发现记录
        ├── Crypto.swift            P-256 / HMAC / AES-GCM 封装
        ├── Proto.swift             最小 protobuf 编解码
        ├── ECP.swift               ECP 16 字节小端帧（CarLife 链路）
        ├── ECPMessages.swift       ECP 的 JSON 报文（手写转义，不用 JSONEncoder）
        └── ECPTLV.swift            ECP 的 TLV 层
```

---

## 三之二、没有 macOS 时怎么验

Windows 上没法编，但有两条机器校验能挡住"抄错一位、编译过、真机才炸"的错：

```powershell
cd D:\Projects\_work\panda
python swift_syntax_check.py     # tree-sitter-swift 解析 15 个 .swift，找 ERROR / missing 节点
python proto_field_check.py      # Proto.swift 里每个 writeXxx(N,…) 的 N 与 smali 的 *_FIELD_NUMBER 逐条比对
```

`proto_field_check.py` 已经抓出过真 bug：`workModes` 原来写 19（那是 `isSupportPoiNav`）、
`isSupportHevc` 原来写 20（那是 `isSupportRotation`），正确值是 **18 / 23**。
这两个错编译期不报、静态读代码也很难看出，只有拿 smali 常量表对才现形。

---

## 四、编译

本机（Windows）没有 `swiftc` / `xcodebuild`，必须在 macOS 上编，或用仓库自带的 GitHub Actions。

### 本地（macOS）

```bash
brew install xcodegen
cd PandaLink
xcodegen generate
xcodebuild -project PandaLink.xcodeproj -scheme PandaLink \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath build \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO build
bash scripts/make_ipa.sh
# → dist/PandaLink.ipa
```

### CI

把 `PandaLink/` 目录内容作为仓库根 push 到 GitHub，`build.yml` 自动跑（`macos-14` + Xcode 15.4），
产物在 Actions 的 artifact `PandaLink-unsigned-ipa` 里。

### 装机

`PandaLink.ipa` 未签名，`MinimumOSVersion 16.1`，直接 TrollStore 装即可。
TrollStore 会自己 ad-hoc 签名，不需要证书。

---

## 五、能力边界（务必先读）

1. **iOS 不能把自己开成热点。** 安卓侧靠 `LocalOnlyHotspot` + 提权跑 `hotspot_ap.dex` 把手机变成 AP；
   iOS 对应的 `NEHotspotConfiguration` 需要 Apple 特批 entitlement，普通侧载拿不到。
   所以本客户端的工作模式是：**车机开热点（或同一局域网），手机连进去，车机反向连手机的这六个端口。**
2. **视频流走 WFD/H.264**，安卓侧是 `libovmsink.so`（1.4 MB 原生库）解码。
   iOS 首版只做到握手 + 控制通道 + 帧统计，**视频解码渲染还没接**（需要 VideoToolbox 起 H.264 解码器）。
3. **CarLife（百度）链路未实现。** 那条走 AOA/USB + tcp:10922/10920/10921，
   安卓侧其实也只是 `com.baidu.carlife` 的壳。`ECP.swift` 是它的协议层，保留备用。
4. **PIN 默认空。** 原安卓版随机生成 6 位 PIN 让用户手动确认，这里留了 `pin` 字段但默认空
   （空 PIN 时 `authPkHmac` / `agreementPkSig` 按协议发空字节，握手照样成立）。
5. **车机侧兼容性未实测。** 所有报文结构来自 smali 静态复原，没有真车机联调过。
   第一次连不上时，把 App 里的日志（每通道前 3 帧）导出来对照第四节核对。

---

## 六、与"改原包"方案的关系

同目录 `..\..\README_降级方案.md` 讲的是"怎么让原 IPA 在 16.1 上跑"，
最终结论是必须砸壳。本工程是另一条路：不碰原包，按协议重写。

两条路都保留了：
- 若哪天拿到 cryptid=0 的砸壳包，用 `..\..\make_ipa.py` 一键改成 16.1 可用（改 minos + 弱绑定 + ad-hoc 重签）。
- 若没有砸壳包，用本工程。
