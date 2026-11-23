//
//  ECPMessages.swift
//  PandaLink
//
//  ECP 帧体（body）里的 JSON 报文。
//
//  依据 `p/yh;->F(...)` 的 sparse-switch 与 `p/jg;->k(...)`：
//    0x10450 →  {"time":<ms>,"currentTime":<ms>,"currentTimeZone":"Asia/Shanghai"}
//    0x10010 →  无线客户端信息（15 个键，见 ECPWirelessClientInfo）
//
//  注意 `p/xk;->L(String)` 是手写 JSON 转义（" \ \t \n \r 与控制字符 \u00xx），
//  键序固定、无空格。Swift 侧**不用 JSONEncoder**（它的键序来自字典、不保证稳定），
//  而是一样手写拼串，见 `ECPJSON`。
//

import Foundation

// MARK: - 手写 JSON（对齐 `p/xk;->L`）

enum ECPJSON {

    /// 对齐 `p/xk;->L(Ljava/lang/String;)Ljava/lang/String;`（`xk.smali:522`）
    /// `"` → `\"`；`\` → `\\`；`\t`/`\n`/`\r` 转义；其它 < 0x20 转 `\u00xx`；结果两侧加引号。
    static func quote(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{09}": out += "\\t"
            case "\u{0A}": out += "\\n"
            case "\u{0D}": out += "\\r"
            default:
                if u.value < 0x20 {
                    out += String(format: "\\u%04x", u.value)
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        out += "\""
        return out
    }
}

// MARK: - 时间同步（0x10450）

struct ECPTimeSync: Equatable {
    var time: Int64
    var currentTime: Int64
    var currentTimeZone: String

    /// 对齐 smali：time 与 currentTime 用同一个 `System.currentTimeMillis()`，
    /// timezone 为空时回落 "Asia/Shanghai"。
    static func now(zone: String = "Asia/Shanghai") -> ECPTimeSync {
        let ms = Int64(Date().timeIntervalSince1970 * 1000)
        return ECPTimeSync(
            time: ms,
            currentTime: ms,
            currentTimeZone: zone.isEmpty ? "Asia/Shanghai" : zone
        )
    }

    /// `{"time":<ms>,"currentTime":<ms>,"currentTimeZone":"…"}`（键序固定）
    func encoded() -> [UInt8] {
        let s = "{\"time\":\(time),\"currentTime\":\(currentTime),"
            + "\"currentTimeZone\":\(ECPJSON.quote(currentTimeZone))}"
        return Array(s.utf8)
    }

    static func decode(_ body: [UInt8]) -> ECPTimeSync? {
        guard !body.isEmpty else { return nil }
        guard let obj = try? JSONSerialization.jsonObject(with: Data(body)) as? [String: Any] else {
            return nil
        }
        func int64(_ key: String) -> Int64? {
            if let n = obj[key] as? NSNumber { return n.int64Value }
            if let s = obj[key] as? String { return Int64(s) }
            return nil
        }
        guard let t = int64("time"), let cur = int64("currentTime") else { return nil }
        let zone = (obj["currentTimeZone"] as? String) ?? "Asia/Shanghai"
        return ECPTimeSync(time: t, currentTime: cur, currentTimeZone: zone)
    }
}

// MARK: - 无线客户端信息（0x10010）

/// 对齐 `p/yh;->F` 的 `:sswitch_2` —— 15 个键，键序即 smali 拼串顺序。
///
/// 常量部分全部来自 smali 字面量：
///   pxcVersion = "1.0.2"
///   phoneOs    = "android"                    ← 安卓字面量，iOS 尊重协议仍填 "android"
///   package    = "net.easyconn.carman.neutral" ← 易联（EasyConn）的中性包名
///   versionCode = 1, supportH264IFrame = true, supportFunction = 0,
///   appVersionFingerPrint = "", token = ""
///
/// 变量部分对应 `Lp/ko;` 的 a…g：
///   a=phoneUUID b=phoneBrand c=phoneModel d=phoneOsVersion
///   e=pubkey   f=encryptedHUID g=bluetoothName
struct ECPWirelessClientInfo: Equatable {
    var pxcVersion: String = "1.0.2"
    var phoneUUID: String
    var phoneBrand: String
    var phoneModel: String
    var phoneOsVersion: String
    var phoneOs: String = "android"
    var package: String = "net.easyconn.carman.neutral"
    var versionCode: Int = 1
    var supportH264IFrame: Bool = true
    var supportFunction: Int = 0
    var appVersionFingerPrint: String = ""
    var token: String = ""
    var pubkey: String
    var encryptedHUID: String
    var bluetoothName: String

    /// 严格按 smali 的拼串顺序与字面量输出
    func encoded() -> [UInt8] {
        let q = ECPJSON.quote
        let s = "{"
            + "\"pxcVersion\":\(q(pxcVersion)),"
            + "\"phoneUUID\":\(q(phoneUUID)),"
            + "\"phoneBrand\":\(q(phoneBrand)),"
            + "\"phoneModel\":\(q(phoneModel)),"
            + "\"phoneOsVersion\":\(q(phoneOsVersion)),"
            + "\"phoneOs\":\(q(phoneOs)),"
            + "\"package\":\(q(package)),"
            + "\"versionCode\":\(versionCode),"
            + "\"supportH264IFrame\":\(supportH264IFrame),"
            + "\"supportFunction\":\(supportFunction),"
            + "\"appVersionFingerPrint\":\(q(appVersionFingerPrint)),"
            + "\"token\":\(q(token)),"
            + "\"pubkey\":\(q(pubkey)),"
            + "\"encryptedHUID\":\(q(encryptedHUID)),"
            + "\"bluetoothName\":\(q(bluetoothName))"
            + "}"
        return Array(s.utf8)
    }
}

// MARK: - HUID 提取

/// 对齐 `p/xk;->M([B)Ljava/lang/String;`
///
/// smali 里**不是** JSON 解析，而是纯字符串扫描：
///   1. 找 `"HUID"`（连引号），找不到再找 `"huid"`（连引号）
///   2. 从该位置往后找 `:`，再找第一个 `"`，再找下一个 `"`
///   3. 取两者之间 substring
/// 这里照抄这段扫描，避免 JSON 解析对格式的额外要求。
enum ECPHUIDExtractor {

    static func extract(_ body: [UInt8]) -> String? {
        guard !body.isEmpty else { return nil }
        let s = String(decoding: body, as: UTF8.self)
        guard !s.isEmpty else { return nil }

        var pos = s.range(of: "\"HUID\"")?.lowerBound
        if pos == nil { pos = s.range(of: "\"huid\"")?.lowerBound }
        guard let anchor = pos else { return nil }

        guard let colon = s[anchor...].firstIndex(of: ":") else { return nil }
        let afterColon = s.index(after: colon)
        guard let open = s[afterColon...].firstIndex(of: "\"") else { return nil }
        let contentStart = s.index(after: open)
        guard let close = s[contentStart...].firstIndex(of: "\"") else { return nil }
        guard close > contentStart else { return nil }
        return String(s[contentStart..<close])
    }
}

// MARK: - 心跳（0x70000000）

/// 对齐 `p/gn;->b`：心跳帧 type 在 `h % 7 == 0` 时是 0（空类型探活），
/// 否则 0x70000000，body 恒为空、extra 恒 4 字节零。
struct ECPHeartbeat {
    let type: UInt32
    let sequence: Int

    static func next(sequence: Int) -> ECPHeartbeat {
        ECPHeartbeat(type: sequence % 7 == 0 ? 0 : ECPType.heartbeat, sequence: sequence)
    }
}

// MARK: - 帧类型可读名

extension ECPType {
    /// 注意：switch 里必须写全 `ECPType.xxx`，裸写 `case authRequest` 会被当成
    /// 「绑定一个新变量」的 identifier pattern，匹配一切，后面的分支全不可达。
    static func label(_ type: UInt32) -> String {
        switch type {
        case ECPType.authRequest: return "认证请求"
        case ECPType.authResponse: return "认证应答"
        case ECPType.wirelessClientInfo: return "无线客户端信息"
        case ECPType.timeSync: return "时间同步"
        case ECPType.controlRequest: return "控制请求"
        case ECPType.heartbeat: return "心跳"
        case 0: return "探活"
        default:
            if type & 1 != 0 { return "应答 0x\(String(type, radix: 16))" }
            return "请求 0x\(String(type, radix: 16))"
        }
    }
}
