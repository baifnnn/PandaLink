//
//  CarLinkPorts.swift
//  PandaLink
//
//  CarLink 监听端口表。
//
//  依据 `com/hpplay/carlink/CarlinkHostActivity.smali:4138-4192` 的六次 `p/o9;->b(I)` 调用：
//    0xdf79 = 57209  AUTH     → o9.e
//    0xdf83 = 57219  CONTROL  → o9.f
//    0xdf97 = 57239  SENSOR   → o9.g
//    0xdf8d = 57229  MEDIA    → o9.h
//    0xdfa1 = 57249  CERT     → o9.i
//    0xdfab = 57259  VIDEO    → o9.j
//
//  角色分配（手机是**服务端**，车机主动连进来）：
//    `p/o9;->b(int)` = `new ServerSocket()` + `setReuseAddress(1)` + `bind(InetSocketAddress(port))`
//    `p/o9;->a(name, socket, ff)` 每个端口起一条 `carlink-accept-<name>` 守护线程
//
//  另外两处端口（非 CarLink ECP）：
//    7236（0x1c44）  `CarlinkSpikeActivity` 里的假手机 RTSP 服务器（AirPlay sink 自测用）
//    10922 / 10930   CarLife AOA 通道（复用百度 CarLife 协议栈）
//

import Foundation

enum CarLinkPorts {
    static let auth: UInt16 = 57209
    static let control: UInt16 = 57219
    static let sensor: UInt16 = 57239
    static let media: UInt16 = 57229
    static let cert: UInt16 = 57249
    static let video: UInt16 = 57259

    /// 启动顺序对齐 smali：auth 先绑，绑不上就整组放弃
    static let ordered: [(role: ChannelRole, port: UInt16)] = [
        (.auth, auth),
        (.control, control),
        (.sensor, sensor),
        (.media, media),
        (.cert, cert),
        (.video, video),
    ]

    /// 车机侧发现记录用的恒量（`p/ss;->a()` 与 `p/f5;->b()` 里的字面量）
    static let discoveryPort: UInt16 = 57209
    static let discoveryType: Int = 1002
    static let discoveryName = "PandaPlay+"
    static let serviceType = "_carlink._tcp"
}

/// 六个通道的角色
enum ChannelRole: String, CaseIterable {
    case auth, control, sensor, media, cert, video

    var label: String {
        switch self {
        case .auth: return "AUTH"
        case .control: return "CONTROL"
        case .sensor: return "SENSOR"
        case .media: return "MEDIA"
        case .cert: return "CERT"
        case .video: return "VIDEO"
        }
    }

    var port: UInt16 {
        switch self {
        case .auth: return CarLinkPorts.auth
        case .control: return CarLinkPorts.control
        case .sensor: return CarLinkPorts.sensor
        case .media: return CarLinkPorts.media
        case .cert: return CarLinkPorts.cert
        case .video: return CarLinkPorts.video
        }
    }

    /// 该通道是否跑 ECP 帧（AUTH/CONTROL 跑；MEDIA/VIDEO 是裸流）
    var usesECP: Bool {
        switch self {
        case .auth, .control, .sensor, .cert: return true
        case .media, .video: return false
        }
    }
}

/// `p/ss;->a()` 的发现记录
///
/// smali 用 `JSONObject.put` 逐字段写，落盘顺序即代码顺序：
///   name / ssid / psk / mac / freq / port / type / ipAddress / channel / band
/// 其中 `port`=57209（0xdf79）、`type`=1002（0x3ea）、`name`="PandaPlay+" 全是字面量。
struct CarLinkDiscoveryRecord: Equatable {
    var name: String = CarLinkPorts.discoveryName
    var ssid: String
    var psk: String
    var mac: String
    var freq: Int
    var port: Int = Int(CarLinkPorts.discoveryPort)
    var type: Int = CarLinkPorts.discoveryType
    var ipAddress: String
    var channel: Int
    var band: Int

    func encoded() -> [UInt8] {
        let q = ECPJSON.quote          // 同一套手写转义（`xk.L`）
        let s = "{"
            + "\"name\":\(q(name)),"
            + "\"ssid\":\(q(ssid)),"
            + "\"psk\":\(q(psk)),"
            + "\"mac\":\(q(mac)),"
            + "\"freq\":\(freq),"
            + "\"port\":\(port),"
            + "\"type\":\(type),"
            + "\"ipAddress\":\(q(ipAddress)),"
            + "\"channel\":\(channel),"
            + "\"band\":\(band)"
            + "}"
        return Array(s.utf8)
    }
}
