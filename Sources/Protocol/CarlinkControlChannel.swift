//
//  CarlinkControlChannel.swift
//  PandaLink
//
//  CONTROL 通道（57219）的报文处理。
//
//  依据 `p/r9;->a(Lp/k9;Lp/u9;[B)V`（全文读完）。
//  帧体是 protobuf `UCarProto$ControlIndex`，**子类型由帧头 param（`u9.h`）决定**，
//  不是靠 ControlIndex 里哪个 oneof 字段被设置 —— 这一点和常见 protobuf RPC 不同。
//
//  param → 处理：
//    1  (0x01) heartbeat         → 回 ControlIndex{heartbeat{timestamp}}，param=1
//    2  (0x02) getPortRequest    → 查端口表，回 ControlIndex{getPortResponse{result=SUCCESS,port}}，param=3
//    23 (0x17) disconnect        → 日志 "phone requested disconnect"，回调上层断开
//    24 (0x18) getUCarConfigReq  → 回 ControlIndex{getUCarConfigResponse{…}}，param=25 (0x19)
//    其它                        → return（静默丢弃）
//
//  getPortRequest 的端口表（`r9.smali:263-283`）：
//    SENSOR(1) → 0xdf97 = 57239
//    AUDIO(2)  → 0xdf8d = 57229
//    UIBC(3)   → 0x10e1 = 4321     ← 这个 4321 不在六端口表里，是 UIBC 单独协商出来的
//    其它      → 0xdf97（默认落在 SENSOR）
//
//  getUCarConfigResponse 的字段值全部来自 `p/p9`（车机配置对象）+ 一批字面量：
//    carBrMac = p9.e, screenWidth = p9.a, screenHeight = p9.b, dpi = p9.c,
//    videoDisplayWidth = 1280, videoDisplayHeight = 720, fps = 30,
//    isSupportP2P = true, isSupportSoftAP = true, isDataTransMode = false,
//    default5GChannel = 149, isSupportCamera = false, isSupportMic = true,
//    isSupportLowLatencyDecodingMode = true, isSupportVoiceWaken = true,
//    sdkVersion = p9.d, workModes = 0, isSupportHevc = true
//

import Foundation

/// 对齐 `p/p9` —— 车机/本机的显示配置
struct CarlinkDisplayConfig {
    var screenWidth: Int = 1280
    var screenHeight: Int = 720
    var dpi: Int = 240
    var carBrMac: [UInt8] = []
    var sdkVersion: String = ""

    /// 视频流固定 720p30（`r9` 里的 0x500 / 0x2d0 / 0x1e）
    static let videoWidth = 1280
    static let videoHeight = 720
    static let fps = 30
    static let default5GChannel = 149
}

/// CONTROL 子类型（帧头 param）
enum CarlinkControlSubtype: UInt16 {
    case heartbeat = 1
    case getPortRequest = 2
    case getPortResponse = 3
    case disconnect = 23
    case getUCarConfigRequest = 24
    case getUCarConfigResponse = 25
}

/// 端口协商结果
enum CarlinkPortNegotiation {
    /// 对齐 `r9.smali:263-283`
    static func port(for serverType: PBServerType) -> UInt16 {
        switch serverType {
        case .sensor: return CarLinkPorts.sensor   // 0xdf97 = 57239
        case .audio: return CarLinkPorts.media     // 0xdf8d = 57229
        case .uibc: return 4321                    // 0x10e1
        case .unknown: return CarLinkPorts.sensor
        }
    }
}

/// CONTROL 通道处理器
final class CarlinkControlChannel {

    private let config: CarlinkDisplayConfig
    private let send: (CarlinkChannelID, UInt16, [UInt8]) -> Void
    private let onDisconnect: () -> Void

    init(config: CarlinkDisplayConfig,
         send: @escaping (CarlinkChannelID, UInt16, [UInt8]) -> Void,
         onDisconnect: @escaping () -> Void) {
        self.config = config
        self.send = send
        self.onDisconnect = onDisconnect
    }

    /// 处理一帧。`body` 是已经过接收侧解密的载荷（AUTH 完成后就是明文 protobuf）。
    func handle(_ frame: CarlinkFrame, body: [UInt8]? = nil) {
        let payload = body ?? frame.body
        guard let idx = try? PBControlIndex.decode(payload) else { return }

        switch CarlinkControlSubtype(rawValue: frame.param) {
        case .heartbeat:
            guard let hb = idx.heartbeat else { return }
            // 原样回带 timestamp（`r9` 把请求里的 timestamp 直接写回去）
            var w = PBWriter()
            w.writeBytes(1, hb)                 // ControlIndex.heartbeat = field 1
            send(.control, CarlinkControlSubtype.heartbeat.rawValue, w.bytes)

        case .getPortRequest:
            guard let req = idx.getPortRequest else { return }
            let port = CarlinkPortNegotiation.port(for: req.serverType)
            let resp = PBGetPortResponse(result: PBPortResult.success.rawValue, port: Int32(port))
            send(.control, CarlinkControlSubtype.getPortResponse.rawValue,
                 PBControlIndex.portResponse(resp))

        case .disconnect:
            onDisconnect()

        case .getUCarConfigRequest:
            send(.control, CarlinkControlSubtype.getUCarConfigResponse.rawValue,
                 Self.ucarConfigResponse(config: config))

        default:
            return
        }
    }

    /// 对齐 `r9` 的 `:cond_0` 分支 —— GetUCarConfigResponse 全部字段
    static func ucarConfigResponse(config: CarlinkDisplayConfig) -> [UInt8] {
        // 先组 GetUCarConfigResponse（字段号见 ucarproto_schema.txt）
        var cfg = PBWriter()
        cfg.writeBytes(1, config.carBrMac)
        cfg.writeInt32(2, Int32(config.screenWidth))
        cfg.writeInt32(3, Int32(config.screenHeight))
        cfg.writeInt32(4, Int32(config.dpi))
        cfg.writeInt32(5, Int32(CarlinkDisplayConfig.videoWidth))
        cfg.writeInt32(6, Int32(CarlinkDisplayConfig.videoHeight))
        cfg.writeInt32(7, Int32(CarlinkDisplayConfig.fps))
        cfg.writeBool(8, true)                                        // isSupportP2P
        cfg.writeBool(9, true)                                        // isSupportSoftAP
        cfg.writeBool(10, false)                                      // isDataTransMode
        cfg.writeInt32(11, Int32(CarlinkDisplayConfig.default5GChannel))
        cfg.writeBool(12, false)                                      // isSupportCamera
        cfg.writeBool(13, true)                                       // isSupportMic
        cfg.writeBool(14, true)                                       // isSupportLowLatencyDecodingMode
        cfg.writeBool(15, true)                                       // isSupportVoiceWaken
        cfg.writeString(17, config.sdkVersion)
        // 字段号实测自 UCarProto$GetUCarConfigResponse.smali 的 *_FIELD_NUMBER：
        // 18=workModes / 19=isSupportPoiNav / 20=isSupportRotation / 21=isSupportHomeKey
        // 22=isSupportBackKey / 23=isSupportHevc / 24=realDpi / 25=vin
        cfg.writeInt32(18, 0)                                         // workModes
        cfg.writeBool(23, true)                                       // isSupportHevc

        // 包进 ControlIndex.getUcarConfigResponse（field 25）
        var w = PBWriter()
        w.writeMessage(25, cfg.bytes)
        return w.bytes
    }
}
