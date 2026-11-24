//
//  WFDParameters.swift
//  PandaLink
//
//  Wi-Fi Display（Miracast）能力协商串。
//
//  全部字面量来自 `libovmsink.so` 的 .rodata（偏移 0x124359–0x124ddc），
//  这是车机侧 sink SDK 真实使用的字符串，不是猜的：
//
//    0x124359  RTSP/1.0 200 OK
//    0x12436b  Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER
//    0x12448c  wfd_car_display_mode: mode=0;display=%d:%d;dpi=%d;fps=%d
//    0x1244c7  wfd_video_formats: 
//    0x1244dd  wfd_audio_codecs: AAC 0000000F 00
//    0x124500  wfd_client_rtp_ports: RTP/AVP/
//    0x12451f  TCP;
//    0x124524  interleaved
//    0x124530  UDP;unicast 19000 0
//    0x124544   mode=play
//    0x124551  wfd_uibc_capability: input_category_list=GENERIC;generic_cap_list=Keyboard, Mouse, SingleTouch;hidc_cap_list=none;port=none
//    0x1245cd  ;uibc_encrypted=true
//    0x1245e4  ovm_control_capability: supported
//    0x124608  wfd_standby_resume_capability: supported
//    0x124633  wfd_audio_latency: %d
//    0x12464b  iccoa_support_hevc: supported
//    0x12466b  iccoa_support_fusion: supported
//    0x12468d  mIsSupportAvRawPacket=%d
//    0x1246a6  wfd_av_raw_packet: true
//    0x1246c0  Content-Type: text/parameters
//    0x1246e0  Content-Length: %d
//    0x124793  run on MODE_ELEMENTARY_STREAMS
//    0x1247b2  run on MODE_TRANSPORT_STREAM
//
//  `iccoa_*` 两条是车厂（ICCOA 车联联盟）私有扩展头，标准 Miracast 里没有。
//

import Foundation

// MARK: - 头名常量

enum WFDHeader {
    static let clientRTPPorts   = "wfd_client_rtp_ports"
    static let videoFormats     = "wfd_video_formats"
    static let audioCodecs      = "wfd_audio_codecs"
    static let uibcCapability   = "wfd_uibc_capability"
    static let standbyResume    = "wfd_standby_resume_capability"
    static let audioLatency     = "wfd_audio_latency"
    static let videoFormats3D   = "wfd_3d_video_formats"
    static let contentProtect   = "wfd_content_protection"
    static let displayEDID      = "wfd_display_edid"
    static let coupledSink      = "wfd_coupled_sink"
    static let triggerMethod    = "wfd_trigger_method"
    static let presentationURL  = "wfd_presentation_URL"
    static let avRawPacket      = "wfd_av_raw_packet"
    static let carDisplayMode   = "wfd_car_display_mode"
    static let ovmControl       = "ovm_control_capability"
    static let iccoaHEVC        = "iccoa_support_hevc"
    static let iccoaFusion      = "iccoa_support_fusion"
    static let session          = "Session"
    static let transport        = "Transport"
    static let publicMethods    = "Public"
    static let cseq             = "CSeq"
    static let contentType      = "Content-Type"
    static let contentLength    = "Content-Length"
    static let userAgent        = "User-Agent"
    static let date             = "Date"
}

// MARK: - 传输模式

/// `wfd_client_rtp_ports` 的两种形态（对应 0x12451f 的 `TCP;interleaved` 与 0x124530 的 `UDP;unicast`）
enum WFDTransportMode: String {
    case tcpInterleaved = "TCP;interleaved"
    case tcpUnicast     = "TCP;unicast"
    case udpUnicast     = "UDP;unicast"
}

/// RTSP 承载的媒体模式（对应 0x124793 / 0x1247b2 两条日志）
enum WFDMediaMode: String {
    /// 裸 ES（raw H.264 / raw AAC），不带 TS 封装
    case elementaryStreams = "MODE_ELEMENTARY_STREAMS"
    /// MPEG2-TS 封装
    case transportStream   = "MODE_TRANSPORT_STREAM"
}

// MARK: - 视频格式位图

/// WFD 1.0 的 H.264 profile 编码（`wfd_video_formats` 第 3 个字段）
enum WFDH264Profile: UInt8 {
    case cbp = 0x01     // Constrained Baseline
    case chp = 0x02     // Constrained High
}

/// `wfd_video_formats` 的 CEA 分辨率位图。这里只列出本项目会用到的。
enum WFDResolution: UInt32, CaseIterable {
    case r640x480p60  = 0x0000_0001
    case r1280x720p30 = 0x0000_0004
    case r1280x720p60 = 0x0000_0008
    case r1920x1080p30 = 0x0000_0040
    case r1920x1080p60 = 0x0000_0080

    var size: (width: Int, height: Int) {
        switch self {
        case .r640x480p60:   return (640, 480)
        case .r1280x720p30, .r1280x720p60:  return (1280, 720)
        case .r1920x1080p30, .r1920x1080p60: return (1920, 1080)
        }
    }
}

// MARK: - 能力集合

/// 一台 WFD 端点的能力描述。`headers()` 产出 `GET_PARAMETER` 响应 / `SET_PARAMETER` 请求里那批 `wfd_*` 行。
struct WFDCapabilities {

    /// `wfd_car_display_mode`：`display=%d:%d;dpi=%d;fps=%d`
    var displayWidth: Int = 1280
    var displayHeight: Int = 720
    var dpi: Int = 240
    var fps: Int = 30

    /// `wfd_video_formats` 里声明的 profile / level（level 4.1 = 0x08）
    var h264Profile: WFDH264Profile = .cbp
    var h264Level: UInt8 = 0x08

    /// 支持的分辨率（按位或）
    var resolutions: UInt32 = WFDResolution.r1280x720p30.rawValue
        | WFDResolution.r1280x720p60.rawValue
        | WFDResolution.r1920x1080p30.rawValue

    /// 传输偏好。`libovmsink` 两条都支持，优先 TCP 交织（不需要额外开端口）
    var transport: WFDTransportMode = .tcpInterleaved
    /// UDP 模式下的本地 RTP 端口（对应 0x124530 的 `UDP;unicast 19000 0`）
    var udpRTSPort: UInt16 = 19000

    /// `wfd_uibc_capability` 里的 `port=`。`none` 表示不支持独立 UIBC 端口，
    /// 触控走 RTSP 连接的 M? 通道（对齐 0x124551 的 `port=none`）。
    var uibcPort: UInt16? = nil
    /// 是否声明 `;uibc_encrypted=true`（对齐 0x1245cd）
    var uibcEncrypted: Bool = true

    /// 是否声明 `wfd_av_raw_packet: true`（对齐 0x1246a6 / `mIsSupportAvRawPacket`）
    var avRawPacket: Bool = true

    /// 音频延迟（ms），对齐 `wfd_audio_latency: %d`
    var audioLatencyMs: Int = 0

    /// 是否声明车厂私有扩展
    var supportHEVC: Bool = false
    var supportFusion: Bool = false

    // MARK: 生成

    /// `wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play`
    func clientRTPPortsLine() -> String {
        switch transport {
        case .tcpInterleaved:
            return "RTP/AVP/TCP;interleaved mode=play"
        case .tcpUnicast:
            return "RTP/AVP/TCP;unicast;client_port=\(udpRTSPort)-\(udpRTSPort + 1) mode=play"
        case .udpUnicast:
            return "RTP/AVP/UDP;unicast \(udpRTSPort) 0 mode=play"
        }
    }

    /// `wfd_video_formats: 00 00 <profile> <level> <resBitmap:8hex> 00 0000 0000 00 none none`
    ///
    /// 字段顺序按 WFD 1.0 spec：
    ///   native / preferred-display-mode-supported / profile / level /
    ///   CEA-resolutions / VESA-resolutions / HH-resolutions / latency /
    ///   min-slice-size / slice-enc-params / frame-rate-control-support /
    ///   max-hres / max-vres / min-hres / min-vres / (hres vres)*
    func videoFormatsLine() -> String {
        let native = "00"                   // 不指定 native
        let preferred = "00"                // 不支持 preferred-display-mode
        let profile = String(format: "%02x", h264Profile.rawValue)
        let level = String(format: "%02x", h264Level)
        let cea = String(format: "%08x", resolutions)
        // latency=00, min-slice-size=0000, slice-enc-params=0000,
        // frame-rate-control-support=00, max/min hres/vres 全 none → 用 bits 表示
        return "\(native) \(preferred) \(profile) \(level) \(cea) "
            + "00 0000 0000 00 none none"
    }

    /// `wfd_audio_codecs: AAC 0000000F 00`
    func audioCodecsLine() -> String { "AAC 0000000F 00" }

    /// `wfd_uibc_capability: input_category_list=...;port=...`（可选 `;uibc_encrypted=true`）
    func uibcCapabilityLine() -> String {
        let portPart = uibcPort.map { "\($0)" } ?? "none"
        var s = "input_category_list=GENERIC;"
            + "generic_cap_list=Keyboard, Mouse, SingleTouch;"
            + "hidc_cap_list=none;port=\(portPart)"
        if uibcEncrypted { s += ";uibc_encrypted=true" }
        return s
    }

    /// `wfd_car_display_mode: mode=0;display=1280:720;dpi=240;fps=30`
    func carDisplayModeLine() -> String {
        "mode=0;display=\(displayWidth):\(displayHeight);dpi=\(dpi);fps=\(fps)"
    }

    /// 一整套能力行，顺序与 `libovmsink` 一致
    func headers() -> [(String, String)] {
        var out: [(String, String)] = [
            (WFDHeader.carDisplayMode, String(carDisplayModeLine().dropFirst("mode=0;".count))),
            (WFDHeader.videoFormats, videoFormatsLine()),
            (WFDHeader.audioCodecs, audioCodecsLine()),
            (WFDHeader.clientRTPPorts, clientRTPPortsLine()),
            (WFDHeader.uibcCapability, uibcCapabilityLine()),
            (WFDHeader.ovmControl, "supported"),
            (WFDHeader.standbyResume, "supported"),
            (WFDHeader.audioLatency, "\(audioLatencyMs)"),
        ]
        if supportHEVC { out.append((WFDHeader.iccoaHEVC, "supported")) }
        if supportFusion { out.append((WFDHeader.iccoaFusion, "supported")) }
        if avRawPacket { out.append((WFDHeader.avRawPacket, "true")) }
        return out
    }

    /// 服务端（sink 侧）在 `GET_PARAMETER` 响应里的 `text/parameters` 正文。
    /// 每条一行，`key: value`，UTF-8，长度写进 `Content-Length`。
    func parameterBody() -> String {
        headers().map { "\($0.0): \($0.1)" }.joined(separator: "\r\n") + "\r\n"
    }

    /// 解析对端 `text/parameters` 正文。返回 key → value（value 已去掉前导空格）
    static func parseParameters(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, let colon = trimmed.firstIndex(of: ":") else { continue }
            let key = String(trimmed[trimmed.startIndex..<colon])
                .trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[trimmed.index(after: colon)...])
                .trimmingCharacters(in: .whitespaces)
            out[key] = value
        }
        return out
    }
}

// MARK: - 端口

extension CarLinkPorts {
    /// WFD 的 RTSP 端口。`p/ga.smali:70` 的 `ServerSocket(0x1c44, 4, 127.0.0.1)` = 7236，
    /// 那是自环测试；真实会话里对端也是 7236。
    static let wfdRTSP: UInt16 = 7236
    /// TCP 交织模式下 RTP/RTCP 的通道号（`Transport: RTP/AVP/TCP;interleaved=0-1`）
    static let rtpInterleaveChannel: UInt8 = 0
    static let rtcpInterleaveChannel: UInt8 = 1
}
