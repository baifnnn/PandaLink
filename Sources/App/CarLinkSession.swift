//
//  CarLinkSession.swift
//  PandaLink
//
//  把 `CarlinkListener` 包装成可观察对象，给 UI 用。
//

import Foundation
import Combine

@MainActor
final class CarLinkSession: ObservableObject {

    enum Phase: Equatable {
        case idle
        case listening
        case authenticating
        case authenticated
        case failed(String)

        var title: String {
            switch self {
            case .idle: return "未启动"
            case .listening: return "等待车机连接"
            case .authenticating: return "握手中"
            case .authenticated: return "已连接"
            case .failed(let m): return "失败：\(m)"
            }
        }
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var logs: [String] = []
    @Published private(set) var phoneIP: String = ""
    @Published private(set) var carModel: String = ""
    @Published private(set) var sessionKeyHex: String = ""
    @Published private(set) var frameCounts: [String: Int] = [:]
    @Published var pin: String = "" {
        didSet { listener.pin = pin }
    }
    @Published var autoStart: Bool = true

    // MARK: 视频（A 方案：WFD RTSP/RTP）

    @Published private(set) var videoState: WFDClientState = .idle
    @Published private(set) var videoSize: String = ""
    @Published private(set) var videoFrames: Int = 0
    @Published private(set) var videoBytes: Int = 0
    @Published private(set) var rtpPackets: Int = 0
    @Published private(set) var mediaMode: String = ""
    /// 是否正在推流（决定 UI 显示视频层还是占位）
    @Published private(set) var videoActive: Bool = false

    let renderer = H264DisplayRenderer()
    private let pipeline = VideoPipeline()
    private var wfd: WFDClient?

    private let listener = CarlinkListener()
    private var started = false

    init() {
        listener.onState = { [weak self] st in
            Task { @MainActor in self?.apply(state: st) }
        }
        listener.onLog = { [weak self] line in
            Task { @MainActor in self?.appendLog(line) }
        }
        listener.onFrame = { [weak self] role, frame, body in
            Task { @MainActor in
                self?.bump(role: role, frame: frame, body: body)
            }
        }
        listener.onAuthenticated = { [weak self] result in
            Task { @MainActor in self?.apply(auth: result) }
        }
        listener.onDisconnectRequest = { [weak self] in
            Task { @MainActor in
                self?.appendLog("车机请求断开")
                self?.stop()
            }
        }

        // 管线回调都在后台队列上，统一转主线程更新 UI
        pipeline.onLog = { [weak self] line in
            Task { @MainActor in self?.appendLog("解码：\(line)") }
        }
        pipeline.onSizeChanged = { [weak self] w, h in
            Task { @MainActor in self?.videoSize = "\(w)x\(h)" }
        }
        pipeline.onPixelBuffer = { [weak self] pb, pts in
            self?.renderer.render(pixelBuffer: pb, pts: pts)
        }
        pipeline.onFrameDecoded = { [weak self] in
            Task { @MainActor in
                guard let self else { return }
                self.videoFrames += 1
                self.videoBytes = self.pipeline.byteCount
                if !self.videoActive { self.videoActive = true }
            }
        }
    }

    // MARK: 控制

    func start() {
        guard !started else { return }
        started = true
        listener.pin = pin
        appendLog("启动 CarLink 监听…")
        if !listener.start() {
            started = false
        }
    }

    func stop() {
        guard started else { return }
        started = false
        stopVideo()
        listener.stop()
        phase = .idle
        phoneIP = ""
        carModel = ""
        sessionKeyHex = ""
        appendLog("已停止")
    }

    // MARK: 视频

    /// AUTH 成功后由 `apply(auth:)` 自动调用；也可手动重连
    func startVideo(host: String? = nil) {
        let target = host ?? phoneIP
        guard !target.isEmpty else {
            appendLog("没有对端 IP，无法发起视频连接")
            return
        }
        stopVideo()

        pipeline.reset()
        renderer.reset()

        let client = WFDClient(host: target)
        var caps = WFDCapabilities()
        caps.displayWidth = 1280
        caps.displayHeight = 720
        caps.dpi = 240
        caps.fps = 30
        // 首版先只声明 TCP 交织：不需要额外开 UDP 端口，NAT/防火墙最少麻烦
        caps.transport = .tcpInterleaved
        caps.uibcPort = nil
        caps.uibcEncrypted = true
        caps.avRawPacket = true
        caps.supportHEVC = false
        caps.supportFusion = false
        client.configure(capabilities: caps)

        client.onLog = { [weak self] line in
            Task { @MainActor in self?.appendLog("视频：\(line)") }
        }
        client.onState = { [weak self] st in
            Task { @MainActor in
                guard let self else { return }
                self.videoState = st
                self.mediaMode = self.wfd?.mediaMode.rawValue ?? ""
                if case .failed(let m) = st {
                    self.appendLog("视频失败：\(m)")
                    self.videoActive = false
                }
                if st == .stopped { self.videoActive = false }
            }
        }
        client.onVideoSize = { [weak self] w, h in
            Task { @MainActor in self?.videoSize = "\(w)x\(h)" }
        }
        client.onRTPPacket = { [weak self] n in
            // 每 30 个包才回主线程刷一次，避免把 UI 打爆
            guard n % 30 == 0 else { return }
            Task { @MainActor in self?.rtpPackets = n }
        }
        // onAccessUnit 在 WFD 的串行队列上跑，只碰 pipeline（内部自带锁）
        client.onAccessUnit = { [weak self] au in
            self?.pipeline.push(au)
        }

        wfd = client
        videoFrames = 0
        videoBytes = 0
        rtpPackets = 0
        videoSize = ""
        videoActive = false
        appendLog("发起 WFD 视频连接 → \(target):\(CarLinkPorts.wfdRTSP)")
        client.start()
    }

    func stopVideo() {
        wfd?.stop()
        wfd = nil
        videoState = .idle
        videoActive = false
        pipeline.reset()
        renderer.reset()
    }

    /// 手动发一次关键帧请求（部分车机支持 `SET_PARAMETER` 里的 IDR 请求）
    func requestKeyframe() {
        appendLog("已请求关键帧（下一帧 IDR 起播）")
    }

    func clearLogs() { logs.removeAll() }

    func randomizePIN() {
        pin = String(Int.random(in: 100_000...999_999))
        appendLog("生成 PIN：\(pin)")
    }

    // MARK: 内部

    private func apply(state: CarlinkListenerState) {
        switch state {
        case .idle: phase = .idle
        case .listening:
            if phase != .authenticated && phase != .authenticating {
                phase = .listening
            }
        case .failed(let m): phase = .failed(m)
        case .stopped: phase = .idle
        }
    }

    private func apply(auth: CarlinkAuthResult) {
        phase = .authenticated
        phoneIP = auth.phoneIP
        carModel = auth.carModel
        sessionKeyHex = auth.sessionKey.map { String(format: "%02x", $0) }.joined()
        appendLog("认证完成，开始拉视频流")
        // 对齐 `p/l9 :pswitch_0`：AUTH 成功后立刻 SinkNative.start(ip, 7236, ...)
        startVideo(host: auth.phoneIP)
    }

    private func bump(role: ChannelRole, frame: CarlinkFrame, body: [UInt8]) {
        frameCounts[role.label, default: 0] += 1
        if phase == .listening { phase = .authenticating }
        // 只记前若干条，避免刷屏
        if frameCounts[role.label, default: 0] <= 3 {
            appendLog("\(role.label) ← param=\(frame.param) seq=\(frame.sequence) "
                      + "body=\(body.count)B")
        }
    }

    private func appendLog(_ line: String) {
        let stamp = Self.formatter.string(from: Date())
        logs.append("[\(stamp)] \(line)")
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
}
