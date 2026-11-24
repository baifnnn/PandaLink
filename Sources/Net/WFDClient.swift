//
//  WFDClient.swift
//  PandaLink
//
//  Wi-Fi Display Sink：主动向车机（source）发起 RTSP 会话，把 M1~M7 走完，
//  SETUP 之后接收 RTP，解出 H.264 访问单元交给 `onAccessUnit`。
//
//  流程（标准 Miracast + `libovmsink.so` 里的实际实现）：
//    1. TCP 连到 `host:7236`
//    2. OPTIONS * RTSP/1.0
//       ← Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER
//    3. GET_PARAMETER（无 body），拿 source 的能力
//       ← wfd_video_formats / wfd_audio_codecs / wfd_client_rtp_ports / ...
//    4. SET_PARAMETER，把我们作为 sink 的能力报上去（M3 应答）
//    5. SET_PARAMETER 带 wfd_trigger_method: SETUP  → 或直接发 SETUP
//    6. SETUP rtsp://<host>/wfd1.0/streamid=0
//       Transport: RTP/AVP/TCP;interleaved=0-1
//       ← Session: <id>
//    7. PLAY
//    8. 收 RTP：TCP 交织模式下，每个 RTP 包前面有 4 字节 `$ <channel> <len:2>`
//       之后周期性发 GET_PARAMETER 保活
//
//  UDP 模式下 RTP/RTCP 走独立 UDP 端口（默认 19000/19001）。
//

import Foundation
import Network

enum WFDClientState: Equatable {
    case idle
    case connecting
    case options
    case negotiated          // M3 已发，等 source 的 SETUP 触发或直接 SETUP
    case setup
    case playing
    case failed(String)
    case stopped

    var label: String {
        switch self {
        case .idle:        return "未启动"
        case .connecting:  return "连接车机…"
        case .options:     return "能力协商中"
        case .negotiated:  return "等待 SETUP"
        case .setup:       return "建立会话"
        case .playing:     return "接收视频流"
        case .failed(let m): return "失败：\(m)"
        case .stopped:     return "已停止"
        }
    }
}

final class WFDClient {

    // MARK: 回调

    var onState: ((WFDClientState) -> Void)?
    var onLog: ((String) -> Void)?
    /// 一个完整访问单元（Annex-B，含 SPS/PPS 前缀）
    var onAccessUnit: (([UInt8]) -> Void)?
    /// 对端协商出来的视频尺寸（从 wfd_video_formats 或 SPS 解出）
    var onVideoSize: ((Int, Int) -> Void)?
    /// 每收一个 RTP 包回调一次（用于 UI 计数，节流由调用方负责）
    var onRTPPacket: ((Int) -> Void)?

    // MARK: 状态

    private(set) var state: WFDClientState = .idle {
        didSet { onState?(state) }
    }

    private let host: String
    private let port: UInt16
    private let queue = DispatchQueue(label: "top.shareway.pandalink.wfd")

    private var connection: NWConnection?
    private var rtspDecoder = RTSPStreamDecoder()

    private var cseq = 1
    private var session: String?
    private var presentationURL: String?

    private var capabilities = WFDCapabilities()
    private var peerParameters: [String: String] = [:]

    /// 协商结果
    private(set) var transportMode: WFDTransportMode = .tcpInterleaved
    private(set) var mediaMode: WFDMediaMode = .transportStream

    // 媒体解包
    private let depacketizer = H264Depacketizer()
    private let tsDemuxer = TSDemuxer()

    /// TCP 上的统一入站缓冲（RTSP 文本 + `$` 交织帧）
    private var inbound: [UInt8] = []
    /// 判定是否 TS 用的样本计数（头几个包投票）
    private var sniffCount = 0
    private var sniffTSCount = 0

    private static let maxInterleavedFrame = 4 * 1024 * 1024

    // 保活
    private var keepAliveTimer: DispatchSourceTimer?

    private(set) var stats = Stats()
    struct Stats {
        var rtspMessages = 0
        var rtpPackets = 0
        var rtpBytes = 0
        var accessUnits = 0
    }

    // MARK: 生命周期

    init(host: String, port: UInt16 = CarLinkPorts.wfdRTSP) {
        self.host = host
        self.port = port
    }

    func configure(capabilities: WFDCapabilities) {
        self.capabilities = capabilities
    }

    func start() {
        guard state == .idle || state == .stopped || isFailed else {
            log("已在运行中，忽略重复启动")
            return
        }
        rtspDecoder.reset()
        depacketizer.reset()
        tsDemuxer.reset()
        inbound.removeAll()
        sniffCount = 0
        sniffTSCount = 0
        cseq = 1
        session = nil
        stats = Stats()

        state = .connecting
        log("连接车机 RTSP：\(host):\(port)")

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            state = .failed("端口非法")
            return
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.noDelay = true
        let conn = NWConnection(host: NWEndpoint.Host(host),
                                port: nwPort,
                                using: params)
        connection = conn
        conn.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.log("RTSP 已连接")
                self.state = .options
                self.receiveLoop()
                self.sendOptions()
            case .failed(let e):
                self.fail("连接失败：\(e.localizedDescription)")
            case .cancelled:
                if self.state != .stopped { self.state = .stopped }
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    func stop() {
        keepAliveTimer?.cancel()
        keepAliveTimer = nil
        if state == .playing || state == .setup {
            // 尽量礼貌地 TEARDOWN，失败也无所谓
            if let url = presentationURL ?? .some(streamURL()) {
                send(.teardown, uri: url)
            }
        }
        connection?.cancel()
        connection = nil
        depacketizer.reset()
        tsDemuxer.reset()
        inbound.removeAll()
        session = nil
        if state != .failed("") { state = .stopped }
    }

    private var isFailed: Bool {
        if case .failed = state { return true }
        return false
    }

    // MARK: RTSP 发送

    private func streamURL() -> String {
        "rtsp://\(host)/wfd1.0/streamid=0"
    }

    private func baseURL() -> String {
        "rtsp://\(host)/wfd1.0"
    }

    private func nextCSeq() -> Int {
        defer { cseq += 1 }
        return cseq
    }

    @discardableResult
    private func send(_ method: RTSPMethod,
                      uri: String,
                      headers: [(String, String)] = [],
                      body: String = "") -> Int {
        let c = nextCSeq()
        let msg = RTSPMessage.request(method, uri: uri, cseq: c,
                                      headers: headers, body: body)
        let data = msg.encoded()
        log("→ \(method.rawValue) \(uri)  (\(data.count) B)")
        connection?.send(content: data, completion: .contentProcessed { [weak self] err in
            if let err { self?.log("发送失败：\(err.localizedDescription)") }
        })
        return c
    }

    // MARK: 各阶段

    private func sendOptions() {
        send(.options, uri: "*")
    }

    private func sendGetParameter() {
        send(.getParameter, uri: baseURL())
    }

    /// M3：把 sink 能力报给 source
    private func sendSetParameterCapabilities() {
        let body = capabilities.parameterBody()
        send(.setParameter, uri: baseURL(), body: body)
    }

    private func sendSetup() {
        let transport: String
        switch capabilities.transport {
        case .tcpInterleaved:
            transport = "RTP/AVP/TCP;interleaved="
                + "\(CarLinkPorts.rtpInterleaveChannel)-\(CarLinkPorts.rtcpInterleaveChannel)"
        case .tcpUnicast:
            transport = "RTP/AVP/TCP;unicast;client_port="
                + "\(capabilities.udpRTSPort)-\(capabilities.udpRTSPort + 1)"
        case .udpUnicast:
            transport = "RTP/AVP/UDP;unicast;client_port="
                + "\(capabilities.udpRTSPort)-\(capabilities.udpRTSPort + 1)"
        }
        var headers: [(String, String)] = [(WFDHeader.transport, transport)]
        if let s = session { headers.append((WFDHeader.session, s)) }
        state = .setup
        log("SETUP transport = \(transport)")
        send(.setup, uri: streamURL(), headers: headers)
    }

    private func sendPlay() {
        var headers: [(String, String)] = []
        if let s = session { headers.append((WFDHeader.session, s)) }
        send(.play, uri: streamURL(), headers: headers)
        state = .playing
        startKeepAlive()
    }

    private func startKeepAlive() {
        keepAliveTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 25, repeating: 25)
        t.setEventHandler { [weak self] in
            guard let self, self.state == .playing else { return }
            self.send(.getParameter, uri: self.baseURL())
        }
        t.resume()
        keepAliveTimer = t
    }

    // MARK: 收

    private func receiveLoop() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.handleIncoming([UInt8](data))
            }
            if let error {
                self.fail("接收失败：\(error.localizedDescription)")
                return
            }
            if isComplete {
                self.log("RTSP 对端关闭")
                self.stop()
                return
            }
            self.receiveLoop()
        }
    }

    /// TCP 上 RTSP 文本与 `$` 交织帧混流，用一个统一缓冲做状态机分流。
    /// `$` 帧：`0x24 | channel | len(2, BE) | payload`
    /// 文本帧：头部到 `\r\n\r\n`，正文长度取 `Content-Length`
    private func handleIncoming(_ chunk: [UInt8]) {
        inbound.append(contentsOf: chunk)
        processInbound()
    }

    private func processInbound() {
        while true {
            guard !inbound.isEmpty else { return }

            // 交织帧
            if inbound[0] == 0x24 {
                guard inbound.count >= 4 else { return }
                let channel = inbound[1]
                let len = (Int(inbound[2]) << 8) | Int(inbound[3])
                guard len <= WFDClient.maxInterleavedFrame else {
                    log("交织帧长度非法 \(len)，丢弃整个缓冲")
                    inbound.removeAll(keepingCapacity: true)
                    return
                }
                let total = 4 + len
                guard inbound.count >= total else { return }
                let payload = Array(inbound[4..<total])
                inbound.removeFirst(total)
                if channel == CarLinkPorts.rtpInterleaveChannel {
                    handleRTP(payload)
                }
                continue
            }

            // RTSP 文本
            guard let headerEnd = findRTSPHeaderEnd() else {
                if inbound.count > RTSPStreamDecoder.maxHeaderBytes {
                    log("RTSP 头部超长，丢弃")
                    inbound.removeAll(keepingCapacity: true)
                }
                return
            }
            let bodyLen = contentLength(in: Array(inbound[0..<headerEnd]))
            guard bodyLen <= RTSPStreamDecoder.maxBodyBytes else {
                log("RTSP 正文超长（\(bodyLen)），丢弃")
                inbound.removeAll(keepingCapacity: true)
                return
            }
            let total = headerEnd + bodyLen
            guard inbound.count >= total else { return }

            let full = Array(inbound[0..<total])
            inbound.removeFirst(total)
            do {
                handleRTSP(try RTSPMessage.parse(full))
            } catch {
                log("RTSP 解析失败：\(error)")
            }
        }
    }

    private func findRTSPHeaderEnd() -> Int? {
        let n = inbound.count
        guard n >= 2 else { return nil }
        var i = 0
        while i + 1 < n {
            if inbound[i] == 0x0D, i + 3 < n,
               inbound[i + 1] == 0x0A, inbound[i + 2] == 0x0D, inbound[i + 3] == 0x0A {
                return i + 4
            }
            if inbound[i] == 0x0A, inbound[i + 1] == 0x0A { return i + 2 }
            i += 1
        }
        return nil
    }

    private func contentLength(in header: [UInt8]) -> Int {
        let text = String(decoding: header, as: UTF8.self)
        for line in text.split(whereSeparator: { $0 == "\n" }) {
            let l = line.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if l.hasPrefix("content-length:") {
                let v = l.dropFirst("content-length:".count)
                    .trimmingCharacters(in: .whitespaces)
                return Int(v) ?? 0
            }
        }
        return 0
    }

    // MARK: RTSP 分派

    private func handleRTSP(_ msg: RTSPMessage) {
        stats.rtspMessages += 1

        if msg.isResponse {
            let code = msg.statusCode ?? 0
            let c = msg.cseq ?? -1
            log("← \(code) \(msg.reason ?? "")  CSeq=\(c)")
            if let s = msg.session { session = s }

            if code != 200 {
                if code >= 400 {
                    log("对端报错：\(code) \(msg.reason ?? "")")
                }
            }

            // 根据当前阶段推进
            handleResponseBody(msg)
            advance()
        } else if let method = msg.method {
            handleRequest(msg, method: method)
        }
    }

    private func handleResponseBody(_ msg: RTSPMessage) {
        guard !msg.body.isEmpty else { return }
        let ct = msg.contentType ?? ""
        if ct.contains("text/parameters") {
            let params = WFDCapabilities.parseParameters(msg.body)
            if !params.isEmpty {
                peerParameters.merge(params) { _, new in new }
                log("对端参数：\(params.keys.sorted().joined(separator: ", "))")
                applyPeerParameters(params)
            }
        } else if ct.contains("application/sdp") {
            applySDP(msg.body)
        }
    }

    private func applyPeerParameters(_ p: [String: String]) {
        if let url = p[WFDHeader.presentationURL] {
            presentationURL = url
            log("presentation_URL = \(url)")
        }
        if let fmts = p[WFDHeader.videoFormats] {
            log("对端 wfd_video_formats = \(fmts)")
        }
        if let ports = p[WFDHeader.clientRTPPorts] {
            log("对端 wfd_client_rtp_ports = \(ports)")
        }
        if let raw = p[WFDHeader.avRawPacket] {
            log("对端 wfd_av_raw_packet = \(raw)")
            if raw.lowercased() == "true" { mediaMode = .elementaryStreams }
        }
        // WFD 1.0 里 source 会通过 wfd_trigger_method 驱动我们发 SETUP/PLAY
        if let trigger = p[WFDHeader.triggerMethod] {
            if let m = RTSPMethod.fromTrigger(trigger) {
                log("对端要求触发：\(m.rawValue)")
                performTriggered(m)
            }
        }
    }

    private func applySDP(_ sdp: String) {
        log("收到 SDP（\(sdp.utf8.count) 字节）")
        for line in sdp.split(whereSeparator: { $0 == "\n" }) {
            let l = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if l.hasPrefix("m=video") || l.hasPrefix("a=rtpmap")
                || l.hasPrefix("a=fmtp") || l.hasPrefix("a=control") {
                log("SDP \(l)")
            }
            if l.hasPrefix("a=fmtp") && l.contains("packetization-mode") {
                log("H.264 分片模式见上")
            }
        }
    }

    /// 按当前状态推进到下一步
    private func advance() {
        switch state {
        case .options:
            // OPTIONS 回了 → 发 GET_PARAMETER 拿能力
            sendGetParameter()

        case .negotiated:
            // 能力已发。若 source 没给 trigger，就自己往下走
            if presentationURL != nil || peerParameters[WFDHeader.triggerMethod] == nil {
                // 等一小会儿看会不会有 wfd_trigger_method: SETUP
                queue.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                    guard let self, self.state == .negotiated else { return }
                    self.sendSetup()
                }
            }

        case .setup:
            if session != nil {
                sendPlay()
            }

        case .playing:
            break

        default:
            break
        }
    }

    private func performTriggered(_ m: RTSPMethod) {
        switch m {
        case .setup:    if state == .negotiated { sendSetup() }
        case .play:     if state == .setup || state == .negotiated { sendPlay() }
        case .pause:    break
        case .teardown: stop()
        default:        break
        }
    }

    private func handleRequest(_ msg: RTSPMessage, method: RTSPMethod) {
        log("← 请求 \(method.rawValue) \(msg.uri)")

        switch method {
        case .options:
            reply(msg, headers: [
                (WFDHeader.publicMethods,
                 "org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER"),
            ])

        case .getParameter:
            // source 问我们的能力
            let body = capabilities.parameterBody()
            reply(msg, body: body)
            if state == .options { state = .negotiated }

        case .setParameter:
            let params = WFDCapabilities.parseParameters(msg.body)
            if !params.isEmpty {
                peerParameters.merge(params) { _, new in new }
                applyPeerParameters(params)
            }
            reply(msg)
            if state == .options {
                // 收到 M? 后把我们的能力回过去
                sendSetParameterCapabilities()
                state = .negotiated
            }

        case .setup:
            reply(msg, headers: session.map { [(WFDHeader.session, $0)] } ?? [])

        case .play:
            reply(msg, headers: session.map { [(WFDHeader.session, $0)] } ?? [])
            state = .playing
            startKeepAlive()

        case .pause, .teardown:
            reply(msg)
            if method == .teardown { stop() }
        }
    }

    private func reply(_ req: RTSPMessage,
                       headers: [(String, String)] = [],
                       body: String = "") {
        let r = RTSPMessage.response(to: req, headers: headers, body: body)
        connection?.send(content: r.encoded(), completion: .contentProcessed { _ in })
    }

    // MARK: 媒体

    private func handleRTP(_ data: [UInt8]) {
        stats.rtpPackets += 1
        stats.rtpBytes += data.count
        onRTPPacket?(stats.rtpPackets)

        guard let packet = try? RTPPacket.parse(data) else {
            log("RTP 解析失败（\(data.count) B）")
            return
        }
        let payload = packet.payload(in: data)
        guard !payload.isEmpty else { return }

        // 前若干个包投票决定是 TS 还是裸 H.264
        if sniffCount < 30 {
            sniffCount += 1
            if RTPPacket.looksLikeTS(payload) { sniffTSCount += 1 }
            if sniffCount == 30 {
                if sniffTSCount >= 15 {
                    mediaMode = .transportStream
                } else {
                    mediaMode = .elementaryStreams
                }
                log("媒体模式判定：\(mediaMode.rawValue)（TS 票 \(sniffTSCount)/30）")
            }
        }

        switch mediaMode {
        case .transportStream:
            for es in tsDemuxer.push(payload) {
                feedElementaryStream(es)
            }
        case .elementaryStreams:
            if let au = depacketizer.push(packet: packet, payload: payload) {
                stats.accessUnits += 1
                onAccessUnit?(au)
            }
        }
    }

    /// TS 解出的 ES 分片可能仍需要按 Annex-B 重切；这里直接当访问单元交给上层，
    /// 由 `H264AccessUnitSplitter` 统一处理边界。
    private func feedElementaryStream(_ es: [UInt8]) {
        guard !es.isEmpty else { return }
        stats.accessUnits += 1
        onAccessUnit?(es)
    }

    // MARK: 工具

    private func fail(_ why: String) {
        log(why)
        state = .failed(why)
        keepAliveTimer?.cancel()
        keepAliveTimer = nil
        connection?.cancel()
        connection = nil
    }

    private func log(_ s: String) { onLog?(s) }
}
