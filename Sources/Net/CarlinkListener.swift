//
//  CarlinkListener.swift
//  PandaLink
//
//  六端口监听，对应 `p/o9` + `p/l9`。
//
//  `CarlinkHostActivity:4138-4192` 依次绑定六个 ServerSocket，绑定顺序与失败策略：
//    AUTH 57209 绑不上 → 打 "AUTH 端口 57209 绑定失败" 并**整组放弃**
//    其余五个失败只打日志，继续
//  成功后打 "监听端口 AUTH=57209 CONTROL=57219 SENSOR=57239 MEDIA=57229 CERT=57249 VIDEO=57259"
//
//  每个端口一条 accept 循环（`p/o9;->a` 起 `carlink-accept-<name>` 守护线程）。
//
//  accept 后的分派（`p/l9` 的 packed-switch）：
//    auth    → 建 `CarlinkAuthChannel`（两对 P-256），挂 send/receive 变换（此时 sessionKey 为 nil，
//              变换函数内部判空直接透传），起 `carlink-auth-rx`
//    control → 建 `CarlinkControlChannel`，收到帧按 param 分派
//    sensor / media / cert / video → 普通 `CarlinkChannel`，帧原样上抛
//
//  AUTH 成功后（`:pswitch_0`）：
//    `o9.n = b9.b`（sessionKey 灌进 listener，后续所有通道的变换立即生效）
//    记 phoneIP；Android 版接着 `SinkNative.start(ip, 7236, 1280, 720, dpi, 30, ...)` 拉视频流，
//    iOS 侧等价动作是让车机按 VIDEO 通道推流 + 本机起一个 RTSP/H.264 接收端（后续实现）。
//

import Foundation
import Network

enum CarlinkListenerState: Equatable {
    case idle
    case listening
    case failed(String)
    case stopped

    var label: String {
        switch self {
        case .idle: return "未监听"
        case .listening: return "监听中"
        case .failed(let m): return "监听失败：\(m)"
        case .stopped: return "已停止"
        }
    }
}

final class CarlinkListener {

    // MARK: 外部钩子

    var onState: ((CarlinkListenerState) -> Void)?
    var onLog: ((String) -> Void)?
    /// 任意通道收到的帧（AUTH/CONTROL 已在内部消费，这里也会收到一份，便于面板显示）
    var onFrame: ((ChannelRole, CarlinkFrame, [UInt8]) -> Void)?
    /// AUTH 完成
    var onAuthenticated: ((CarlinkAuthResult) -> Void)?
    /// 车机请求断开（CONTROL param 23）
    var onDisconnectRequest: (() -> Void)?

    // MARK: 状态

    private(set) var state: CarlinkListenerState = .idle {
        didSet { onState?(state) }
    }

    /// `p/o9;->n`：AUTH 完成后的 session_key，其他通道发送/接收都靠它
    private(set) var sessionKey: [UInt8]?
    /// `p/s9;->e`：车机（其实是手机）IP
    private(set) var phoneIP: String = ""

    var displayConfig = CarlinkDisplayConfig()
    /// 6 位 PIN，空串表示不校验（对应 `CarlinkHostActivity.z`）
    var pin: String = ""

    private var listeners: [ChannelRole: NWListener] = [:]
    private var channels: [ChannelRole: CarlinkChannel] = [:]
    private var authChannel: CarlinkAuthChannel?
    private var controlChannel: CarlinkControlChannel?

    private let queue = DispatchQueue(label: "top.shareway.pandalink.carlink")

    // MARK: 启停

    /// 对齐 `CarlinkHostActivity` 的绑定序列。返回是否成功起监听（AUTH 绑不上即失败）。
    @discardableResult
    func start() -> Bool {
        stop()

        for (role, port) in CarLinkPorts.ordered {
            do {
                try bind(role: role, port: port)
            } catch {
                if role == .auth {
                    log("AUTH 端口 \(port) 绑定失败：\(error.localizedDescription)")
                    state = .failed("AUTH 端口 \(port) 绑定失败")
                    stop()
                    return false
                }
                log("\(role.label) 端口 \(port) 绑定失败：\(error.localizedDescription)")
            }
        }

        guard listeners[.auth] != nil else {
            state = .failed("AUTH 端口未就绪")
            return false
        }

        state = .listening
        log("监听端口 AUTH=\(CarLinkPorts.auth) CONTROL=\(CarLinkPorts.control) "
            + "SENSOR=\(CarLinkPorts.sensor) MEDIA=\(CarLinkPorts.media) "
            + "CERT=\(CarLinkPorts.cert) VIDEO=\(CarLinkPorts.video)")
        return true
    }

    func stop() {
        for ch in channels.values {
            ch.onFrame = nil
            ch.onClosed = nil
            ch.close()
        }
        channels.removeAll()

        for (_, l) in listeners { l.cancel() }
        listeners.removeAll()

        authChannel = nil
        controlChannel = nil
        sessionKey = nil
        phoneIP = ""

        if state == .listening { state = .stopped }
    }

    // MARK: 绑定

    private func bind(role: ChannelRole, port: UInt16) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw NSError(domain: "PandaLink", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "端口非法"])
        }

        // 对齐 `p/o9;->b`：`new ServerSocket()` + `setReuseAddress(true)` + `bind(InetSocketAddress(port))`
        // 车机连的是 Wi-Fi 私网，优先只走 wifi；模拟器/以太网调试时回落到默认接口。
        var lastError: Error?
        for requireWifi in [true, false] {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            if requireWifi { params.requiredInterfaceType = .wifi }
            do {
                let listener = try NWListener(using: params, on: nwPort)
                configure(listener, role: role, port: port)
                listener.start(queue: queue)
                listeners[role] = listener
                return
            } catch {
                lastError = error
            }
        }
        throw lastError ?? NSError(domain: "PandaLink", code: -2,
                                   userInfo: [NSLocalizedDescriptionKey: "监听失败"])
    }

    private func configure(_ listener: NWListener, role: ChannelRole, port: UInt16) {
        listener.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.log("\(role.label) 端口 \(port) 已就绪")
            case .failed(let e):
                self.log("\(role.label) 端口 \(port) 监听失败：\(e.localizedDescription)")
                if role == .auth { self.state = .failed(e.localizedDescription) }
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in
            self?.accept(role: role, connection: conn)
        }
    }

    // MARK: accept

    private func accept(role: ChannelRole, connection: NWConnection) {
        let connQueue = DispatchQueue(label: "top.shareway.pandalink.carlink.\(role.rawValue)")
        let channelID = channelID(for: role)

        switch role {
        case .auth:
            log("手机已连入 AUTH，握手进行中…")
            let auth = CarlinkAuthChannel()
            auth.pin = pin
            auth.onLog = { [weak self] s in self?.log(s) }
            auth.socketPeerAddress = {
                Self.hostString(of: connection.endpoint)
            }
            auth.onAuthenticated = { [weak self] result in
                self?.finishAuth(result)
            }

            let ch = CarlinkChannel(role: .auth, channelID: channelID,
                                    connection: connection, queue: connQueue)
            ch.onFrame = { [weak auth] channel, frame, body in
                auth?.handle(frame: frame, body: body)
                _ = channel
            }
            ch.onClosed = { [weak self] c, e in
                self?.log("AUTH 通道关闭\(e.map { "：\($0.localizedDescription)" } ?? "")")
                _ = c
            }
            auth.start(on: ch)
            authChannel = auth
            channels[.auth] = ch
            ch.start()

        case .control:
            log("CONTROL 通道已建立")
            let ctrl = CarlinkControlChannel(
                config: displayConfig,
                send: { [weak self] chID, param, payload in
                    self?.channels[.control]?.send(channel: chID, param: param, payload: payload)
                },
                onDisconnect: { [weak self] in
                    self?.log("phone requested disconnect")
                    self?.onDisconnectRequest?()
                }
            )
            let ch = CarlinkChannel(role: .control, channelID: channelID,
                                    connection: connection, queue: connQueue)
            attach(crypto: ch)
            ch.onFrame = { [weak self] _, frame, body in
                ctrl.handle(frame, body: body)
                self?.onFrame?(.control, frame, body)
            }
            controlChannel = ctrl
            channels[.control] = ch
            ch.start()

        case .sensor, .media, .cert, .video:
            let ch = CarlinkChannel(role: role, channelID: channelID,
                                    connection: connection, queue: connQueue)
            attach(crypto: ch)
            ch.onFrame = { [weak self] _, frame, body in
                self?.onFrame?(role, frame, body)
            }
            ch.onClosed = { [weak self] c, e in
                self?.log("\(role.label) 通道关闭\(e.map { "：\($0.localizedDescription)" } ?? "")")
                _ = c
            }
            channels[role] = ch
            log("\(role.label) 通道已连接")
            ch.start()
        }
    }

    /// 给通道挂上 `p/l9` 的加密/解密变换（sessionKey 为空时内部透传）
    private func attach(crypto ch: CarlinkChannel) {
        ch.sendTransform = { [weak self] plain in
            self?.authChannel?.encrypt(plain) ?? plain
        }
        ch.receiveTransform = { [weak self] cipher in
            self?.authChannel?.decrypt(cipher) ?? cipher
        }
    }

    private func finishAuth(_ result: CarlinkAuthResult) {
        sessionKey = result.sessionKey
        phoneIP = result.phoneIP
        log("认证完成，手机IP=\(result.phoneIP)")
        onAuthenticated?(result)
    }

    // MARK: 工具

    private func channelID(for role: ChannelRole) -> CarlinkChannelID {
        switch role {
        case .auth: return .auth
        case .control: return .control
        case .sensor: return .sensor
        case .media: return .audio
        case .cert: return .cert
        case .video: return .video
        }
    }

    private static func hostString(of endpoint: NWEndpoint) -> String {
        switch endpoint {
        case .hostPort(let host, _):
            switch host {
            case .ipv4(let addr): return "\(addr)"
            case .ipv6(let addr): return "\(addr)"
            case .name(let n, _): return n
            @unknown default: return "0.0.0.0"
            }
        default:
            return "0.0.0.0"
        }
    }

    private func log(_ s: String) { onLog?(s) }
}
