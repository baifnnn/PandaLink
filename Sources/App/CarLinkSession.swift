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
        listener.stop()
        phase = .idle
        phoneIP = ""
        carModel = ""
        sessionKeyHex = ""
        appendLog("已停止")
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
