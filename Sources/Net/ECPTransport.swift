//
//  ECPTransport.swift
//  PandaLink
//
//  TCP 连接 + ECP 帧收发。底层用 Network.framework 的 NWConnection。
//

import Foundation
import Network

enum ECPTransportState: Equatable {
    case idle
    case connecting
    case ready
    case failed(String)
    case cancelled

    var label: String {
        switch self {
        case .idle: return "未连接"
        case .connecting: return "连接中…"
        case .ready: return "已连接"
        case .failed(let m): return "失败：\(m)"
        case .cancelled: return "已断开"
        }
    }
}

final class ECPTransport {

    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "top.shareway.pandalink.ecp")
    private var decoder = ECPStreamDecoder()

    /// 收到完整一帧
    var onFrame: ((ECPFrame) -> Void)?
    /// 状态变化
    var onState: ((ECPTransportState) -> Void)?
    /// 原始帧（用于日志 / 诊断）
    var onRawFrame: ((UInt32, Int) -> Void)?

    private(set) var state: ECPTransportState = .idle {
        didSet { onState?(state) }
    }

    private(set) var host: String = ""
    private(set) var port: UInt16 = 0

    // MARK: 连接

    func connect(host: String, port: UInt16, timeout: TimeInterval = 8) {
        disconnect()
        self.host = host
        self.port = port
        decoder.reset()
        state = .connecting

        let p = NWParameters.tcp
        p.allowLocalEndpointReuse = true
        // 车机热点通常是 192.168.x.x 私网，允许蜂窝/无线混合
        p.requiredInterfaceType = .wifi

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            state = .failed("端口非法")
            return
        }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: p)
        connection = conn

        conn.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.state = .ready
                self.receiveLoop()
            case .waiting(let e):
                self.state = .failed(e.localizedDescription)
            case .failed(let e):
                self.state = .failed(e.localizedDescription)
                self.connection?.cancel()
                self.connection = nil
            case .cancelled:
                self.state = .cancelled
            default:
                break
            }
        }
        conn.start(queue: queue)

        // 连接超时
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.state = .failed("连接超时")
            self.connection?.cancel()
            self.connection = nil
        }
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
        decoder.reset()
        if state != .idle { state = .cancelled }
    }

    // MARK: 收

    private func receiveLoop() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let frames = self.decoder.feed([UInt8](data))
                for f in frames {
                    self.onRawFrame?(f.type, f.totalLength)
                    self.onFrame?(f)
                }
            }
            if let error {
                self.state = .failed(error.localizedDescription)
                return
            }
            if isComplete {
                self.state = .cancelled
                return
            }
            if self.connection != nil { self.receiveLoop() }
        }
    }

    // MARK: 发

    @discardableResult
    func send(_ bytes: [UInt8]) -> Bool {
        guard let conn = connection, state == .ready else { return false }
        conn.send(content: Data(bytes), completion: .contentProcessed { _ in })
        return true
    }

    @discardableResult
    func send(type: UInt32, body: [UInt8] = [], extra: [UInt8] = [0, 0, 0, 0]) -> Bool {
        send(ECPCodec.encode(type: type, extra: extra, body: body))
    }

    @discardableResult
    func reply(to frame: ECPFrame, body: [UInt8] = []) -> Bool {
        send(ECPCodec.reply(to: frame, body: body))
    }
}
