//
//  CarlinkChannel.swift
//  PandaLink
//
//  单条 CarLink 通道的连接封装，对应 `p/k9`。
//
//  `p/k9` 字段：
//    a 通道名（"auth" / "control" / "sensor" / "media" / "cert" / "video"）
//    b Socket
//    c onFrame 回调   → `(channel, frame, body)`
//    d onClosed 回调  → `(channel, throwable)`
//    e 发送前变换（加密）  ← AUTH 成功后挂上 AES-GCM
//    f 接收后变换（解密）
//    i AtomicInteger seq，**初值 1**
//    j 活跃标志
//
//  `p/k9;->b(k9, ma, param, body)` 发帧，注意它写死的三个枚举：
//    direction = mt.c = **CAR(0)**    ← 手机发出的帧方向字段是 CAR，不是 PHONE
//    encoding  = nc.c = RAW(0)
//    role      = rl.d = RES(2)
//  只有 channel 与 param 由调用方给。
//
//  `p/k9;->c()` 起 `carlink-<name>-rx` 读线程：先读满 20 字节头，
//  `p0.i` 校验通过后按 `total - 20` 读 body；`total - 20 < 0` 时
//  打 `[<name>] bad messageSize=<n>; dropping connection` 并关连接。
//

import Foundation
import Network

final class CarlinkChannel {

    let role: ChannelRole
    let channelID: CarlinkChannelID

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var decoder = CarlinkStreamDecoder()

    /// `p/k9;->i` 的 AtomicInteger，初值 1
    private var sequence: UInt32 = 1
    private let seqLock = NSLock()

    /// `p/k9;->e` 发送前变换（加密）
    var sendTransform: (([UInt8]) -> [UInt8])?
    /// `p/k9;->f` 接收后变换（解密）
    var receiveTransform: (([UInt8]) -> [UInt8])?

    /// `p/k9;->c` 的 `lf` 回调
    var onFrame: ((CarlinkChannel, CarlinkFrame, [UInt8]) -> Void)?
    /// `p/k9;->d` 的 `kf` 回调
    var onClosed: ((CarlinkChannel, Error?) -> Void)?

    private(set) var isActive = true
    private(set) var framesReceived = 0
    private(set) var bytesReceived = 0

    init(role: ChannelRole, channelID: CarlinkChannelID, connection: NWConnection, queue: DispatchQueue) {
        self.role = role
        self.channelID = channelID
        self.connection = connection
        self.queue = queue
    }

    // MARK: 生命周期

    /// 对齐 `p/k9;->c()`：`setTcpNoDelay(true)` + 起读线程
    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.receiveLoop()
            case .failed(let e):
                self.close(error: e)
            case .cancelled:
                self.close(error: nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// 对齐 `p/k9;->a()`
    func close(error: Error? = nil) {
        guard isActive else { return }
        isActive = false
        connection.cancel()
        decoder.reset()
        onClosed?(self, error)
    }

    // MARK: 收

    private func receiveLoop() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self, self.isActive else { return }

            if let data, !data.isEmpty {
                self.bytesReceived += data.count
                let frames = self.decoder.feed([UInt8](data))
                for f in frames {
                    self.framesReceived += 1
                    var body = f.body
                    if !body.isEmpty, let t = self.receiveTransform {
                        body = t(body)
                    }
                    self.onFrame?(self, f, body)
                }
            }

            if let error {
                self.close(error: error)
                return
            }
            if isComplete {
                self.close(error: nil)
                return
            }
            if self.isActive { self.receiveLoop() }
        }
    }

    // MARK: 发

    /// 对齐 `p/k9;->b(k9, ma, param, body)`
    func send(channel: CarlinkChannelID? = nil, param: UInt16, payload: [UInt8] = []) {
        guard isActive else { return }

        var body = payload
        if !body.isEmpty, let t = sendTransform {
            body = t(body)
        }

        seqLock.lock()
        let seq = sequence
        sequence = sequence &+ 1
        seqLock.unlock()

        // 方向 / 编码 / 角色三者写死，见文件头注释
        let frame = CarlinkFrame(sequence: seq,
                                 direction: .car,
                                 encoding: .raw,
                                 role: .res,
                                 channel: channel ?? channelID,
                                 param: param,
                                 body: body)
        let bytes = CarlinkFrameCodec.encode(frame)
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in })
    }

    /// 只发 body 不回包（用于 media/video 裸流）
    func sendRaw(_ bytes: [UInt8]) {
        guard isActive, !bytes.isEmpty else { return }
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in })
    }
}
