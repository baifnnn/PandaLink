//
//  VideoPipeline.swift
//  PandaLink
//
//  视频接收管线的非隔离容器。
//
//  为什么单独一层：`CarLinkSession` 是 `@MainActor` 隔离的，
//  而 WFD 的解包 / 解码全在后台队列上跑。把 splitter + decoder 放进
//  这个普通 class，主线程只通过回调拿计数，避免跨 actor 直接写属性。
//

import Foundation
import CoreMedia

final class VideoPipeline {

    /// 解出一帧（在后台队列上调用，调用方自己转主线程）
    var onFrameDecoded: (() -> Void)?
    var onSizeChanged: ((Int, Int) -> Void)?
    var onLog: ((String) -> Void)?
    /// 送显：直接交给 renderer
    var onPixelBuffer: ((CVPixelBuffer, CMTime) -> Void)?

    private let splitter = H264AccessUnitSplitter()
    private let decoder = H264Decoder()

    private let lock = NSLock()
    private var _accessUnits = 0
    private var _bytes = 0

    var accessUnits: Int {
        lock.lock(); defer { lock.unlock() }
        return _accessUnits
    }
    var byteCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _bytes
    }

    init() {
        decoder.onLog = { [weak self] line in self?.onLog?(line) }
        decoder.onFormatSize = { [weak self] w, h in self?.onSizeChanged?(w, h) }
        decoder.onPixelBuffer = { [weak self] pb, pts in
            self?.onPixelBuffer?(pb, pts)
            self?.onFrameDecoded?()
        }
    }

    func reset() {
        splitter.reset()
        decoder.reset()
        lock.lock()
        _accessUnits = 0
        _bytes = 0
        lock.unlock()
    }

    /// 喂一个访问单元（Annex-B）
    func push(_ accessUnit: [UInt8]) {
        guard !accessUnit.isEmpty else { return }
        lock.lock()
        _bytes += accessUnit.count
        lock.unlock()

        let frames = splitter.push(accessUnit)
        for f in frames {
            lock.lock(); _accessUnits += 1; lock.unlock()
            decoder.decode(accessUnit: f.data)
        }
    }

    /// 会话结束，把残留帧刷出来
    func drain() {
        if let f = splitter.drain() {
            decoder.decode(accessUnit: f.data)
        }
    }
}
