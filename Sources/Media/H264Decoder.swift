//
//  H264Decoder.swift
//  PandaLink
//
//  VideoToolbox H.264 解码 + AVSampleBufferDisplayLayer 送显。
//
//  为什么不用 AVPlayer：WFD 送的是裸 Annex-B 码流，没有容器，
//  只能手工建 CMFormatDescription 再喂 CMSampleBuffer。
//
//  做法：
//    1. 从 SPS/PPS 建 `CMVideoFormatDescription`（`CMVideoFormatDescriptionCreateFromH264ParameterSets`）
//    2. 每个访问单元：Annex-B → AVCC（4 字节长度前缀），前面包一个 `CMBlockBuffer`
//       参数集每帧都重附一次（WFD 丢包后重连、或中途插 IDR 时需要）
//    3. `VTDecompressionSession` 解出 `CVPixelBuffer`
//    4. 用 `CMVideoFormatDescription` + `CMSampleBufferCreateReadyWithImageBuffer` 包成显示用 sample
//    5. 交给 `AVSampleBufferDisplayLayer.enqueue`
//
//  iOS 16.1 上 VideoToolbox 的软/硬解都可用（A12 及以上硬解 H.264）。
//

import Foundation
import AVFoundation
import VideoToolbox
import CoreMedia

final class H264Decoder: NSObject {

    // MARK: 回调

    /// 解码出一帧
    var onPixelBuffer: ((CVPixelBuffer, CMTime) -> Void)?
    /// 尺寸变化
    var onFormatSize: ((Int, Int) -> Void)?
    var onLog: ((String) -> Void)?

    // MARK: 状态

    private var session: VTDecompressionSession?
    private var formatDescription: CMVideoFormatDescription?
    private var currentSize: (Int, Int)?

    private(set) var decodedFrames = 0
    private(set) var droppedFrames = 0

    /// 送显队列（解码回调可能是多线程的）
    private let lock = NSLock()

    // MARK: 生命周期

    func reset() {
        lock.lock()
        if let s = session { VTDecompressionSessionInvalidate(s) }
        session = nil
        formatDescription = nil
        currentSize = nil
        decodedFrames = 0
        droppedFrames = 0
        lock.unlock()
    }

    deinit {
        if let s = session { VTDecompressionSessionInvalidate(s) }
    }

    // MARK: 主入口

    /// 喂一个访问单元（Annex-B，必须含 SPS/PPS 或此前已经喂过）
    func decode(accessUnit: [UInt8], pts: CMTime? = nil) {
        let nals = H264AccessUnitSplitter.splitNALs(accessUnit)
        guard !nals.isEmpty else { return }

        var sps: [UInt8]?
        var pps: [UInt8]?
        var vcl: [[UInt8]] = []

        for nal in nals {
            guard let head = nal.first else { continue }
            switch head & 0x1F {
            case 7: sps = nal
            case 8: pps = nal
            case 1, 5: vcl.append(nal)
            default: break        // SEI / AUD 不需要进 AVCC
            }
        }

        // 有 SPS/PPS 就（重新）建 format description
        if let s = sps, let p = pps {
            rebuildFormat(sps: s, pps: p)
        }

        guard let fmt = formatDescription, !vcl.isEmpty else { return }

        // AVCC：每个 NAL 前置 4 字节大端长度
        var avcc: [UInt8] = []
        avcc.reserveCapacity(accessUnit.count + vcl.count * 4)
        for nal in vcl {
            let n = nal.count
            avcc.append(UInt8((n >> 24) & 0xFF))
            avcc.append(UInt8((n >> 16) & 0xFF))
            avcc.append(UInt8((n >> 8) & 0xFF))
            avcc.append(UInt8(n & 0xFF))
            avcc.append(contentsOf: nal)
        }

        var blockBuffer: CMBlockBuffer?
        let status = CMBlockBufferCreateWithMemoryBlock(
            allocator: kCFAllocatorDefault,
            memoryBlock: nil,
            blockLength: avcc.count,
            blockAllocator: kCFAllocatorDefault,
            customBlockSource: nil,
            offsetToData: 0,
            dataLength: avcc.count,
            flags: 0,
            blockBufferOut: &blockBuffer)
        guard status == kCMBlockBufferNoErr, let bb = blockBuffer else {
            log("CMBlockBufferCreateWithMemoryBlock 失败 \(status)")
            return
        }

        let copyStatus = avcc.withUnsafeBufferPointer { ptr -> OSStatus in
            CMBlockBufferReplaceDataBytes(
                with: ptr.baseAddress!,
                blockBuffer: bb,
                offsetIntoDestination: 0,
                dataLength: avcc.count)
        }
        guard copyStatus == kCMBlockBufferNoErr else {
            log("CMBlockBufferReplaceDataBytes 失败 \(copyStatus)")
            return
        }

        let isKeyframe = vcl.contains { ($0.first ?? 0) & 0x1F == 5 }
        var sampleBuffer: CMSampleBuffer?
        var sampleSize = avcc.count
        var timing = CMSampleTimingInfo(
            duration: CMTime(value: 1, timescale: 30),
            presentationTimeStamp: pts ?? CMTime(value: CMTimeValue(decodedFrames),
                                                timescale: 30),
            decodeTimeStamp: .invalid)

        let sbStatus = CMSampleBufferCreateReady(
            allocator: kCFAllocatorDefault,
            dataBuffer: bb,
            formatDescription: fmt,
            sampleCount: 1,
            sampleTimingEntryCount: 1,
            sampleTimingArray: &timing,
            sampleSizeEntryCount: 1,
            sampleSizeArray: &sampleSize,
            sampleBufferOut: &sampleBuffer)
        guard sbStatus == kCMBlockBufferNoErr, let sb = sampleBuffer else {
            log("CMSampleBufferCreateReady 失败 \(sbStatus)")
            return
        }

        // 关键帧标记，解码器据此跳过依赖帧
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: true),
           CFArrayGetCount(attachments) > 0 {
            let dict = unsafeBitCast(
                CFArrayGetValueAtIndex(attachments, 0),
                to: CFMutableDictionary.self)
            let key = Unmanaged.passUnretained(kCMSampleAttachmentKey_NotSync).toOpaque()
            if !isKeyframe {
                CFDictionarySetValue(dict, key, Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
            }
        }

        guard let s = session else { return }
        var flagsOut: VTDecodeInfoFlags = []
        let decStatus = VTDecompressionSessionDecodeFrame(
            s, sampleBuffer: sb, flags: [._EnableAsynchronousDecompression],
            infoFlagsOut: &flagsOut) { [weak self] status, _, imageBuffer, _, _ in
                guard let self else { return }
                guard status == noErr, let pb = imageBuffer else {
                    self.lock.lock(); self.droppedFrames += 1; self.lock.unlock()
                    return
                }
                self.lock.lock()
                self.decodedFrames += 1
                let idx = self.decodedFrames
                self.lock.unlock()
                let t = CMTime(value: CMTimeValue(idx), timescale: 30)
                self.onPixelBuffer?(pb, t)
        }
        if decStatus != noErr {
            log("VTDecompressionSessionDecodeFrame 失败 \(decStatus)")
        }
    }

    // MARK: format

    private func rebuildFormat(sps: [UInt8], pps: [UInt8]) {
        // 已经建过且参数相同就不重建
        if formatDescription != nil, currentSize != nil {
            // 简单起见：每次带 SPS 都重建（IDR 时才会有，频率很低）
        }

        var fmt: CMVideoFormatDescription?
        let status: OSStatus = sps.withUnsafeBufferPointer { spsPtr in
            pps.withUnsafeBufferPointer { ppsPtr in
                let pointers: [UnsafePointer<UInt8>] = [spsPtr.baseAddress!, ppsPtr.baseAddress!]
                let sizes: [Int] = [sps.count, pps.count]
                return pointers.withUnsafeBufferPointer { ptrs in
                    sizes.withUnsafeBufferPointer { szs in
                        CMVideoFormatDescriptionCreateFromH264ParameterSets(
                            allocator: kCFAllocatorDefault,
                            parameterSetCount: 2,
                            parameterSetPointers: ptrs.baseAddress!,
                            parameterSetSizes: szs.baseAddress!,
                            nalUnitHeaderLength: 4,
                            formatDescriptionOut: &fmt)
                    }
                }
            }
        }

        guard status == noErr, let f = fmt else {
            log("创建 CMVideoFormatDescription 失败 \(status)")
            return
        }

        let dims = CMVideoFormatDescriptionGetDimensions(f)
        let size = (Int(dims.width), Int(dims.height))
        let changed = currentSize == nil
            || currentSize!.0 != size.0 || currentSize!.1 != size.1

        formatDescription = f
        currentSize = size

        if changed {
            log("视频尺寸 \(size.0)x\(size.1)")
            onFormatSize?(size.0, size.1)
            createSession(format: f, width: size.0, height: size.1)
        }
    }

    private func createSession(format: CMVideoFormatDescription, width: Int, height: Int) {
        if let old = session {
            VTDecompressionSessionInvalidate(old)
            session = nil
        }

        let attrs: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: width,
            kCVPixelBufferHeightKey as String: height,
            kCVPixelBufferIOSurfacePropertiesKey as String: [:] as [String: Any],
        ]

        var s: VTDecompressionSession?
        let status = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            formatDescription: format,
            decoderSpecification: nil,
            imageBufferAttributes: attrs as CFDictionary,
            outputCallback: nil,
            decompressionSessionOut: &s)

        guard status == noErr, let created = s else {
            log("VTDecompressionSessionCreate 失败 \(status)")
            return
        }
        session = created
        log("解码会话已建立 \(width)x\(height)")
    }

    private func log(_ s: String) { onLog?(s) }
}

// MARK: - 显示层

/// 把 CVPixelBuffer 直接送进 `AVSampleBufferDisplayLayer`。
/// 比走 `CIContext` 或 `Metal` 省事，而且 iOS 16 上这条路的延迟够低。
final class H264DisplayRenderer {

    private var formatDescription: CMVideoFormatDescription?
    private var frameIndex: Int64 = 0
    private let lock = NSLock()

    weak var layer: AVSampleBufferDisplayLayer?

    func reset() {
        lock.lock()
        formatDescription = nil
        frameIndex = 0
        lock.unlock()
        layer?.flush()
    }

    func render(pixelBuffer: CVPixelBuffer, pts: CMTime) {
        lock.lock()
        if formatDescription == nil {
            var fmt: CMVideoFormatDescription?
            let st = CMVideoFormatDescriptionCreateForImageBuffer(
                allocator: kCFAllocatorDefault,
                imageBuffer: pixelBuffer,
                formatDescriptionOut: &fmt)
            if st == noErr { formatDescription = fmt }
        }
        guard let fmt = formatDescription else { lock.unlock(); return }
        frameIndex += 1
        let idx = frameIndex
        lock.unlock()

        var timing = CMSampleTimingInfo(
            duration: CMTime(value: 1, timescale: 30),
            presentationTimeStamp: pts,
            decodeTimeStamp: .invalid)
        var sample: CMSampleBuffer?
        let st = CMSampleBufferCreateReadyWithImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pixelBuffer,
            formatDescription: fmt,
            sampleTiming: &timing,
            sampleBufferOut: &sample)
        guard st == noErr, let sb = sample else { return }

        // 保证不攒帧：显示层要求 sample 有 display immediately 标记
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: true),
           CFArrayGetCount(attachments) > 0 {
            let dict = unsafeBitCast(
                CFArrayGetValueAtIndex(attachments, 0),
                to: CFMutableDictionary.self)
            CFDictionarySetValue(
                dict,
                Unmanaged.passUnretained(kCMSampleAttachmentKey_DisplayImmediately).toOpaque(),
                Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
        }
        _ = idx

        guard let layer else { return }
        if layer.status == .failed {
            layer.flush()
        }
        layer.enqueue(sb)
    }
}
