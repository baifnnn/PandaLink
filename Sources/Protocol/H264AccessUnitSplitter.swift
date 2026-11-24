//
//  H264AccessUnitSplitter.swift
//  PandaLink
//
//  把任意形态的 H.264 字节流切成「一个访问单元 = 一帧」。
//
//  为什么要这一层：TS 解出来的 ES 分片边界是 PES 包的边界，不是帧边界；
//  裸 RTP 模式虽然由 `H264Depacketizer` 按 marker 切了帧，但 SPS/PPS 可能
//  只在开头出现一次，后续 IDR 帧需要自己补上。
//
//  判据（对齐 `avc_utils.cpp` 里 NALBitReader / nalSize 那套逻辑）：
//    NAL type 1  (non-IDR slice) → 遇到新的 type 1 且上一帧已有 VCL → 切
//    NAL type 5  (IDR slice)     → 遇到就切
//    NAL type 6  (SEI)           → 归入下一帧
//    NAL type 7/8 (SPS/PPS)      → 缓存，每帧 IDR 前补发
//    NAL type 9  (AUD)           → 切帧标记
//

import Foundation

final class H264AccessUnitSplitter {

    struct Frame {
        /// Annex-B 码流，已保证包含 SPS/PPS（IDR 帧）
        var data: [UInt8]
        var isKeyframe: Bool
        /// 从 SPS 解出的宽高（若能解出）
        var size: (width: Int, height: Int)?
    }

    private var sps: [UInt8]?
    private var pps: [UInt8]?
    private var pending: [UInt8] = []
    private var hasVCL = false
    private var pendingHasIDR = false

    static let startCode: [UInt8] = [0x00, 0x00, 0x00, 0x01]

    private(set) var lastSize: (width: Int, height: Int)?

    func reset() {
        pending.removeAll(keepingCapacity: false)
        hasVCL = false
        pendingHasIDR = false
        lastSize = nil
    }

    /// 喂入一段字节。返回这次能完整切出的帧。
    func push(_ bytes: [UInt8]) -> [Frame] {
        pending.append(contentsOf: bytes)
        var out: [Frame] = []

        let nals = H264AccessUnitSplitter.splitNALs(pending)
        guard !nals.isEmpty else { return out }

        // 末尾若还不是完整的 NAL（没有下一个起始码且不是整段结束），
        // splitNALs 已经按「到结尾」收下，所以这里可以整体处理。
        pending.removeAll(keepingCapacity: true)

        for nal in nals {
            guard let first = nal.first else { continue }
            let type = first & 0x1F

            switch type {
            case 7:                       // SPS
                sps = nal
                if let s = H264AccessUnitSplitter.parseSPS(nal) {
                    lastSize = s
                }
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)

            case 8:                       // PPS
                pps = nal
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)

            case 9:                       // AUD — 明确的帧边界
                if hasVCL, let f = flush() { out.append(f) }
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)

            case 5:                       // IDR
                if hasVCL, let f = flush() { out.append(f) }
                ensureParameterSets()
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)
                hasVCL = true
                pendingHasIDR = true

            case 1:                       // non-IDR slice
                if hasVCL {
                    // 一个 slice 结束后再来一个 slice → 上一帧结束
                    if let f = flush() { out.append(f) }
                }
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)
                hasVCL = true

            case 6:                       // SEI
                if hasVCL, let f = flush() { out.append(f) }
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)

            default:
                pending.append(contentsOf: H264AccessUnitSplitter.startCode)
                pending.append(contentsOf: nal)
            }
        }
        return out
    }

    /// 抽出残留的最后一帧（会话结束时调用）
    func drain() -> Frame? {
        hasVCL ? flush() : nil
    }

    private func ensureParameterSets() {
        // 若当前 pending 里还没有 SPS/PPS，补在最前面
        let text = pending
        let hasSPS = H264AccessUnitSplitter.splitNALs(text).contains { ($0.first ?? 0) & 0x1F == 7 }
        guard !hasSPS else { return }
        var prefix: [UInt8] = []
        if let s = sps {
            prefix.append(contentsOf: H264AccessUnitSplitter.startCode)
            prefix.append(contentsOf: s)
        }
        if let p = pps {
            prefix.append(contentsOf: H264AccessUnitSplitter.startCode)
            prefix.append(contentsOf: p)
        }
        if !prefix.isEmpty {
            pending = prefix + pending
        }
    }

    private func flush() -> Frame? {
        guard !pending.isEmpty, hasVCL else {
            hasVCL = false
            pendingHasIDR = false
            return nil
        }
        let data = pending
        let key = pendingHasIDR
        pending.removeAll(keepingCapacity: true)
        hasVCL = false
        pendingHasIDR = false
        return Frame(data: data, isKeyframe: key, size: lastSize)
    }

    // MARK: NAL 切分

    /// 按 00 00 01 / 00 00 00 01 切 NAL，返回不含起始码的 NAL 体
    static func splitNALs(_ bytes: [UInt8]) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var i = 0
        var nalStart = -1
        let n = bytes.count

        while i + 2 < n {
            if bytes[i] == 0x00, bytes[i + 1] == 0x00, bytes[i + 2] == 0x01 {
                if nalStart >= 0, i > nalStart {
                    out.append(Array(bytes[nalStart..<i]))
                }
                var next = i + 3
                // 跳过 00 00 00 01 的额外 0
                while next < n, bytes[next] == 0x00 { next += 1 }
                nalStart = next
                i = next
                continue
            }
            i += 1
        }

        if nalStart >= 0, nalStart < n {
            var end = n
            // 去掉尾部的零填充
            while end > nalStart, bytes[end - 1] == 0x00 { end -= 1 }
            if end > nalStart {
                out.append(Array(bytes[nalStart..<end]))
            }
        }
        return out
    }

    // MARK: SPS 解析（只取宽高）

    /// 解析 SPS 的 pic_width_in_mbs_minus1 / pic_height_in_map_units_minus1 与 frame_crop。
    /// 对齐 `avc_utils.cpp` 里的 `frame_crop = (%u, %u, %u, %u)`。
    static func parseSPS(_ nal: [UInt8]) -> (width: Int, height: Int)? {
        guard nal.count > 4 else { return nil }

        // 去掉 NAL 头与 emulation prevention bytes
        var rbsp: [UInt8] = []
        rbsp.reserveCapacity(nal.count)
        var zeros = 0
        for byte in nal.dropFirst() {
            if zeros >= 2, byte == 0x03 {
                zeros = 0
                continue
            }
            zeros = (byte == 0x00) ? zeros + 1 : 0
            rbsp.append(byte)
        }

        var reader = BitReader(rbsp)
        do {
            let profile = try reader.u(8)
            _ = try reader.u(8)                 // constraint flags
            _ = try reader.u(8)                 // level_idc
            _ = try reader.ue()                 // seq_parameter_set_id

            var chromaFormatIdc = 1
            var separateColourPlane = 0
            if profile == 100 || profile == 110 || profile == 122 || profile == 244
                || profile == 44 || profile == 83 || profile == 86
                || profile == 118 || profile == 128 || profile == 138
                || profile == 139 || profile == 134 || profile == 135 {
                chromaFormatIdc = try reader.ue()
                if chromaFormatIdc == 3 { separateColourPlane = try reader.u(1) }
                _ = try reader.ue()             // bit_depth_luma_minus8
                _ = try reader.ue()             // bit_depth_chroma_minus8
                _ = try reader.u(1)             // qpprime_y_zero_transform_bypass_flag
                let scalingMatrix = try reader.u(1)
                if scalingMatrix == 1 {
                    let count = chromaFormatIdc != 3 ? 8 : 12
                    for i in 0..<count {
                        let present = try reader.u(1)
                        if present == 1 {
                            let size = i < 6 ? 16 : 64
                            skipScalingList(&reader, size)
                        }
                    }
                }
            }

            _ = try reader.ue()                 // log2_max_frame_num_minus4
            let pocType = try reader.ue()
            if pocType == 0 {
                _ = try reader.ue()
            } else if pocType == 1 {
                _ = try reader.u(1)
                _ = try reader.se()
                _ = try reader.se()
                let n = try reader.ue()
                for _ in 0..<min(n, 256) { _ = try reader.se() }
            }
            _ = try reader.ue()                 // max_num_ref_frames
            _ = try reader.u(1)                 // gaps_in_frame_num_value_allowed_flag

            let widthMbs = try reader.ue() + 1
            let heightMapUnits = try reader.ue() + 1
            let frameMbsOnly = try reader.u(1)
            if frameMbsOnly == 0 { _ = try reader.u(1) }   // mb_adaptive_frame_field_flag
            _ = try reader.u(1)                 // direct_8x8_inference_flag

            var cropLeft = 0, cropRight = 0, cropTop = 0, cropBottom = 0
            let cropFlag = try reader.u(1)
            if cropFlag == 1 {
                cropLeft = try reader.ue()
                cropRight = try reader.ue()
                cropTop = try reader.ue()
                cropBottom = try reader.ue()
            }

            let subWidthC = (chromaFormatIdc == 1 || chromaFormatIdc == 2) ? 2 : 1
            let subHeightC = chromaFormatIdc == 1 ? 2 : 1
            let chromaArrayType = separateColourPlane == 1 ? 0 : chromaFormatIdc
            let cropUnitX = chromaArrayType == 0 ? 1 : subWidthC
            let cropUnitY = (chromaArrayType == 0 ? 1 : subHeightC) * (2 - frameMbsOnly)

            let width = widthMbs * 16 - (cropLeft + cropRight) * cropUnitX
            let height = (2 - frameMbsOnly) * heightMapUnits * 16
                - (cropTop + cropBottom) * cropUnitY

            guard width > 0, height > 0 else { return nil }
            return (width, height)
        } catch {
            return nil
        }
    }

    private static func skipScalingList(_ reader: inout BitReader, _ size: Int) {
        var lastScale = 8
        var nextScale = 8
        for j in 0..<size {
            if nextScale != 0 {
                let delta = (try? reader.se()) ?? 0
                nextScale = (lastScale + delta + 256) % 256
            }
            if nextScale != 0 { lastScale = nextScale }
            _ = j
        }
    }

    // MARK: 位读取

    struct BitReader {
        private let bytes: [UInt8]
        private var bitPos = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        mutating func u(_ n: Int) throws -> Int {
            guard n >= 0, n <= 32 else { throw Err.range }
            var v = 0
            for _ in 0..<n {
                let byteIdx = bitPos >> 3
                guard byteIdx < bytes.count else { throw Err.eof }
                let bit = (bytes[byteIdx] >> (7 - UInt8(bitPos & 7))) & 1
                v = (v << 1) | Int(bit)
                bitPos += 1
            }
            return v
        }

        mutating func ue() throws -> Int {
            var leadingZeros = 0
            while true {
                let b = try u(1)
                if b == 1 { break }
                leadingZeros += 1
                if leadingZeros > 31 { throw Err.range }
            }
            if leadingZeros == 0 { return 0 }
            let rest = try u(leadingZeros)
            return (1 << leadingZeros) - 1 + rest
        }

        mutating func se() throws -> Int {
            let k = try ue()
            let sign = (k & 1) == 1 ? 1 : -1
            return sign * ((k + 1) / 2)
        }

        enum Err: Error { case eof, range }
    }
}
