//
//  RTP.swift
//  PandaLink
//
//  RTP 解包 + H.264 去分片 + MPEG2-TS 解复用。
//
//  依据 `libovmsink.so` 里的类名（这些都是 C++ RTTI 符号，绝对可靠）：
//    N3mga11RTPReceiver13H264AssemblerE      → H.264 分片重组
//    N3mga11RTPReceiver11TSAssemblerE        → MPEG2-TS 重组
//    N3mga11RTPReceiver12AACAssemblerE       → AAC 重组
//    N3mga6VectorINS_11NALPositionEEE        → NAL 位置表
//    N3mga12NALBitReaderE                    → NAL 位流读取
//  以及 avc_utils.cpp 的日志：
//    "found AVC codec config (%d x %d, %s-profile level %d.%d)"
//    "find sps, size =%zu" / "find pps, size =%zu" / "no sps found !!!"
//    "frame_crop = (%u, %u, %u, %u)"
//  与 mpeg2ts 的：
//    ATSParser.cpp / ESQueue.cpp / "GetMPEGAudioFrameSize(header,...)"
//    "run on MODE_ELEMENTARY_STREAMS" / "run on MODE_TRANSPORT_STREAM"
//
//  所以 RTP 载荷有两种可能：裸 H.264（ES 模式）或 MPEG2-TS（TS 模式）。
//  两种都实现，运行时按首个包的形态自动判定。
//

import Foundation

// MARK: - RTP 报文

struct RTPPacket {
    /// 版本，应为 2
    var version: UInt8
    var padding: Bool
    var extensionFlag: Bool
    var csrcCount: UInt8
    var marker: Bool
    /// 载荷类型。WFD 视频通常是 96（动态）或 102/103（H.264）
    var payloadType: UInt8
    var sequence: UInt16
    var timestamp: UInt32
    var ssrc: UInt32
    /// 载荷起始位置（已跳过 CSRC 与扩展头）
    var payloadOffset: Int

    enum ParseError: Error, CustomStringConvertible {
        case tooShort(Int)
        case badVersion(UInt8)
        case truncatedExtension

        var description: String {
            switch self {
            case .tooShort(let n):      return "RTP 包过短（\(n) 字节）"
            case .badVersion(let v):    return "RTP 版本不是 2（\(v)）"
            case .truncatedExtension:   return "RTP 扩展头被截断"
            }
        }
    }

    static func parse(_ data: [UInt8]) throws -> RTPPacket {
        guard data.count >= 12 else { throw ParseError.tooShort(data.count) }
        let b0 = data[0]
        let version = (b0 >> 6) & 0x03
        guard version == 2 else { throw ParseError.badVersion(version) }

        let padding = (b0 & 0x20) != 0
        let extensionFlag = (b0 & 0x10) != 0
        let csrcCount = b0 & 0x0F
        let marker = (data[1] & 0x80) != 0
        let payloadType = data[1] & 0x7F
        let seq = (UInt16(data[2]) << 8) | UInt16(data[3])
        let ts = (UInt32(data[4]) << 24) | (UInt32(data[5]) << 16)
            | (UInt32(data[6]) << 8) | UInt32(data[7])
        let ssrc = (UInt32(data[8]) << 24) | (UInt32(data[9]) << 16)
            | (UInt32(data[10]) << 8) | UInt32(data[11])

        var off = 12 + Int(csrcCount) * 4
        guard off <= data.count else { throw ParseError.truncatedExtension }

        if extensionFlag {
            guard off + 4 <= data.count else { throw ParseError.truncatedExtension }
            let words = (Int(data[off + 2]) << 8) | Int(data[off + 3])
            off += 4 + words * 4
            guard off <= data.count else { throw ParseError.truncatedExtension }
        }

        if padding, let last = data.last, Int(last) > 0, Int(last) <= data.count - off {
            // 由调用方决定是否裁掉；这里只在 offset 里保留，长度信息交给 payload()
        }

        return RTPPacket(version: version, padding: padding,
                         extensionFlag: extensionFlag, csrcCount: csrcCount,
                         marker: marker, payloadType: payloadType,
                         sequence: seq, timestamp: ts, ssrc: ssrc,
                         payloadOffset: off)
    }

    /// 取载荷（自动裁掉 padding）
    func payload(in data: [UInt8]) -> [UInt8] {
        guard payloadOffset < data.count else { return [] }
        var end = data.count
        if padding, let last = data.last {
            let pad = Int(last)
            if pad > 0, pad <= end - payloadOffset { end -= pad }
        }
        return Array(data[payloadOffset..<end])
    }

    /// 是否是 MPEG2-TS（188 字节包，首字节 0x47）
    static func looksLikeTS(_ payload: [UInt8]) -> Bool {
        guard payload.count >= 188 else { return false }
        return payload[0] == 0x47 && (payload.count < 377 || payload[188] == 0x47)
    }
}

// MARK: - H.264 去分片（RFC 6184）

/// 输出：一帧完整的 Annex-B 码流（每个 NAL 前置 00 00 00 01）
final class H264Depacketizer {

    enum NALType: UInt8 {
        case singleOrReserved = 0
        case stapA     = 24
        case stapB     = 25
        case mtap16    = 26
        case mtap24    = 27
        case fuA       = 28
        case fuB       = 29
        case sps       = 7
        case pps       = 8
    }

    /// 累积当前访问单元（一帧）的 NAL
    private var accessUnit: [[UInt8]] = []
    /// FU-A 中间态
    private var fuBuffer: [UInt8] = []
    private var fuHeaderByte: UInt8 = 0
    private var fuActive = false

    private(set) var lastTimestamp: UInt32 = 0
    private(set) var sps: [UInt8]?
    private(set) var pps: [UInt8]?

    static let startCode: [UInt8] = [0x00, 0x00, 0x00, 0x01]

    func reset() {
        accessUnit.removeAll(keepingCapacity: false)
        fuBuffer.removeAll(keepingCapacity: false)
        fuActive = false
        lastTimestamp = 0
    }

    /// 喂一个 RTP 包。返回本次**凑齐的一帧**（Annex-B，可能为 nil）
    func push(packet: RTPPacket, payload: [UInt8]) -> [UInt8]? {
        guard !payload.isEmpty else { return nil }

        // 时间戳变了说明上一帧收完
        if packet.timestamp != lastTimestamp, !accessUnit.isEmpty {
            lastTimestamp = packet.timestamp
            // 注意：先处理本包的 NAL，再 flush；这里返回上一帧
            let finished = flushAccessUnit()
            appendNALs(from: payload, marker: packet.marker)
            return finished
        }
        lastTimestamp = packet.timestamp

        appendNALs(from: payload, marker: packet.marker)

        if packet.marker {
            return flushAccessUnit()
        }
        return nil
    }

    private func appendNALs(from payload: [UInt8], marker: Bool) {
        guard let type = NALType(rawValue: payload[0] & 0x1F) else { return }

        switch type {
        case .fuA:
            guard payload.count >= 2 else { return }
            let fuHeader = payload[1]
            let start = (fuHeader & 0x80) != 0
            let end = (fuHeader & 0x40) != 0
            let nalType = fuHeader & 0x1F

            if start {
                // NAL 头 = FU indicator 的 F|NRI + FU header 的 type
                fuHeaderByte = (payload[0] & 0xE0) | nalType
                fuBuffer = [fuHeaderByte] + payload[2...]
                fuActive = true
            } else if fuActive {
                fuBuffer.append(contentsOf: payload[2...])
            }

            if end, fuActive {
                storeNAL(fuBuffer)
                fuBuffer.removeAll(keepingCapacity: true)
                fuActive = false
            }

        case .stapA:
            var i = 1
            while i + 2 <= payload.count {
                let len = (Int(payload[i]) << 8) | Int(payload[i + 1])
                i += 2
                guard i + len <= payload.count else { break }
                storeNAL(Array(payload[i..<(i + len)]))
                i += len
            }

        case .singleOrReserved, .sps, .pps:
            storeNAL(payload)

        default:
            // STAP-B / MTAP 在 WFD 里不用，直接忽略
            break
        }
    }

    private func storeNAL(_ nal: [UInt8]) {
        guard !nal.isEmpty else { return }
        let t = nal[0] & 0x1F
        if t == NALType.sps.rawValue { sps = nal }
        if t == NALType.pps.rawValue { pps = nal }
        accessUnit.append(nal)
    }

    private func flushAccessUnit() -> [UInt8]? {
        guard !accessUnit.isEmpty else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(accessUnit.reduce(0) { $0 + $1.count + 4 })
        for nal in accessUnit {
            out.append(contentsOf: H264Depacketizer.startCode)
            out.append(contentsOf: nal)
        }
        accessUnit.removeAll(keepingCapacity: true)
        return out
    }
}

// MARK: - MPEG2-TS 解复用

/// 只做最小可用：PAT → PMT → 找到 H.264（stream_type 0x1B）与 AAC（0x0F）的 PID，
/// 再把 PES 载荷拼出来。对齐 `ATSParser.cpp` / `ESQueue.cpp` 的职责。
final class TSDemuxer {

    static let packetSize = 188
    static let syncByte: UInt8 = 0x47

    struct StreamInfo {
        var pid: UInt16
        var streamType: UInt8
    }

    private(set) var pmtPID: UInt16?
    private(set) var streams: [StreamInfo] = []
    private(set) var videoPID: UInt16?
    private(set) var audioPID: UInt16?

    /// 按 PID 累积 PES 载荷
    private var pesBuffers: [UInt16: [UInt8]] = [:]
    /// 每个 PID 上一次的 continuity counter
    private var lastCC: [UInt16: UInt8] = [:]

    func reset() {
        pmtPID = nil
        streams.removeAll()
        videoPID = nil
        audioPID = nil
        pesBuffers.removeAll()
        lastCC.removeAll()
    }

    /// 喂入一段字节（可以是任意切分，内部会自己对齐 188）
    /// 返回本次解出的视频 ES 分片（Annex-B 或长度前缀，取决于流）
    func push(_ bytes: [UInt8]) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var i = 0
        // 对齐到 0x47
        while i < bytes.count && bytes[i] != TSDemuxer.syncByte { i += 1 }
        while i + TSDemuxer.packetSize <= bytes.count {
            let pkt = Array(bytes[i..<(i + TSDemuxer.packetSize)])
            if pkt[0] != TSDemuxer.syncByte { i += 1; continue }
            if let es = handlePacket(pkt) { out.append(es) }
            i += TSDemuxer.packetSize
        }
        return out
    }

    private func handlePacket(_ pkt: [UInt8]) -> [UInt8]? {
        let pid = (UInt16(pkt[1] & 0x1F) << 8) | UInt16(pkt[2])
        let pusi = (pkt[1] & 0x40) != 0
        let adaptationField = (pkt[3] & 0x20) != 0
        let cc = pkt[3] & 0x0F

        // 连续计数检查（丢掉重复包）
        if let last = lastCC[pid], last == cc, !pusi { return nil }
        lastCC[pid] = cc

        var off = 4
        if adaptationField {
            let afLen = Int(pkt[4])
            if afLen > 0, off + 1 + afLen <= TSDemuxer.packetSize {
                let flags = pkt[5]
                // 不连续指示
                if (flags & 0x80) != 0 { pesBuffers[pid] = [] }
            }
            off += 1 + afLen
        }
        guard off < TSDemuxer.packetSize else { return nil }
        let payload = Array(pkt[off...])

        if pid == 0 { parsePAT(payload, pusi: pusi); return nil }
        if let pmt = pmtPID, pid == pmt { parsePMT(payload, pusi: pusi); return nil }

        guard pid == videoPID || pid == audioPID else { return nil }

        if pusi {
            // 新 PES 开始，先把旧的吐出去
            var flushed: [UInt8]? = nil
            if let old = pesBuffers[pid], !old.isEmpty {
                flushed = stripPESHeader(old, isVideo: pid == videoPID)
            }
            pesBuffers[pid] = payload
            return flushed
        } else {
            pesBuffers[pid, default: []].append(contentsOf: payload)
            return nil
        }
    }

    /// PES 头：00 00 01 <stream_id> <len:2> <flags:2> <header_data_length:1> <data...>
    private func stripPESHeader(_ pes: [UInt8], isVideo: Bool) -> [UInt8]? {
        guard pes.count >= 9, pes[0] == 0x00, pes[1] == 0x00, pes[2] == 0x01 else { return nil }
        let headerDataLen = Int(pes[8])
        let start = 9 + headerDataLen
        guard start < pes.count else { return nil }
        return Array(pes[start...])
    }

    private func parsePAT(_ payload: [UInt8], pusi: Bool) {
        var off = 0
        if pusi {
            guard payload.count >= 1 + 1 + Int(payload[0]) else { return }
            off = 1 + Int(payload[0])   // pointer_field
        }
        guard off + 8 <= payload.count else { return }
        guard payload[off] == 0x00 else { return }       // table_id = PAT
        let sectionLen = ((Int(payload[off + 1]) & 0x0F) << 8) | Int(payload[off + 2])
        let end = min(off + 3 + sectionLen - 4, payload.count)   // 去掉 CRC32
        var i = off + 8
        while i + 4 <= end {
            let program = (UInt16(payload[i]) << 8) | UInt16(payload[i + 1])
            let pmtPid = (UInt16(payload[i + 2] & 0x1F) << 8) | UInt16(payload[i + 3])
            if program != 0 { pmtPID = pmtPid }
            i += 4
        }
    }

    private func parsePMT(_ payload: [UInt8], pusi: Bool) {
        var off = 0
        if pusi {
            guard payload.count >= 1 + 1 + Int(payload[0]) else { return }
            off = 1 + Int(payload[0])
        }
        guard off + 12 <= payload.count else { return }
        guard payload[off] == 0x02 else { return }       // table_id = PMT
        let sectionLen = ((Int(payload[off + 1]) & 0x0F) << 8) | Int(payload[off + 2])
        let end = min(off + 3 + sectionLen - 4, payload.count)
        let programInfoLen = ((Int(payload[off + 10]) & 0x0F) << 8) | Int(payload[off + 11])

        streams.removeAll()
        var i = off + 12 + programInfoLen
        while i + 5 <= end {
            let streamType = payload[i]
            let esPid = (UInt16(payload[i + 1] & 0x1F) << 8) | UInt16(payload[i + 2])
            let esInfoLen = ((Int(payload[i + 3]) & 0x0F) << 8) | Int(payload[i + 4])
            streams.append(StreamInfo(pid: esPid, streamType: streamType))
            if streamType == 0x1B { videoPID = esPid }        // H.264
            if streamType == 0x0F { audioPID = esPid }        // AAC ADTS
            i += 5 + esInfoLen
        }
    }
}
