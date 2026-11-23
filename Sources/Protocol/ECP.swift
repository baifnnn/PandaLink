//
//  ECP.swift
//  PandaLink
//
//  ECP 帧编解码。
//
//  完全按 top.shareway.pandaplayplus v1.0.10 的 smali 实现复刻：
//    p/xk.smali   i([B)Lp/kd;        解析
//    p/yh.smali   a(Lp/kd;[B)[B     构造应答（type+1）
//    p/yh.smali   F(Lp/kd;Lp/ko;JLjava/lang/String;)[B  构造应答（type 不变）
//    p/kd.smali   字段 a:I(类型) b:[B(4 字节) c:[B(帧体)
//
//  线格式（全部小端）：
//    offset 0  u32 type        帧类型
//    offset 4  u32 length      整帧长度（含 16 字节头）
//    offset 8  u32 checksum    = type ^ length
//    offset 12 [4]byte extra   固定 4 字节，通常全 0
//    offset 16 ...             body，长度 = length - 16
//

import Foundation

/// 一帧 ECP。字段命名对齐 smali 里的 `Lp/kd;`。
struct ECPFrame {
    /// smali `kd.a` —— 帧类型
    let type: UInt32
    /// smali `kd.b` —— 头部那 4 个额外字节
    let extra: [UInt8]
    /// smali `kd.c` —— 帧体
    let body: [UInt8]

    static let headerSize = 16
    static let maxFrameSize: UInt32 = 0x0100_0000   // 16 MiB，与 smali 的 0x1000000 一致
    static let minFrameSize: UInt32 = 16

    var totalLength: Int { ECPFrame.headerSize + body.count }
}

// MARK: - 帧类型

enum ECPType {
    static let authRequest: UInt32 = 0x10000       // 手机 → 车机 认证请求
    static let authResponse: UInt32 = 0x10001      // 车机 → 手机
    static let wirelessClientInfo: UInt32 = 0x10010 // 无线客户端信息（HUID 加密）
    static let simpleAck20: UInt32 = 0x10020
    static let simpleAck40: UInt32 = 0x10040
    static let simpleAck200: UInt32 = 0x10200
    static let simpleAck3e0: UInt32 = 0x103e0
    static let simpleAck400: UInt32 = 0x10400
    static let timeSync: UInt32 = 0x10450
    static let simpleAck470: UInt32 = 0x10470
    static let simpleAck610: UInt32 = 0x10610
    static let simpleAck690: UInt32 = 0x10690
    static let controlRequest: UInt32 = 0x20000
    static let simpleAck30000: UInt32 = 0x30000
    static let heartbeat: UInt32 = 0x7000_0000

    /// `yh.F` 里明确「不回包」的类型
    /// （含 0x80000010 / 0x80000020 —— 这两个是可靠传输的 ACK，收到即消费）
    static let noReply: Set<UInt32> = [
        0x40010, 0x30030, 0x30020, 0x30040, 0x102b0,
        0x8000_0010, 0x8000_0020,
    ]

    /// 默认兜底应答的 type：`yh.F` 的 default 分支里 v1 = `frame.type & 0xFF000000`
    /// （smali 用 `const/high16 v1, -0x1000000` + `and-int/2addr` 算出来）。
    /// 例：0x10010 之外的偶数未知类型 0x00200002 → 应答 type 是 0x00000000。
    static func genericAckType(for type: UInt32) -> UInt32 { type & 0xFF00_0000 }

    /// `yh.F` 的 sparse-switch 表里走「wireless client info」的分支
    static let needsWirelessInfo: UInt32 = 0x10010
    /// 走「时间同步」的分支
    static let needsTimeSync: UInt32 = 0x10450

    /// 走 `yh.a(frame, empty)` 即 type+1、空 body 的分支
    static let passThrough: Set<UInt32> = [
        0x10000, 0x20000,
        0x10020, 0x10040, 0x10200, 0x103e0, 0x10400,
        0x10470, 0x10610, 0x10690, 0x30000, 0x7000_0000,
    ]
}

// MARK: - 解析

enum ECPCodec {

    enum ParseError: Error, CustomStringConvertible {
        case tooShort(Int)
        case badLength(declared: UInt32, actual: Int)
        case outOfRange(UInt32)
        case checksumMismatch(type: UInt32, length: UInt32, got: UInt32)

        var description: String {
            switch self {
            case .tooShort(let n): return "ECP 帧过短：\(n) < 16"
            case .badLength(let d, let a): return "ECP 长度不符：声明 \(d)，实际 \(a)"
            case .outOfRange(let l): return "ECP 长度越界：\(l)"
            case .checksumMismatch(let t, let l, let g):
                return "ECP 校验不符：type=0x\(String(t, radix: 16)) len=\(l) got=0x\(String(g, radix: 16))"
            }
        }
    }

    /// 对齐 `p/xk;->i([B)Lp/kd;`
    static func parse(_ data: [UInt8]) throws -> ECPFrame {
        guard data.count >= ECPFrame.headerSize else {
            throw ParseError.tooShort(data.count)
        }
        let type = readU32(data, 0)
        let length = readU32(data, 4)
        let checksum = readU32(data, 8)
        let extra = Array(data[12..<16])

        guard Int(length) == data.count else {
            throw ParseError.badLength(declared: length, actual: data.count)
        }
        guard length >= ECPFrame.minFrameSize, length <= ECPFrame.maxFrameSize else {
            throw ParseError.outOfRange(length)
        }
        guard (type ^ length) == checksum else {
            throw ParseError.checksumMismatch(type: type, length: length, got: checksum)
        }
        let body = data.count > ECPFrame.headerSize
            ? Array(data[ECPFrame.headerSize..<data.count])
            : []
        return ECPFrame(type: type, extra: extra, body: body)
    }

    /// 通用打包：给定 type / extra / body
    static func encode(type: UInt32, extra: [UInt8] = [0, 0, 0, 0], body: [UInt8] = []) -> [UInt8] {
        let total = ECPFrame.headerSize + body.count
        var out = [UInt8]()
        out.reserveCapacity(total)
        appendU32(&out, type)
        appendU32(&out, UInt32(total))
        appendU32(&out, type ^ UInt32(total))
        var e = extra
        if e.count < 4 { e += Array(repeating: 0, count: 4 - e.count) }
        out += e.prefix(4)
        out += body
        return out
    }

    /// 对齐 `p/yh;->a(Lp/kd;[B)[B` —— 应答，type = 原 type + 1，extra 原样保留（补足 4 字节）
    static func reply(to frame: ECPFrame, body: [UInt8] = []) -> [UInt8] {
        encode(type: frame.type &+ 1, extra: frame.extra, body: body)
    }

    /// 对齐 `p/yh;->F(...)` 的 default 分支 —— 通用 ACK
    static func genericAck(for frame: ECPFrame) -> [UInt8] {
        encode(type: ECPType.genericAckType(for: frame.type), extra: frame.extra, body: [])
    }

    /// 对齐 `p/yh;->F(...)` 的分派结果
    enum ReplyPlan: Equatable {
        case none                                   // 不回包
        case passthrough                            // type+1，空 body
        case timeSync                               // type+1，时间同步 JSON
        case wirelessInfo                           // type+1，无线客户端信息 JSON
        case genericAck                             // type = frame.type & 0xFF000000，空 body
    }

    static func plan(for type: UInt32) -> ReplyPlan {
        if type & 1 != 0 { return .none }                       // 奇数=应答帧
        if ECPType.noReply.contains(type) { return .none }
        if (type & 0xFF00_0000) == 0x6000_0000 { return .none }
        if type == ECPType.needsWirelessInfo { return .wirelessInfo }
        if type == ECPType.needsTimeSync { return .timeSync }
        if ECPType.passThrough.contains(type) { return .passthrough }
        return .genericAck
    }

    // MARK: 字节序

    static func readU32(_ b: [UInt8], _ off: Int) -> UInt32 {
        UInt32(b[off]) | (UInt32(b[off + 1]) << 8)
            | (UInt32(b[off + 2]) << 16) | (UInt32(b[off + 3]) << 24)
    }

    static func appendU32(_ out: inout [UInt8], _ v: UInt32) {
        out.append(UInt8(v & 0xFF))
        out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8((v >> 16) & 0xFF))
        out.append(UInt8((v >> 24) & 0xFF))
    }
}

// MARK: - 粘包拆包

/// 对齐 `p/dt;->a([B)V` 的流式拆包：
/// 缓冲累积 → 长度合法（16…16 MiB）→ 整帧到齐 → 解析 → 继续。
final class ECPStreamDecoder {

    private var buffer = [UInt8]()
    private let lock = NSLock()
    private let maxBufferBytes = ECPFrame.maxFrameSize
    private(set) var droppedBytes = 0

    func feed(_ chunk: [UInt8]) -> [ECPFrame] {
        lock.lock()
        defer { lock.unlock() }

        if buffer.count + chunk.count > Int(maxBufferBytes) {
            droppedBytes += buffer.count
            buffer.removeAll(keepingCapacity: true)
        }
        buffer += chunk

        var frames = [ECPFrame]()
        while true {
            guard buffer.count >= ECPFrame.headerSize else { break }
            let declared = ECPCodec.readU32(buffer, 4)
            guard declared >= ECPFrame.minFrameSize, declared <= ECPFrame.maxFrameSize else {
                // 长度非法 → 整段丢弃，等下次重新对齐
                droppedBytes += buffer.count
                buffer.removeAll(keepingCapacity: true)
                break
            }
            let total = Int(declared)
            guard buffer.count >= total else { break }

            let slice = Array(buffer[0..<total])
            buffer.removeFirst(total)
            if let f = try? ECPCodec.parse(slice) {
                frames.append(f)
            } else {
                droppedBytes += total
            }
        }
        return frames
    }

    func reset() {
        lock.lock(); defer { lock.unlock() }
        buffer.removeAll(keepingCapacity: false)
    }
}
