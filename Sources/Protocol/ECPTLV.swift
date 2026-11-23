//
//  ECPTLV.swift
//  PandaLink
//
//  ECP 控制通道的 TLV 子层。
//
//  依据 smali：
//    p/xk.smali  w([BI)[B   构造一个 TLV 记录
//    p/b5.smali  h([B)      从流里切出 TLV 记录列表（Lp/fr 数组）
//    p/fr.smali  <init>([BI)  字段 a:I(类型) b:[B(内容)
//    p/jg.smali  a(Lp/k4;[B)  按 TLV 类型分派处理
//    p/jg.smali  h(I[BZLp/m4;ILjava/lang/Object;)V  发一个 TLV
//
//  记录线格式（小端，8 字节头）：
//    offset 0  u16 type
//    offset 2  u16 length
//    offset 4  u32 reserved（构造时恒 0）
//    offset 8  ... payload(length 字节)
//

import Foundation

struct ECPTLV: Equatable {
    /// `p/fr.a`
    let type: UInt16
    /// `p/fr.b`
    let payload: [UInt8]

    static let headerSize = 8
}

// MARK: - 编

enum ECPTLVCodec {

    /// 对齐 `p/xk;->w([BI)[B`
    static func encode(type: UInt16, payload: [UInt8] = []) -> [UInt8] {
        precondition(payload.count <= 0xFFFF, "TLV payload 超长")
        var out = [UInt8]()
        out.reserveCapacity(ECPTLV.headerSize + payload.count)
        // u16 小端
        out.append(UInt8(type & 0xFF))
        out.append(UInt8((type >> 8) & 0xFF))
        // u16 小端
        let n = UInt16(payload.count)
        out.append(UInt8(n & 0xFF))
        out.append(UInt8((n >> 8) & 0xFF))
        // u32 保留
        out.append(contentsOf: [0, 0, 0, 0])
        out.append(contentsOf: payload)
        return out
    }

    /// 对齐 `p/b5;->h([B)` —— 增量解析，返回完整记录，剩余字节留待下次
    struct StreamParser {
        private var buffer: [UInt8] = []

        mutating func feed(_ chunk: [UInt8]) -> [ECPTLV] {
            guard buffer.count + chunk.count <= 0x0010_0000 else {
                buffer.removeAll(keepingCapacity: true)
                return []
            }
            buffer.append(contentsOf: chunk)

            var out = [ECPTLV]()
            var off = 0
            while buffer.count - off >= ECPTLV.headerSize {
                let type = UInt16(buffer[off]) | (UInt16(buffer[off + 1]) << 8)
                let len = UInt16(buffer[off + 2]) | (UInt16(buffer[off + 3]) << 8)
                let need = ECPTLV.headerSize + Int(len)
                guard buffer.count - off >= need else { break }
                let body = Array(buffer[(off + ECPTLV.headerSize)..<(off + need)])
                out.append(ECPTLV(type: type, payload: body))
                off += need
            }
            if off > 0 {
                buffer.removeFirst(off)
            }
            return out
        }

        mutating func reset() { buffer.removeAll(keepingCapacity: false) }
        var pendingBytes: Int { buffer.count }
    }
}

// MARK: - TLV 类型表（来自 jg.a 的 switch + dex 字符串）

enum ECPTLVType: UInt16 {
    // ── 认证阶段（jg.a 里 0x10 / 0x20 / 0x30 / 0x40 / 0x60 / 0x70 那几个分支）
    case captureConfig      = 0x0010   // 捕获配置（≥27 字节：4+2+2+... 见 readCaptureConfig）
    case authBody           = 0x0020
    case authResult         = 0x0030
    case authConfirm        = 0x0040
    case supportFunction    = 0x0060   // 回 {"supportFunction":0}
    case serviceReady       = 0x0070   // 回 0x138A + 序号

    // ── 认证后（jg.a 的 cond_5 / cond_6 等）
    case ack                = 0x0041   // 空 body
    case extra61            = 0x0061   // 回 {"supportFunction":0}
    case captureAck         = 0x0011   // 发捕获配置应答
    case unhandled          = 0x7F02
}

// MARK: - 若干已知 TLV 报文

/// `p/jg.smali` 的 cond_c：0x10 捕获配置
///   取 u16@0 & 0xFFF0 = width（16 对齐）
///   取 u16@2 & 0xFFF0 = height（16 对齐）
///   取 i32@4          = 某个计数（≥0）
///   取 i32@8          = type，只接受 1 / 2 / 4
///   取 i32@12         = 帧率/码率参数
///   取 byte@25、byte@26
struct ECPCaptureConfig: Equatable {
    var width: Int
    var height: Int
    var limit: Int32
    var mediaType: Int32        // 1 / 2 / 4
    var rate: Int32
    var byte25: Int
    var byte26: Int

    enum ParseError: Error { case truncated, invalid }

    static func parse(_ b: [UInt8]) throws -> ECPCaptureConfig {
        guard b.count >= 0x1B else { throw ParseError.truncated }
        func u16(_ o: Int) -> UInt16 { UInt16(b[o]) | (UInt16(b[o + 1]) << 8) }
        func i32(_ o: Int) -> Int32 {
            Int32(bitPattern: UInt32(b[o]) | (UInt32(b[o + 1]) << 8)
                  | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24))
        }
        let w = Int(u16(0) & 0xFFF0)
        let h = Int(u16(2) & 0xFFF0)
        let limit = i32(4)
        var media = i32(8)
        if media != 1 && media != 2 && media != 4 { media = 1 }
        let rate = i32(12)
        guard w > 0, h > 0, limit >= 0 else { throw ParseError.invalid }
        return ECPCaptureConfig(width: w, height: h, limit: limit,
                                mediaType: media, rate: rate,
                                byte25: Int(b[25]), byte26: Int(b[26]))
    }

    /// 回给车机的 16 字节应答（`jg.a` cond_c 末尾构造的那个 ByteBuffer）
    func acknowledgement() -> [UInt8] {
        var out = [UInt8]()
        ECPCodec.appendU32(&out, UInt32(bitPattern: mediaType))
        out.append(UInt8(UInt16(width) & 0xFF)); out.append(UInt8(UInt16(width) >> 8))
        out.append(UInt8(UInt16(height) & 0xFF)); out.append(UInt8(UInt16(height) >> 8))
        ECPCodec.appendU32(&out, UInt32(bitPattern: Int32(byte25)))
        ECPCodec.appendU32(&out, UInt32(bitPattern: Int32(byte26)))
        return out
    }
}

extension ECPTLVType {
    /// 便于日志
    var label: String {
        switch self {
        case .captureConfig: return "捕获配置"
        case .authBody: return "认证体"
        case .authResult: return "认证结果"
        case .authConfirm: return "认证确认"
        case .supportFunction: return "能力声明"
        case .serviceReady: return "服务就绪"
        case .ack: return "ACK"
        case .extra61: return "能力声明(0x61)"
        case .captureAck: return "捕获应答"
        case .unhandled: return "未处理"
        }
    }
}
