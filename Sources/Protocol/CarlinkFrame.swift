//
//  CarlinkFrame.swift
//  PandaLink
//
//  CarLink 通道（端口 57209/57219/57229/57239/57249/57259）真正的帧格式。
//
//  ⚠️ 与 `ECP.swift` 里的 16 字节小端帧不是一回事：
//    - `p/k9;->b` 发的是本文件这套 **20 字节大头 + CRC16-MODBUS**（`p/u9`）
//    - 16 字节小端 ECP 帧（`p/xk;->i` / `p/yh;->a` / `p/yh;->F`）走的是 CarLife-ADB 那条链
//      （`p/h1` / `p/dt` / `p/zu`，端口 tcp:10922 / 10920 / 10921）
//
//  帧头 20 字节，全部大端（`p/p0;->p` 与 `p/p0;->B` 都是大端读写）：
//    offset 0   u32  totalLength   整帧长度，含 20 字节头（`u9.a` 里 = body.count + 0x14）
//    offset 4   u32  sequence      `AtomicInteger.getAndIncrement()`，初值 1
//    offset 8   u32  unixSeconds   `System.currentTimeMillis() / 1000`
//    offset 12  u8   flags         bit0 = mt, bits1-2 = nc, bits3-4 = rl
//    offset 13  u8   channel       `p/ma`（NONE/CONTROL/SENSOR/AUTH/AUDIO/VIDEO/CERT/ACK）
//    offset 14  u16  param         调用方给的子类型（`u9.h`，如 AuthResponse 用 2）
//    offset 16  u16  reserved      恒 0
//    offset 18  u16  crc16         覆盖前 18 字节
//    offset 20  ...  body
//
//  校验在 `p/p0;->i([B)`：
//    `len >= 0x14`；读 len/seq/sec；flags 拆三组；channel 查枚举；param = u16@14；
//    读 u16@18 与 `p0.h(p0, 18)` 比，不等则抛 `IllegalStateException("bad checksum expect=… actual=…")`
//
//  `p/p0;->h([BI)` 逐行（`p0.smali:997`）：
//    `crc = 0`；每个字节 `crc ^= b`；8 轮：
//      `bit = crc & 1` → `crc >>= 1` → `if bit != 0 { crc ^= 0xA001 }`
//    最后 `crc & 0xFFFF`。
//
//  ⚠️ 命名：这是 **CRC-16/ARC（IBM）**，poly 0xA001 反射、**init 0x0000**、不 xor-out。
//     常见资料把它叫 CRC-16/MODBUS，但 MODBUS 的 init 是 0xFFFF、check 值 0x4B37；
//     这里 init=0，check 值应为 0xBB3D（"123456789"）。已用 Python 复刻 smali 验证过。
//

import Foundation

// MARK: - 帧标志

/// `p/mt`：帧方向
enum CarlinkDirection: Int, CustomStringConvertible {
    case car = 0       // 枚举名 "CAR"
    case phone = 1     // 枚举名 "PHONE"

    var description: String { self == .car ? "CAR" : "PHONE" }
}

/// `p/nc`：载荷编码
enum CarlinkPayloadEncoding: Int, CustomStringConvertible {
    case raw = 0
    case pb3 = 1
    case rawNoEncrypted = 2


    var description: String {
        switch self {
        case .raw: return "RAW"
        case .pb3: return "PB3"
        case .rawNoEncrypted: return "RAW_NO_ENCRYPTED"
        }
    }
}

/// `p/rl`：交互角色
enum CarlinkRole: Int, CustomStringConvertible {
    case send = 0
    case req = 1
    case res = 2
    case sendSync = 3

    var description: String {
        switch self {
        case .send: return "SEND"
        case .req: return "REQ"
        case .res: return "RES"
        case .sendSync: return "SEND_SYNC"
        }
    }
}

/// `p/ma`：通道
enum CarlinkChannelID: Int, CaseIterable, CustomStringConvertible {
    case none = 0
    case control = 1
    case sensor = 2
    case auth = 3
    case audio = 4
    case video = 5
    case cert = 6
    case ack = 7

    var description: String {
        switch self {
        case .none: return "NONE"
        case .control: return "CONTROL"
        case .sensor: return "SENSOR"
        case .auth: return "AUTH"
        case .audio: return "AUDIO"
        case .video: return "VIDEO"
        case .cert: return "CERT"
        case .ack: return "ACK"
        }
    }

    var role: ChannelRole {
        switch self {
        case .auth: return .auth
        case .control: return .control
        case .sensor: return .sensor
        case .video: return .video
        case .cert: return .cert
        case .audio, .none, .ack: return .media   // AUDIO 与 MEDIA 共用 57229
        }
    }
}

// MARK: - 帧

struct CarlinkFrame: Equatable {
    static let headerSize = 20
    static let maxPayload = 0x0100_0000

    var totalLength: Int
    var sequence: UInt32
    var unixSeconds: UInt32
    var direction: CarlinkDirection
    var encoding: CarlinkPayloadEncoding
    var role: CarlinkRole
    var channel: CarlinkChannelID
    var param: UInt16
    var body: [UInt8]

    /// 构造时自动算总长（对齐 `u9.a` 里 `a = body.count + 0x14`）
    init(sequence: UInt32,
         unixSeconds: UInt32 = UInt32(Date().timeIntervalSince1970),
         direction: CarlinkDirection = .phone,
         encoding: CarlinkPayloadEncoding = .raw,
         role: CarlinkRole = .res,
         channel: CarlinkChannelID,
         param: UInt16 = 0,
         body: [UInt8] = []) {
        self.sequence = sequence
        self.unixSeconds = unixSeconds
        self.direction = direction
        self.encoding = encoding
        self.role = role
        self.channel = channel
        self.param = param
        self.body = body
        self.totalLength = body.count + Self.headerSize
    }
}

// MARK: - CRC-16/ARC

enum CarlinkCRC {
    /// 对齐 `p/p0;->h([BI)I`（`p0.smali:997`）。
    /// poly 0xA001 反射、init 0x0000、不 xor-out —— 即 CRC-16/ARC。
    /// `count` 是参与计算的**字节数**（调用侧传 18 = 帧头去掉 crc 自身）。
    static func crc16(_ bytes: [UInt8], count: Int? = nil) -> UInt16 {
        let n = min(count ?? bytes.count, bytes.count)
        var crc: UInt32 = 0
        for i in 0..<n {
            crc ^= UInt32(bytes[i])
            for _ in 0..<8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001
                } else {
                    crc >>= 1
                }
            }
        }
        return UInt16(crc & 0xFFFF)
    }
}

// MARK: - 编解码

enum CarlinkFrameCodec {

    enum ParseError: Error, CustomStringConvertible {
        case tooShort(Int)
        case badLength(Int)
        case badChecksum(expect: UInt16, actual: UInt16)

        var description: String {
            switch self {
            case .tooShort(let n): return "CarLink 帧过短：\(n) < 20"
            case .badLength(let n): return "CarLink 帧长度非法：\(n)"
            case .badChecksum(let e, let a):
                return "bad checksum expect=0x\(String(e, radix: 16)) actual=0x\(String(a, radix: 16))"
            }
        }
    }

    /// 对齐 `p/u9;->a([B)[B`
    static func encode(_ frame: CarlinkFrame) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: CarlinkFrame.headerSize + frame.body.count)
        let total = out.count

        writeBE32(&out, 0, UInt32(total))
        writeBE32(&out, 4, frame.sequence)
        writeBE32(&out, 8, frame.unixSeconds)

        // flags = (mt & 1) | ((nc & 3) << 1) | ((rl & 3) << 3)
        let flags = UInt8((frame.direction.rawValue & 1)
                          | ((frame.encoding.rawValue & 3) << 1)
                          | ((frame.role.rawValue & 3) << 3))
        out[12] = flags
        out[13] = UInt8(frame.channel.rawValue & 0xFF)
        out[14] = UInt8((Int(frame.param) >> 8) & 0xFF)
        out[15] = UInt8(Int(frame.param) & 0xFF)
        out[16] = 0
        out[17] = 0

        let crc = CarlinkCRC.crc16(out, count: 18)
        out[18] = UInt8((UInt16(crc) >> 8) & 0xFF)
        out[19] = UInt8(UInt16(crc) & 0xFF)

        if !frame.body.isEmpty {
            out.replaceSubrange(CarlinkFrame.headerSize..<total, with: frame.body)
        }
        return out
    }

    /// 对齐 `p/p0;->i([B)Lp/u9;`
    static func parse(_ data: [UInt8]) throws -> CarlinkFrame {
        guard data.count >= CarlinkFrame.headerSize else {
            throw ParseError.tooShort(data.count)
        }
        let total = Int(readBE32(data, 0))
        guard total >= CarlinkFrame.headerSize, total <= CarlinkFrame.maxPayload, total == data.count else {
            throw ParseError.badLength(total)
        }
        let seq = readBE32(data, 4)
        let sec = readBE32(data, 8)

        let flags = data[12]
        let direction = CarlinkDirection(rawValue: Int(flags & 1)) ?? .car
        let encoding = CarlinkPayloadEncoding(rawValue: Int((flags >> 1) & 3)) ?? .raw
        let role = CarlinkRole(rawValue: Int((flags >> 3) & 3)) ?? .send
        let channel = CarlinkChannelID(rawValue: Int(data[13])) ?? .none
        let param = UInt16(data[14]) << 8 | UInt16(data[15])

        let expect = UInt16(data[18]) << 8 | UInt16(data[19])
        let actual = CarlinkCRC.crc16(data, count: 18)
        guard expect == actual else {
            throw ParseError.badChecksum(expect: expect, actual: actual)
        }

        let body = data.count > CarlinkFrame.headerSize
            ? Array(data[CarlinkFrame.headerSize...])
            : []
        return CarlinkFrame(sequence: seq,
                            unixSeconds: sec,
                            direction: direction,
                            encoding: encoding,
                            role: role,
                            channel: channel,
                            param: param,
                            body: body)
    }

    static func readBE32(_ b: [UInt8], _ off: Int) -> UInt32 {
        (UInt32(b[off]) << 24) | (UInt32(b[off + 1]) << 16)
            | (UInt32(b[off + 2]) << 8) | UInt32(b[off + 3])
    }

    static func writeBE32(_ out: inout [UInt8], _ off: Int, _ v: UInt32) {
        out[off] = UInt8((v >> 24) & 0xFF)
        out[off + 1] = UInt8((v >> 16) & 0xFF)
        out[off + 2] = UInt8((v >> 8) & 0xFF)
        out[off + 3] = UInt8(v & 0xFF)
    }
}

// MARK: - 流式拆帧

/// CarLink 通道的增量拆帧器。
/// `p/n2` 的 rx 分支读一次性读到多少就 `p0.i` 一次，但真实 TCP 会粘包，
/// 这里按总长字段切齐，行为等价且更稳。
final class CarlinkStreamDecoder {
    private var buffer = [UInt8]()
    private let limit: Int

    private(set) var droppedBytes = 0

    init(limit: Int = CarlinkFrame.maxPayload) {
        self.limit = limit
    }

    func reset() {
        buffer.removeAll(keepingCapacity: true)
    }

    var pendingBytes: Int { buffer.count }

    func feed(_ chunk: [UInt8]) -> [CarlinkFrame] {
        guard !chunk.isEmpty else { return [] }
        if buffer.count + chunk.count > limit {
            droppedBytes += buffer.count + chunk.count
            buffer.removeAll(keepingCapacity: true)
            return []
        }
        buffer += chunk

        var frames = [CarlinkFrame]()
        while buffer.count >= CarlinkFrame.headerSize {
            let total = Int(CarlinkFrameCodec.readBE32(buffer, 0))
            guard total >= CarlinkFrame.headerSize, total <= limit else {
                // 长度非法 → 整段丢弃，对齐 `dt` 的 `ECP length out of range` 行为
                droppedBytes += buffer.count
                buffer.removeAll(keepingCapacity: true)
                break
            }
            guard buffer.count >= total else { break }

            let slice = Array(buffer[0..<total])
            buffer.removeFirst(total)
            if let f = try? CarlinkFrameCodec.parse(slice) {
                frames.append(f)
            } else {
                droppedBytes += total
            }
        }
        return frames
    }
}
