//
//  Proto.swift
//  PandaLink
//
//  最小 protobuf 编解码器。
//
//  依据：安卓包 `com.ucar.databus.proto.UCarProto$*` 全部消息类（115 个消息 / 301 字段）
//  的 encode/decode 结构，字段号从各消息类的 `*_FIELD_NUMBER:I` 静态字段实测得出
//  （见 `D:\Projects\_work\panda\android\ucarproto_schema.txt`）。
//
//  只实现 proto3 线格式里实际出现的三种 wire type：
//    varint(0) / length-delimited(2) / fixed32(5, float) / fixed64(1, double)
//  未出现 repeated（除个别 list 字段用 length-delimited 重复 key）。
//

import Foundation

// MARK: - 线格式读写

/// protobuf wire type
enum PBWire: UInt8 {
    case varint = 0
    case fixed64 = 1
    case lengthDelimited = 2
    case startGroup = 3
    case endGroup = 4
    case fixed32 = 5
}

/// 编码器：按字段号顺序追加
struct PBWriter {
    private(set) var bytes = [UInt8]()

    mutating func writeTag(_ field: Int, _ wire: PBWire) {
        writeVarint(UInt64(field) << 3 | UInt64(wire.rawValue))
    }

    mutating func writeVarint(_ v: UInt64) {
        var value = v
        while true {
            let b = UInt8(value & 0x7F)
            value >>= 7
            if value == 0 {
                bytes.append(b)
                return
            }
            bytes.append(b | 0x80)
        }
    }

    mutating func writeInt32(_ field: Int, _ v: Int32) {
        guard v != 0 else { return }                  // proto3 默认值不写
        writeTag(field, .varint)
        // int32 负数按 64 位补码编码（protobuf 规定）
        writeVarint(v < 0 ? UInt64(bitPattern: Int64(v)) : UInt64(v))
    }

    mutating func writeUInt32(_ field: Int, _ v: UInt32) {
        guard v != 0 else { return }
        writeTag(field, .varint)
        writeVarint(UInt64(v))
    }

    mutating func writeBool(_ field: Int, _ v: Bool) {
        guard v else { return }
        writeTag(field, .varint)
        writeVarint(1)
    }

    mutating func writeEnum(_ field: Int, _ v: Int32) {
        writeInt32(field, v)
    }

    mutating func writeBytes(_ field: Int, _ v: [UInt8]) {
        guard !v.isEmpty else { return }
        writeTag(field, .lengthDelimited)
        writeVarint(UInt64(v.count))
        bytes += v
    }

    mutating func writeString(_ field: Int, _ v: String) {
        guard !v.isEmpty else { return }
        writeBytes(field, Array(v.utf8))
    }

    mutating func writeFloat(_ field: Int, _ v: Float) {
        guard v != 0 else { return }
        writeTag(field, .fixed32)
        let bits = v.bitPattern
        bytes.append(UInt8(bits & 0xFF))
        bytes.append(UInt8((bits >> 8) & 0xFF))
        bytes.append(UInt8((bits >> 16) & 0xFF))
        bytes.append(UInt8((bits >> 24) & 0xFF))
    }

    mutating func writeDouble(_ field: Int, _ v: Double) {
        guard v != 0 else { return }
        writeTag(field, .fixed64)
        let bits = v.bitPattern
        for i in 0..<8 { bytes.append(UInt8((bits >> (UInt64(i) * 8)) & 0xFF)) }
    }

    /// 嵌套消息：先序列化子消息，再作为 length-delimited 写入
    mutating func writeMessage(_ field: Int, _ body: [UInt8]) {
        guard !body.isEmpty else { return }
        writeBytes(field, body)
    }
}

/// 解码器：顺序读字段
struct PBReader {
    private let data: [UInt8]
    private var off = 0

    init(_ data: [UInt8]) { self.data = data }

    var isAtEnd: Bool { off >= data.count }

    mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard off < data.count else { throw PBError.truncated }
            let b = data[off]; off += 1
            result |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { return result }
            shift += 7
            if shift > 63 { throw PBError.varintOverflow }
        }
    }

    /// 返回 (字段号, wire type)
    mutating func readTag() throws -> (Int, PBWire) {
        let key = try readVarint()
        let field = Int(key >> 3)
        guard let wire = PBWire(rawValue: UInt8(key & 7)) else {
            throw PBError.unsupportedWire(UInt8(key & 7))
        }
        return (field, wire)
    }

    mutating func readBytes() throws -> [UInt8] {
        let len = Int(try readVarint())
        guard len >= 0, off + len <= data.count else { throw PBError.truncated }
        let v = Array(data[off..<(off + len)])
        off += len
        return v
    }

    mutating func readString() throws -> String {
        String(decoding: try readBytes(), as: UTF8.self)
    }

    mutating func skip(_ wire: PBWire) throws {
        switch wire {
        case .varint: _ = try readVarint()
        case .fixed64:
            guard off + 8 <= data.count else { throw PBError.truncated }
            off += 8
        case .lengthDelimited: _ = try readBytes()
        case .fixed32:
            guard off + 4 <= data.count else { throw PBError.truncated }
            off += 4
        case .startGroup, .endGroup: throw PBError.unsupportedWire(wire.rawValue)
        }
    }
}

enum PBError: Error, CustomStringConvertible {
    case truncated
    case varintOverflow
    case unsupportedWire(UInt8)

    var description: String {
        switch self {
        case .truncated: return "protobuf 数据被截断"
        case .varintOverflow: return "protobuf varint 溢出"
        case .unsupportedWire(let w): return "protobuf 不支持的 wire type \(w)"
        }
    }
}

// MARK: - UCarProto 消息

/// `UCarProto$GetPortRequest$ServerType`
enum PBServerType: Int32 {
    case unknown = 0
    case sensor = 1
    case audio = 2
    case uibc = 3
}

/// `UCarProto$GetPortResponse$Result`
enum PBPortResult: Int32 {
    case unknown = 0
    case success = 1
    case failure = 2
}

/// `UCarProto$AuthRequest` —— 车机 → 手机（authMethod == 1 时）
struct PBAuthRequest {
    var version: Int32 = 0
    var authPk: [UInt8] = []
    var authPkHmac: [UInt8] = []
    var agreementPk: [UInt8] = []
    var agreementPkSig: [UInt8] = []
    var random: [UInt8] = []
    var id: [UInt8] = []
    var model: String = ""
    var userConfirmed: Bool = false
    var workModes: Int32 = 0
    var productName: String = ""

    static func decode(_ bytes: [UInt8]) throws -> PBAuthRequest {
        var r = PBReader(bytes)
        var m = PBAuthRequest()
        while !r.isAtEnd {
            let (f, w) = try r.readTag()
            switch f {
            case 1: m.version = Int32(bitPattern: UInt32(truncatingIfNeeded: try r.readVarint()))
            case 2: m.authPk = try r.readBytes()
            case 3: m.authPkHmac = try r.readBytes()
            case 4: m.agreementPk = try r.readBytes()
            case 5: m.agreementPkSig = try r.readBytes()
            case 6: m.random = try r.readBytes()
            case 7: m.id = try r.readBytes()
            case 8: m.model = try r.readString()
            case 9: m.userConfirmed = try r.readVarint() != 0
            case 10: m.workModes = Int32(bitPattern: UInt32(truncatingIfNeeded: try r.readVarint()))
            case 11: m.productName = try r.readString()
            default: try r.skip(w)
            }
        }
        return m
    }
}

/// `UCarProto$AuthResponse` —— 手机 → 车机
struct PBAuthResponse {
    var version: Int32 = 0x701
    var authPk: [UInt8] = []
    var authPkHmac: [UInt8] = []
    var agreementPk: [UInt8] = []
    var agreementPkSig: [UInt8] = []
    var random: [UInt8] = []
    var result: Int32 = 0
    var workModes: Int32 = 0
    var dayOrNightMode: Int32 = 1
    var screenInfo: String = "1280_720_240_1280_720"

    func encode() -> [UInt8] {
        var w = PBWriter()
        w.writeInt32(1, version)
        w.writeBytes(2, authPk)
        w.writeBytes(3, authPkHmac)
        w.writeBytes(4, agreementPk)
        w.writeBytes(5, agreementPkSig)
        w.writeBytes(6, random)
        w.writeInt32(7, result)
        w.writeInt32(8, workModes)
        w.writeInt32(9, dayOrNightMode)
        w.writeString(10, screenInfo)
        return w.bytes
    }
}

/// `UCarProto$AuthConfirm` —— 车机 → 手机（authMethod == 3 时）
struct PBAuthConfirm {
    var cipher: [UInt8] = []

    static func decode(_ bytes: [UInt8]) throws -> PBAuthConfirm {
        var r = PBReader(bytes)
        var m = PBAuthConfirm()
        while !r.isAtEnd {
            let (f, w) = try r.readTag()
            switch f {
            case 1: m.cipher = try r.readBytes()
            default: try r.skip(w)
            }
        }
        return m
    }
}

/// `UCarProto$AuthIndex` —— 认证通道的顶层信封
struct PBAuthIndex {
    var authRequest: PBAuthRequest?
    var authResponse: PBAuthResponse?
    var authConfirm: PBAuthConfirm?

    static func decode(_ bytes: [UInt8]) throws -> PBAuthIndex {
        var r = PBReader(bytes)
        var m = PBAuthIndex()
        while !r.isAtEnd {
            let (f, w) = try r.readTag()
            switch f {
            case 1: m.authRequest = try PBAuthRequest.decode(r.readBytes())
            case 2: _ = try r.readBytes()          // 手机自己发的应答，一般不回头解析
            case 3: m.authConfirm = try PBAuthConfirm.decode(r.readBytes())
            default: try r.skip(w)
            }
        }
        return m
    }

    /// 只带 authResponse 的信封
    static func response(_ resp: PBAuthResponse) -> [UInt8] {
        var w = PBWriter()
        w.writeMessage(2, resp.encode())
        return w.bytes
    }
}

/// `UCarProto$GetPortRequest` / `GetPortResponse`
struct PBGetPortRequest {
    var type: Int32 = 0

    static func decode(_ bytes: [UInt8]) throws -> PBGetPortRequest {
        var r = PBReader(bytes)
        var m = PBGetPortRequest()
        while !r.isAtEnd {
            let (f, w) = try r.readTag()
            switch f {
            case 1: m.type = Int32(bitPattern: UInt32(truncatingIfNeeded: try r.readVarint()))
            default: try r.skip(w)
            }
        }
        return m
    }

    var serverType: PBServerType { PBServerType(rawValue: type) ?? .unknown }

    var label: String {
        switch serverType {
        case .sensor: return "SENSOR"
        case .audio: return "AUDIO"
        case .uibc: return "UIBC"
        case .unknown: return "UNKNOWN(\(type))"
        }
    }
}

struct PBGetPortResponse {
    var result: Int32 = PBPortResult.success.rawValue
    var port: Int32 = 0

    static func decode(_ bytes: [UInt8]) throws -> PBGetPortResponse {
        var r = PBReader(bytes)
        var m = PBGetPortResponse()
        while !r.isAtEnd {
            let (f, w) = try r.readTag()
            switch f {
            case 1: m.result = Int32(bitPattern: UInt32(truncatingIfNeeded: try r.readVarint()))
            case 2: m.port = Int32(bitPattern: UInt32(truncatingIfNeeded: try r.readVarint()))
            default: try r.skip(w)
            }
        }
        return m
    }

    func encode() -> [UInt8] {
        var w = PBWriter()
        w.writeInt32(1, result)
        w.writeInt32(2, port)
        return w.bytes
    }
}

/// `UCarProto$ControlIndex` —— 控制通道顶层信封（41 个字段，只实现在用的那些）
///
/// 字段类型实测（`UCarProto$ControlIndex.smali` 的 getter 返回类型）：
///   1  heartbeat                 → Heartbeat（message）
///   2  get_port_request          → GetPortRequest（message）
///   3  get_port_response         → GetPortResponse（message）
///   4  notify_car_to_foreground  → NotifyCarToForeground（message，字段 1 timestamp）
///   5  notify_car_to_background  → NotifyCarToBackground（message，字段 1 timestamp）
///   22 bluetooth_mac             → BluetoothMacInfo（message，字段 1 op_type / 2 bluetooth_mac）
///   23 disconnect                → Disconnect（message，无字段）
/// **这些全是 length-delimited 子消息，不是 bool/string** —— 早期按 bool 解会漏读或错位。
struct PBControlIndex {
    var heartbeat: [UInt8]?
    var getPortRequest: PBGetPortRequest?
    var getPortResponse: PBGetPortResponse?
    var notifyCarToForeground: [UInt8]?
    var notifyCarToBackground: [UInt8]?
    var disconnect: [UInt8]?
    var bluetoothMac: [UInt8]?

    var hasDisconnect: Bool { disconnect != nil }
    var hasPortRequest: Bool { getPortRequest != nil }

    static func decode(_ bytes: [UInt8]) throws -> PBControlIndex {
        var r = PBReader(bytes)
        var m = PBControlIndex()
        while !r.isAtEnd {
            let (f, w) = try r.readTag()
            switch f {
            case 1: m.heartbeat = try r.readBytes()
            case 2: m.getPortRequest = try PBGetPortRequest.decode(r.readBytes())
            case 3: m.getPortResponse = try PBGetPortResponse.decode(r.readBytes())
            case 4: m.notifyCarToForeground = try r.readBytes()
            case 5: m.notifyCarToBackground = try r.readBytes()
            case 22: m.bluetoothMac = try r.readBytes()
            case 23: m.disconnect = try r.readBytes()
            default: try r.skip(w)
            }
        }
        return m
    }

    /// 带 getPortResponse 的控制信封
    static func portResponse(_ resp: PBGetPortResponse) -> [UInt8] {
        var w = PBWriter()
        w.writeMessage(3, resp.encode())
        return w.bytes
    }
}
