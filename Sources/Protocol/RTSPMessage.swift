//
//  RTSPMessage.swift
//  PandaLink
//
//  RTSP 1.0 报文编解码。只覆盖 WFD sink 需要的那些：
//    OPTIONS / GET_PARAMETER / SET_PARAMETER / SETUP / PLAY / PAUSE / TEARDOWN
//
//  对端（车机 source）回来的报文形态参考 `libovmsink.so`：
//    0x124359  "RTSP/1.0 200 OK"
//    0x1242ff  "505 RTSP Version not supported"
//    0x12436b  "Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER"
//    0x1246c0  "Content-Type: text/parameters"
//    0x1246e0  "Content-Length: %d"
//    0x12448c  "wfd_car_display_mode: ..."
//    0x1249e7  "rtsp://%s/wfd1.0/streamid=0"
//    0x1248d8  "Session: %s"
//    0x124e8d  "CSeq: %d"
//

import Foundation

// MARK: - 请求方法

enum RTSPMethod: String {
    case options       = "OPTIONS"
    case getParameter  = "GET_PARAMETER"
    case setParameter  = "SET_PARAMETER"
    case setup         = "SETUP"
    case play          = "PLAY"
    case pause         = "PAUSE"
    case teardown      = "TEARDOWN"

    /// 对端可能用 `wfd_trigger_method` 让我们发这些
    static func fromTrigger(_ s: String) -> RTSPMethod? {
        switch s.uppercased() {
        case "SETUP":    return .setup
        case "PLAY":     return .play
        case "PAUSE":    return .pause
        case "TEARDOWN": return .teardown
        default:         return nil
        }
    }
}

// MARK: - 报文

struct RTSPMessage {

    /// 请求行的方法（请求报文）
    var method: RTSPMethod? = nil
    /// 请求行 / 状态行的 URI
    var uri: String = "*"
    /// 状态码（响应报文）
    var statusCode: Int? = nil
    /// 原因短语（响应报文）
    var reason: String? = nil

    /// 头部。同名头保留顺序（WFD 里 `wfd_*` 可能重复）
    var headers: [(String, String)] = []
    /// 正文（text/parameters 或 SDP）
    var body: String = ""

    var isResponse: Bool { statusCode != nil }

    // MARK: 头部读写

    func header(_ name: String) -> String? {
        let lower = name.lowercased()
        return headers.first { $0.0.lowercased() == lower }?.1
    }

    func headerValues(_ name: String) -> [String] {
        let lower = name.lowercased()
        return headers.filter { $0.0.lowercased() == lower }.map { $0.1 }
    }

    var cseq: Int? { header(WFDHeader.cseq).flatMap { Int($0) } }
    var session: String? { header(WFDHeader.session) }
    var contentType: String? { header(WFDHeader.contentType) }

    // MARK: 构造

    static func request(
        _ method: RTSPMethod,
        uri: String,
        cseq: Int,
        headers extra: [(String, String)] = [],
        body: String = "",
        userAgent: String = "PandaLink/1.0"
    ) -> RTSPMessage {
        var m = RTSPMessage(method: method, uri: uri)
        m.headers = [
            (WFDHeader.cseq, "\(cseq)"),
            (WFDHeader.userAgent, userAgent),
        ]
        m.headers.append(contentsOf: extra)
        if !body.isEmpty {
            let len = body.utf8.count
            m.headers.append((WFDHeader.contentType, "text/parameters"))
            m.headers.append((WFDHeader.contentLength, "\(len)"))
        }
        m.body = body
        return m
    }

    static func response(
        to req: RTSPMessage,
        status: Int = 200,
        reason: String = "OK",
        headers extra: [(String, String)] = [],
        body: String = ""
    ) -> RTSPMessage {
        var m = RTSPMessage(uri: req.uri, statusCode: status, reason: reason)
        if let c = req.cseq {
            m.headers.append((WFDHeader.cseq, "\(c)"))
        }
        m.headers.append((WFDHeader.date, RTSPMessage.rfc1123Date()))
        m.headers.append(contentsOf: extra)
        if !body.isEmpty {
            let len = body.utf8.count
            m.headers.append((WFDHeader.contentType, "text/parameters"))
            m.headers.append((WFDHeader.contentLength, "\(len)"))
        }
        m.body = body
        return m
    }

    // MARK: 序列化

    func encoded() -> Data {
        var s = ""
        if let method {
            s += "\(method.rawValue) \(uri) RTSP/1.0\r\n"
        } else {
            let code = statusCode ?? 200
            s += "RTSP/1.0 \(code) \(reason ?? "OK")\r\n"
        }
        for (k, v) in headers {
            s += "\(k): \(v)\r\n"
        }
        s += "\r\n"
        s += body
        return Data(s.utf8)
    }

    // MARK: 解析

    enum ParseError: Error, CustomStringConvertible {
        case noHeaderTerminator
        case malformedStartLine(String)
        case malformedHeader(String)

        var description: String {
            switch self {
            case .noHeaderTerminator:        return "RTSP 报文没有空行结尾"
            case .malformedStartLine(let l): return "RTSP 起始行无法解析：\(l)"
            case .malformedHeader(let l):    return "RTSP 头部无法解析：\(l)"
            }
        }
    }

    /// 解析一段**完整**报文（调用方保证头部已到齐，且正文已按 Content-Length 截好）
    static func parse(_ bytes: [UInt8]) throws -> RTSPMessage {
        let text = String(decoding: bytes, as: UTF8.self)
        // 头与正文分隔：优先 CRLFCRLF，退回 LFLF
        var headerPart: String
        var bodyPart: String
        if let r = text.range(of: "\r\n\r\n") {
            headerPart = String(text[text.startIndex..<r.lowerBound])
            bodyPart = String(text[r.upperBound...])
        } else if let r = text.range(of: "\n\n") {
            headerPart = String(text[text.startIndex..<r.lowerBound])
            bodyPart = String(text[r.upperBound...])
        } else {
            throw ParseError.noHeaderTerminator
        }

        let lines = headerPart
            .replacingOccurrences(of: "\r\n", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
        guard let startLine = lines.first.map(String.init), !startLine.isEmpty else {
            throw ParseError.malformedStartLine("<empty>")
        }

        var msg: RTSPMessage
        if startLine.uppercased().hasPrefix("RTSP/") {
            // 状态行：RTSP/1.0 200 OK
            let comps = startLine.split(separator: " ", maxSplits: 2,
                                        omittingEmptySubsequences: true).map(String.init)
            guard comps.count >= 2, let code = Int(comps[1]) else {
                throw ParseError.malformedStartLine(startLine)
            }
            msg = RTSPMessage(uri: "*", statusCode: code,
                              reason: comps.count >= 3 ? comps[2] : "")
        } else {
            // 请求行：OPTIONS * RTSP/1.0 / SETUP rtsp://... RTSP/1.0
            let comps = startLine.split(separator: " ", maxSplits: 2,
                                        omittingEmptySubsequences: true).map(String.init)
            guard comps.count >= 2, let m = RTSPMethod(rawValue: comps[0].uppercased()) else {
                throw ParseError.malformedStartLine(startLine)
            }
            msg = RTSPMessage(method: m, uri: comps[1])
        }

        for line in lines.dropFirst() {
            let l = String(line)
            if l.isEmpty { continue }
            guard let colon = l.firstIndex(of: ":") else {
                throw ParseError.malformedHeader(l)
            }
            let k = String(l[l.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let v = String(l[l.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            msg.headers.append((k, v))
        }

        msg.body = bodyPart
        return msg
    }

    static func rfc1123Date(_ date: Date = Date()) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return f.string(from: date)
    }
}

// MARK: - 流式拆包

/// RTSP 是「头部 + Content-Length 正文」的流式协议，TCP 上会粘包。
/// 这个解码器负责把任意切分的字节流还原成一条条完整报文。
final class RTSPStreamDecoder {

    private var buffer: [UInt8] = []
    private(set) var droppedBytes = 0

    static let maxHeaderBytes = 64 * 1024
    static let maxBodyBytes = 4 * 1024 * 1024

    func reset() {
        buffer.removeAll(keepingCapacity: false)
    }

    /// 喂入新字节，返回这次能解析出的所有完整报文
    func feed(_ chunk: [UInt8]) -> [RTSPMessage] {
        buffer.append(contentsOf: chunk)
        var out: [RTSPMessage] = []

        while true {
            guard let headerEnd = findHeaderEnd() else {
                // 头都没齐。超长就整段丢弃，避免无限增长
                if buffer.count > RTSPStreamDecoder.maxHeaderBytes {
                    droppedBytes += buffer.count
                    buffer.removeAll(keepingCapacity: false)
                }
                break
            }

            // headerEnd 指向正文第一字节
            let headerBytes = Array(buffer[0..<headerEnd])
            let bodyLen = contentLength(in: headerBytes)
            let total = headerEnd + bodyLen
            guard bodyLen <= RTSPStreamDecoder.maxBodyBytes else {
                droppedBytes += buffer.count
                buffer.removeAll(keepingCapacity: false)
                break
            }
            guard buffer.count >= total else { break }   // 正文还没齐

            let full = Array(buffer[0..<total])
            buffer.removeFirst(total)

            do {
                out.append(try RTSPMessage.parse(full))
            } catch {
                droppedBytes += total
            }
        }
        return out
    }

    /// 返回正文起始下标（头部含 CRLFCRLF）
    private func findHeaderEnd() -> Int? {
        let n = buffer.count
        guard n >= 4 else { return nil }
        var i = 0
        while i + 3 < n {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A,
               buffer[i + 2] == 0x0D, buffer[i + 3] == 0x0A {
                return i + 4
            }
            // 容忍纯 LF 的实现
            if buffer[i] == 0x0A, buffer[i + 1] == 0x0A {
                return i + 2
            }
            i += 1
        }
        return nil
    }

    private func contentLength(in headerBytes: [UInt8]) -> Int {
        let text = String(decoding: headerBytes, as: UTF8.self)
        for line in text.split(whereSeparator: { $0 == "\n" }) {
            let l = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let colon = l.firstIndex(of: ":") else { continue }
            let k = l[l.startIndex..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            if k == "content-length" {
                let v = l[l.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                return Int(v) ?? 0
            }
        }
        return 0
    }
}
