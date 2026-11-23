//
//  Crypto.swift
//  PandaLink
//
//  CarLink 认证通道的密码学复刻。
//
//  依据 `p/e9.smali` 的 `a(Lp/u9;[B)V` 与 `p/p0.smali` 的工具函数：
//    p0.m(PublicKey)[B        → SEC1 非压缩点 0x04||X(32)||Y(32)，65 字节
//    p0.N([B)[B               → BigInteger.toByteArray() 结果定长化为 32 字节
//    p0.C([BI)I               → 大端 int32
//    p0.d([B,[B)[B            → AES/GCM/NoPadding 解密（多段 records）
//    e3.Y([B,[B)[B            → 拼字节
//
//  会话密钥推导（`e9` 里逐条对过）：
//    salt   = carRandom || ownRandom                     (AuthRequest.random + 自己 32 字节随机)
//    prk    = HMAC-SHA256(key = SHA256(salt), data = ECDH(agreement) 共享密钥)
//    okm    = HMAC-SHA256(key = prk, data = "" || "session_key" || 0x01)
//    session_key = okm[0..<16]                            (uibc 复用同一把密钥)
//
//  authPkHmac（仅当车机给了 >= 6 字节的 PIN/口令时非空）：
//    pinKey = HMAC-SHA256(key = SHA256(ownRandom || pin), data = authPk)
//
//  agreementPkSig（同一条件下非空）：
//    SHA256withECDSA(authKey.private, authPk || ownRandom || carRandom)
//

import Foundation
import CryptoKit
import Security

enum CarLinkCryptoError: Error, CustomStringConvertible {
    case badAgreementKey(Int)
    case badPointPrefix(UInt8)
    case ecdhFailed
    case gcmFailed(String)

    var description: String {
        switch self {
        case .badAgreementKey(let n): return "车机 agreementPk 长度非法：\(n)"
        case .badPointPrefix(let b): return "agreementPk 前缀不是 0x04：0x\(String(b, radix: 16))"
        case .ecdhFailed: return "ECDH 协商失败"
        case .gcmFailed(let s): return "AES-GCM 解密失败：\(s)"
        }
    }
}

enum CarLinkCrypto {

    /// 定长化到 32 字节（对齐 `p0.N`）：>32 且首字节 0x00 则砍掉首字节；<32 则左补 0
    static func fixed32(_ b: [UInt8]) -> [UInt8] {
        if b.count == 32 { return b }
        if b.count == 33, b.first == 0x00 { return Array(b[1...]) }
        if b.count > 32 { return Array(b.suffix(32)) }
        return Array(repeating: 0, count: 32 - b.count) + b
    }

    /// SEC1 非压缩点（对齐 `p0.m`）
    static func uncompressedPoint(_ key: P256.KeyAgreement.PublicKey) -> [UInt8] {
        let rep = key.rawRepresentation          // 65 字节 0x04||X||Y
        return [UInt8](rep)
    }

    static func uncompressedPoint(_ key: P256.Signing.PublicKey) -> [UInt8] {
        let rep = key.rawRepresentation
        return [UInt8](rep)
    }

    /// 车机 agreementPk（65 字节 0x04||X||Y）→ CryptoKit 公钥
    static func parseCarAgreementKey(_ raw: [UInt8]) throws -> P256.KeyAgreement.PublicKey {
        guard raw.count == 65 else { throw CarLinkCryptoError.badAgreementKey(raw.count) }
        guard raw[0] == 0x04 else { throw CarLinkCryptoError.badPointPrefix(raw[0]) }
        do {
            return try P256.KeyAgreement.PublicKey(rawRepresentation: Data(raw))
        } catch {
            throw CarLinkCryptoError.ecdhFailed
        }
    }

    /// 会话密钥推导。返回 16 字节。
    static func deriveSessionKey(
        ownAgreementKey: P256.KeyAgreement.PrivateKey,
        carAgreementKeyRaw: [UInt8],
        carRandom: [UInt8],
        ownRandom: [UInt8]
    ) throws -> [UInt8] {
        let carKey = try parseCarAgreementKey(carAgreementKeyRaw)
        let shared: SharedSecret
        do {
            shared = try ownAgreementKey.sharedSecretFromKeyAgreement(with: carKey)
        } catch {
            throw CarLinkCryptoError.ecdhFailed
        }
        let sharedBytes = shared.withUnsafeBytes { [UInt8]($0) }

        let salt = carRandom + ownRandom
        let saltDigest = [UInt8](SHA256.hash(data: Data(salt)))

        // prk = HMAC-SHA256(key: SHA256(salt), data: sharedSecret)
        let prk = hmacSHA256(key: saltDigest, data: sharedBytes)

        // okm = HMAC-SHA256(key: prk, data: "" || "session_key" || 0x01)
        let okm = hmacSHA256(key: prk, data: Array("session_key".utf8) + [0x01])
        return Array(okm.prefix(16))
    }

    /// authPkHmac（车机给了 PIN 才有）
    static func authPkHmac(
        authPk: [UInt8],
        ownRandom: [UInt8],
        pin: [UInt8]?
    ) -> [UInt8] {
        guard let pin, pin.count >= 6 else { return [] }
        let pinKey = [UInt8](SHA256.hash(data: Data(ownRandom + pin)))
        return hmacSHA256(key: pinKey, data: authPk)
    }

    /// agreementPkSig（车机给了 PIN 才有）
    static func agreementPkSignature(
        authSigningKey: P256.Signing.PrivateKey,
        authPk: [UInt8],
        ownRandom: [UInt8],
        carRandom: [UInt8],
        pin: [UInt8]?
    ) throws -> [UInt8] {
        guard let pin, pin.count >= 6 else { return [] }
        let message = authPk + ownRandom + carRandom
        let sig = try authSigningKey.signature(for: Data(message))
        return [UInt8](sig.derRepresentation)
    }

    /// 对齐 `p0.d([B,[B)[B`：AES/GCM 解密，输入可能是多段
    /// 格式：重复 [ u32 大端 ivLen | iv | u32 大端 ctLen | ct ]
    static func decryptGCM(key: [UInt8], payload: [UInt8]) throws -> [UInt8] {
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw CarLinkCryptoError.gcmFailed("密钥长度 \(key.count)")
        }
        let sym = SymmetricKey(data: Data(key))
        var out = [UInt8]()
        var off = 0
        while off + 4 <= payload.count {
            let ivLen = Int(readBE32(payload, off)); off += 4
            guard ivLen >= 0, off + ivLen <= payload.count else { break }
            let iv = Array(payload[off..<(off + ivLen)]); off += ivLen

            guard off + 4 <= payload.count else { break }
            let ctLen = Int(readBE32(payload, off)); off += 4
            guard ctLen >= 0, off + ctLen <= payload.count else { break }
            let ct = Array(payload[off..<(off + ctLen)]); off += ctLen

            do {
                let box = try AES.GCM.SealedBox(
                    nonce: try AES.GCM.Nonce(data: Data(iv)),
                    ciphertext: Data(ct.dropLast(min(16, ct.count))),
                    tag: Data(ct.suffix(min(16, ct.count)))
                )
                let plain = try AES.GCM.open(box, using: sym)
                out += [UInt8](plain)
            } catch {
                throw CarLinkCryptoError.gcmFailed(error.localizedDescription)
            }
        }
        return out
    }

    // MARK: 基础

    static func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let k = SymmetricKey(data: Data(key))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(data), using: k)
        return [UInt8](mac)
    }

    static func readBE32(_ b: [UInt8], _ off: Int) -> UInt32 {
        (UInt32(b[off]) << 24) | (UInt32(b[off + 1]) << 16)
            | (UInt32(b[off + 2]) << 8) | UInt32(b[off + 3])
    }

    static func appendBE32(_ out: inout [UInt8], _ v: UInt32) {
        out.append(UInt8((v >> 24) & 0xFF))
        out.append(UInt8((v >> 16) & 0xFF))
        out.append(UInt8((v >> 8) & 0xFF))
        out.append(UInt8(v & 0xFF))
    }

    /// 生成一对固定长度的随机
    static func randomBytes(_ n: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return b
    }
}
