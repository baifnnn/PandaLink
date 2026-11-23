//
//  CarlinkAuthChannel.swift
//  PandaLink
//
//  AUTH 通道（57209）状态机，对应 `p/e9`。
//
//  帧头 param = authMethod：
//    1  AuthRequest  车机 → 手机
//    3  AuthConfirm  车机 → 手机
//    2  AuthResponse 手机 → 车机（我们发出时用）
//
//  AuthRequest 处理（`p/e9;->a` 的 authMethod==1 分支）：
//    1. 存 carId / carModel / workModes
//    2. ownRandom = 32 字节 SecureRandom
//    3. agreementPk 必须 65 字节且首字节 0x04，否则放弃（`:cond_10`）
//    4. ECDH：本机 agreementKeyPair.private × 车机 agreementPk → sharedSecret
//    5. sessionKey = HKDF-ish（见 Crypto.swift）
//    6. pinUsed = (PIN 长度 >= 6)
//       pinUsed → authPkHmac + agreementPkSig
//       !pinUsed → 两者都是空
//    7. 组 AuthResponse（version 0x701 / result 0 / dayOrNightMode 1 /
//       screenInfo "1280_720_240_1280_720"）→ AuthIndex field 2 → 发出
//
//  AuthConfirm 处理（authMethod==3）：
//    sessionKey 未推导 → 抛 "AuthConfirm before key derivation"
//    否则 AES-GCM 解出 phoneIp（UTF-8）；失败回落 socket peer ip
//    回调 onAuthenticated(phoneIp, sessionKey, carId, carModel, workModes)
//

import Foundation
import CryptoKit

struct CarlinkAuthResult {
    var phoneIP: String
    var sessionKey: [UInt8]
    var carID: [UInt8]
    var carModel: String
    var workModes: Int32
}

final class CarlinkAuthChannel {

    enum AuthError: Error, CustomStringConvertible {
        case badAgreementKeyLength(Int)
        case badAgreementKeyPrefix(UInt8)
        case confirmBeforeKeyDerivation
        case decryptFailed(String)

        var description: String {
            switch self {
            case .badAgreementKeyLength(let n):
                return "车机 agreementPk 长度非法：\(n)（应为 65）"
            case .badAgreementKeyPrefix(let b):
                return "agreementPk 首字节不是 0x04：0x\(String(b, radix: 16))"
            case .confirmBeforeKeyDerivation:
                return "AuthConfirm before key derivation"
            case .decryptFailed(let s):
                return "AuthConfirm 解密失败：\(s)"
            }
        }
    }

    /// 车机从 socket 上看过去的地址，解密失败时兜底
    var socketPeerAddress: () -> String = { "0.0.0.0" }

    var onAuthenticated: ((CarlinkAuthResult) -> Void)?
    /// 每步的可读日志（对齐 `CarlinkAuth` tag）
    var onLog: ((String) -> Void)?

    private(set) var authSigningKey = P256.Signing.PrivateKey()
    private(set) var agreementKey = P256.KeyAgreement.PrivateKey()

    private var carID: [UInt8] = []
    private var carModel = ""
    private var workModes: Int32 = 0
    private var ownRandom: [UInt8] = []
    private(set) var sessionKey: [UInt8]?

    /// 6 位数字 PIN（对应 `CarlinkHostActivity.z`，范围 100000–999999）
    var pin: String = ""

    private weak var channel: CarlinkChannel?

    init() {}

    /// 生成两对 P-256 密钥（对齐 `p/l9` 的 `:pswitch_8`：先 authKeyPair 再 agreementKeyPair）
    func start(on channel: CarlinkChannel) {
        self.channel = channel
        authSigningKey = P256.Signing.PrivateKey()
        agreementKey = P256.KeyAgreement.PrivateKey()
        log("AUTH channel started, waiting for AuthRequest")
    }

    /// 入口：由 `CarlinkChannel.onFrame` 转进来
    func handle(frame: CarlinkFrame, body: [UInt8]) {
        switch frame.param {
        case 1: handleAuthRequest(body)
        case 3: handleAuthConfirm(body)
        default: log("unexpected auth method \(frame.param)")
        }
    }

    // MARK: authMethod == 1

    private func handleAuthRequest(_ body: [UInt8]) {
        guard let idx = try? PBAuthIndex.decode(body), let req = idx.authRequest else {
            log("AuthRequest 解析失败")
            return
        }

        log("AuthRequest version=\(req.version) model=\(req.model) "
            + "idLen=\(req.id.count) authPkLen=\(req.authPk.count) "
            + "agreementPkLen=\(req.agreementPk.count) randomLen=\(req.random.count) "
            + "userConfirmed=\(req.userConfirmed) workModes=\(req.workModes)")

        carID = req.id
        carModel = req.model
        workModes = req.workModes

        let carRandom = req.random
        ownRandom = CarLinkCrypto.randomBytes(32)

        guard req.agreementPk.count == 65 else {
            log(AuthError.badAgreementKeyLength(req.agreementPk.count).description)
            return
        }
        guard req.agreementPk.first == 0x04 else {
            log(AuthError.badAgreementKeyPrefix(req.agreementPk[0]).description)
            return
        }

        let key: [UInt8]
        do {
            key = try CarLinkCrypto.deriveSessionKey(
                ownAgreementKey: agreementKey,
                carAgreementKeyRaw: req.agreementPk,
                carRandom: carRandom,
                ownRandom: ownRandom
            )
        } catch {
            log("ECDH 失败：\(error)")
            return
        }
        sessionKey = key
        log("derived session_key (\(key.count)B); uibc uses same key")

        // PIN 判定：`p/y9;->b()` 返回空串时视作 null
        let pinBytes: [UInt8]? = pin.isEmpty ? nil : Array(pin.utf8)
        let pinUsed = (pinBytes?.count ?? 0) >= 6

        let authPk = CarLinkCrypto.uncompressedPoint(authSigningKey.publicKey)
        let agreementPk = CarLinkCrypto.uncompressedPoint(agreementKey.publicKey)

        let authPkHmac = CarLinkCrypto.authPkHmac(authPk: authPk, ownRandom: ownRandom, pin: pinBytes)

        var agreementPkSig: [UInt8] = []
        if pinUsed {
            agreementPkSig = (try? CarLinkCrypto.agreementPkSignature(
                authSigningKey: authSigningKey,
                authPk: authPk,
                ownRandom: ownRandom,
                carRandom: carRandom,
                pin: pinBytes
            )) ?? []
        }

        var resp = PBAuthResponse()
        resp.version = 0x701
        resp.authPk = authPk
        resp.authPkHmac = authPkHmac
        resp.agreementPk = agreementPk
        resp.agreementPkSig = agreementPkSig
        resp.random = ownRandom
        resp.result = 0
        resp.workModes = workModes
        resp.dayOrNightMode = 1
        resp.screenInfo = "1280_720_240_1280_720"

        let payload = PBAuthIndex.response(resp)
        channel?.send(channel: .auth, param: 2, payload: payload)

        log("AuthResponse sent (result=0, pinUsed=\(pinUsed), "
            + "authPkHmac=\(authPkHmac.count)B, agreementPkSig=\(agreementPkSig.count)B)")
    }

    // MARK: authMethod == 3

    private func handleAuthConfirm(_ body: [UInt8]) {
        guard let idx = try? PBAuthIndex.decode(body), let confirm = idx.authConfirm else {
            log("AuthConfirm 解析失败")
            return
        }
        guard let key = sessionKey else {
            log(AuthError.confirmBeforeKeyDerivation.description)
            return
        }

        let phoneIP: String
        do {
            let plain = try CarLinkCrypto.decryptGCM(key: key, payload: confirm.cipher)
            phoneIP = String(decoding: plain, as: UTF8.self)
        } catch {
            log("AuthConfirm decrypt failed, falling back to socket peer ip")
            phoneIP = socketPeerAddress()
        }

        log("AuthConfirm -> phoneIp=\(phoneIP)")

        let result = CarlinkAuthResult(phoneIP: phoneIP,
                                       sessionKey: key,
                                       carID: carID,
                                       carModel: carModel,
                                       workModes: workModes)
        onAuthenticated?(result)
    }

    // MARK: 发送侧加密变换（对齐 `p/l9` 的 `:pswitch_7`）

    /// 用 sessionKey 做 AES-GCM 加密，输出 `[u32 ivLen][iv][u32 ctLen][ct]`
    func encrypt(_ plain: [UInt8]) -> [UInt8] {
        guard let key = sessionKey else { return plain }
        let sym = SymmetricKey(data: Data(key))
        guard let box = try? AES.GCM.seal(Data(plain), using: sym),
              let combined = box.combined else { return plain }
        // CryptoKit 的 combined = nonce(12) || ciphertext || tag(16)
        let nonce = [UInt8](combined.prefix(12))
        let rest = [UInt8](combined.dropFirst(12))

        var out = [UInt8]()
        CarLinkCrypto.appendBE32(&out, UInt32(nonce.count))
        out += nonce
        CarLinkCrypto.appendBE32(&out, UInt32(rest.count))
        out += rest
        return out
    }

    /// 接收侧解密变换（对齐 `p/l9` 的 `:pswitch_6`）
    func decrypt(_ cipher: [UInt8]) -> [UInt8] {
        guard let key = sessionKey else { return cipher }
        return (try? CarLinkCrypto.decryptGCM(key: key, payload: cipher)) ?? cipher
    }

    private func log(_ s: String) { onLog?(s) }
}
