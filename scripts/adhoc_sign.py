#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adhoc_sign.py — 纯 Python 的 ad-hoc 代码签名器（ldid 兼容超集，够 TrollStore/内核用）

为什么需要它：
  改 minos 会让原 Apple/TestFlight 签名失效。若把 LC_CODE_SIGNATURE 直接清零，
  连 entitlements 一起丢了 —— 这个 App 恰恰依赖
    com.apple.developer.networking.HotspotConfiguration
    com.apple.developer.networking.wifi-info
  丢了就连不上车机热点。TrollStore 在安装时会读二进制里已有的 entitlements 再 ldid 重签，
  所以我们必须先把一份"结构合法、哈希自洽、带 entitlements"的签名塞回去。

输出结构（与 Apple/ldid 一致）：
  superblob 0xfade0cc0
    [0] CodeDirectory 0xfade0c02  version 0x20400  flags=CS_ADHOC(0x2)
    [2] Requirements  0xfade0c01  空需求集
    [5] Entitlements  0xfade7171  XML plist
  特殊槽：-1 Info.plist / -2 Requirements / -5 Entitlements（-3/-4/-6 置零）

用法:
  python adhoc_sign.py APP_DIR [--entitlements FILE] [--out-entitlements FILE] [--verify]

  --entitlements  不给则从 APP_DIR 主可执行现有签名里提取；都没有就用 DEFAULT_ENTITLEMENTS
  --verify        签完重新解析自检（推荐）
"""
import argparse, hashlib, os, plistlib, struct, sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY      = 0xFADE0C02
CSMAGIC_REQUIREMENTS       = 0xFADE0C01
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_BLOBWRAPPER        = 0xFADE0B01

CSSLOT_CODEDIRECTORY  = 0
CSSLOT_REQUIREMENTS   = 2
CSSLOT_ENTITLEMENTS   = 5
CSSLOT_DER_ENTITLEMENTS = 7

CS_ADHOC = 0x00000002
PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
HASH_SIZE = 32    # SHA-256
HASH_TYPE = 2     # CS_HASHTYPE_SHA256

LC_CODE_SIGNATURE = 0x1D

DEFAULT_ENTITLEMENTS = {
    "application-identifier": "top.shareway.pandaplayplus.ios",
    "com.apple.developer.team-identifier": "MX42GAQFQ8",
    "get-task-allow": True,
    "com.apple.developer.networking.wifi-info": True,
    "com.apple.developer.networking.HotspotConfiguration": True,
    "com.apple.security.network.client": True,
    "com.apple.security.network.server": True,
    "com.apple.security.device.audio-input": True,
    "com.apple.security.device.camera": True,
}


# ---------------- Mach-O 基础 ----------------

def load_commands(buf):
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    off = 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        out.append((off, cmd, cmdsize))
        off += cmdsize
    return out


def find_signature(buf):
    for off, cmd, cmdsize in load_commands(buf):
        if cmd == LC_CODE_SIGNATURE:
            return off, struct.unpack_from("<II", buf, off + 8)
    return None, (0, 0)


# ---------------- superblob 解析（提 entitlements） ----------------

def parse_superblob(data):
    magic, length, count = struct.unpack_from(">III", data, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError("not a superblob")
    slots = []
    for i in range(count):
        t, o = struct.unpack_from(">II", data, 12 + 8 * i)
        m, ln = struct.unpack_from(">II", data, o)
        slots.append({"type": t, "magic": m, "offset": o, "length": ln,
                      "blob": data[o:o + ln]})
    return slots


def extract_entitlements(buf):
    off, (dataoff, datasize) = find_signature(buf)
    if not dataoff or datasize == 0:
        return None, "无 LC_CODE_SIGNATURE"
    blob = bytes(buf[dataoff:dataoff + datasize])
    try:
        slots = parse_superblob(blob)
    except Exception as e:
        return None, f"superblob 解析失败: {e}"
    for s in slots:
        if s["type"] in (CSSLOT_ENTITLEMENTS, CSSLOT_DER_ENTITLEMENTS):
            if s["magic"] == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                body = s["blob"][8:]
                text = body.rstrip(b"\0")
                try:
                    return plistlib.loads(text), None
                except Exception:
                    try:
                        return plistlib.loads(text, fmt=plistlib.FMT_BINARY), None
                    except Exception as e:
                        return None, f"entitlements plist 解析失败: {e}"
    return None, "签名里没有 entitlements 槽"


# ---------------- blob 构造 ----------------

def _blob(magic, payload):
    return struct.pack(">II", magic, 8 + len(payload)) + payload


def build_requirements():
    # 空需求集：magic + length + count=0，共 12 字节
    return struct.pack(">III", CSMAGIC_REQUIREMENTS, 12, 0)


def build_entitlements_blob(ent):
    xml = plistlib.dumps(ent, fmt=plistlib.FMT_XML)
    return _blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, xml)


def build_code_directory(ident, codeLimit, nCodeSlots, code_hashes, specials):
    """
    specials: dict slot(-1..-6) -> 32B hash
    version 0x20400 布局：
      magic length version flags hashOffset identOffset nSpecialSlots nCodeSlots codeLimit
      hashSize hashType platform pageSize spare2 scatterOffset teamOffset spare3 codeLimit64
      execSegBase execSegLimit execSegFlags
    """
    nSpecialSlots = 6
    hdr_size = 4*9 + 4 + 4*4 + 8 + 8*3   # = 88
    ident_bytes = ident.encode() + b"\0"
    identOffset = hdr_size
    special_start = identOffset + len(ident_bytes)
    hashOffset = special_start + HASH_SIZE * nSpecialSlots

    hdr = struct.pack(
        ">IIIIIIIIIBBBBIIIIQQQQ",
        CSMAGIC_CODEDIRECTORY,          # magic
        0,                              # length (fill later)
        0x20400,                        # version
        CS_ADHOC,                       # flags
        hashOffset,                     # hashOffset
        identOffset,                    # identOffset
        nSpecialSlots,                  # nSpecialSlots
        nCodeSlots,                     # nCodeSlots
        codeLimit & 0xFFFFFFFF,         # codeLimit
        HASH_SIZE, HASH_TYPE, 0, PAGE_SHIFT,   # hashSize hashType platform pageSize
        0,                              # spare2
        0,                              # scatterOffset
        0,                              # teamOffset
        0,                              # spare3
        codeLimit,                      # codeLimit64
        0, 0, 0,                        # execSegBase execSegLimit execSegFlags
    )
    assert len(hdr) == hdr_size, (len(hdr), hdr_size)

    # 特殊槽按 slot -6 .. -1 的升序写入，使 hashOffset - i*HASH_SIZE 恰好是 slot -i
    sp = b""
    for slot in range(-nSpecialSlots, 0):
        sp += specials.get(slot, b"\0" * HASH_SIZE)

    body = hdr + ident_bytes + sp + b"".join(code_hashes)
    body = bytearray(body)
    struct.pack_into(">I", body, 4, len(body))
    return bytes(body)


def build_superblob(blobs):
    """blobs: [(type, bytes)] -> superblob bytes"""
    count = len(blobs)
    header_len = 12 + 8 * count
    offsets = []
    cur = header_len
    for _, b in blobs:
        offs_aligned = (cur + 15) & ~15
        offsets.append(offs_aligned)
        cur = offs_aligned + len(b)
    total = (cur + 15) & ~15

    out = bytearray(total)
    struct.pack_into(">III", out, 0, CSMAGIC_EMBEDDED_SIGNATURE, total, count)
    for i, ((t, b), o) in enumerate(zip(blobs, offsets)):
        struct.pack_into(">II", out, 12 + 8 * i, t, o)
        out[o:o + len(b)] = b
    return bytes(out)


# ---------------- 签名主流程 ----------------

def fix_info_plist_slot(app_dir, entitlements, ident):
    """Info.plist 的哈希槽（slot -1）"""
    return hashlib.sha256(open(os.path.join(app_dir, "Info.plist"), "rb").read()).digest()


def sign_app(app_dir, entitlements=None, verify=False, keep_existing=True):
    """
    对 .app 目录做 ad-hoc 重签。返回 report dict。
    """
    pl = plistlib.load(open(os.path.join(app_dir, "Info.plist"), "rb"))
    ident = pl.get("CFBundleIdentifier", "unknown")
    exe_name = pl["CFBundleExecutable"]
    exe = os.path.join(app_dir, exe_name)

    raw = open(exe, "rb").read()
    if raw[:4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("需要 64 位小端 Mach-O")

    ent = entitlements
    ent_src = "arg"
    if ent is None and keep_existing:
        got, err = extract_entitlements(raw)
        if got:
            ent = got
            ent_src = "extracted"
    if ent is None:
        ent = dict(DEFAULT_ENTITLEMENTS)
        ent["application-identifier"] = ident
        ent_src = "default"

    lc_off, (old_off, old_size) = find_signature(raw)
    if lc_off is None:
        raise SystemExit("没有 LC_CODE_SIGNATURE 槽")

    head = raw[:old_off] if old_size else raw
    codeLimit = (len(head) + 15) & ~15
    if len(head) < codeLimit:
        head = head + b"\0" * (codeLimit - len(head))

    ent_blob = build_entitlements_blob(ent)
    req_blob = build_requirements()
    info_hash = fix_info_plist_slot(app_dir, ent, ident)
    specials = {
        -1: info_hash,
        -2: hashlib.sha256(req_blob).digest(),
        -5: hashlib.sha256(ent_blob).digest(),
    }
    nCodeSlots = (codeLimit + PAGE_SIZE - 1) // PAGE_SIZE

    # ---- 第一遍：占位哈希，求 superblob 的最终长度 ----
    dummy = [b"\0" * HASH_SIZE] * nCodeSlots
    cd_probe = build_code_directory(ident, codeLimit, nCodeSlots, dummy, specials)
    sb_probe = build_superblob([
        (CSSLOT_CODEDIRECTORY, cd_probe),
        (CSSLOT_REQUIREMENTS, req_blob),
        (CSSLOT_ENTITLEMENTS, ent_blob),
    ])
    sig_size = len(sb_probe)

    # ---- 第二遍：先把 LC_CODE_SIGNATURE 写成最终值（它本身在 codeLimit 内，必须先定稿）----
    head = bytearray(head)
    struct.pack_into("<II", head, lc_off + 8, codeLimit, sig_size)

    code_hashes = [hashlib.sha256(bytes(head[i:min(i + PAGE_SIZE, codeLimit)])).digest()
                   for i in range(0, codeLimit, PAGE_SIZE)]
    assert len(code_hashes) == nCodeSlots, (len(code_hashes), nCodeSlots)

    cd = build_code_directory(ident, codeLimit, nCodeSlots, code_hashes, specials)
    sb = build_superblob([
        (CSSLOT_CODEDIRECTORY, cd),
        (CSSLOT_REQUIREMENTS, req_blob),
        (CSSLOT_ENTITLEMENTS, ent_blob),
    ])
    assert len(sb) == sig_size, (len(sb), sig_size)

    out = bytes(head) + sb
    open(exe, "wb").write(out)

    rep = {
        "app": app_dir, "executable": exe, "identifier": ident,
        "entitlements_source": ent_src, "entitlements": ent,
        "codeLimit": codeLimit, "nCodeSlots": len(code_hashes),
        "signature_offset": codeLimit, "signature_size": len(sb),
        "code_directory_size": len(cd),
        "old_signature": {"offset": old_off, "size": old_size},
        "binary_size": len(out),
    }
    if verify:
        rep["verify"] = verify_signature(bytes(out))
    return rep


# ---------------- 自检 ----------------

def verify_signature(buf):
    """重新解析刚写的签名，检查哈希是否自洽"""
    res = {"ok": True, "problems": []}
    lc_off, (dataoff, datasize) = find_signature(buf)
    if not dataoff:
        return {"ok": False, "problems": ["无签名"]}
    blob = bytes(buf[dataoff:dataoff + datasize])
    slots = parse_superblob(blob)
    cd_slot = next((s for s in slots if s["type"] == CSSLOT_CODEDIRECTORY), None)
    if cd_slot is None:
        return {"ok": False, "problems": ["无 CodeDirectory"]}
    cd = cd_slot["blob"]
    (magic, length, version, flags, hashOffset, identOffset, nSpecial,
     nCode, codeLimit) = struct.unpack_from(">IIIIIIIII", cd, 0)
    hashSize, hashType, platform, pageSize = struct.unpack_from(">BBBB", cd, 36)
    res.update({"version": hex(version), "flags": hex(flags), "nSpecialSlots": nSpecial,
                "nCodeSlots": nCode, "codeLimit": codeLimit,
                "hashSize": hashSize, "hashType": hashType, "pageSize": pageSize,
                "identifier": cd[identOffset:cd.index(b"\0", identOffset)].decode(),
                "cd_length": length})
    if dataoff != codeLimit:
        res["ok"] = False
        res["problems"].append(f"codeLimit({codeLimit}) != 签名偏移({dataoff})")

    # 校验 code slots
    bad = 0
    for i in range(nCode):
        off = hashOffset + i * hashSize
        want = cd[off:off + hashSize]
        s = i * (1 << pageSize)
        got = hashlib.sha256(bytes(buf[s:min(s + (1 << pageSize), codeLimit)])).digest()
        if want != got[:hashSize]:
            bad += 1
    res["bad_code_slots"] = bad
    if bad:
        res["ok"] = False
        res["problems"].append(f"{bad}/{nCode} 个 code slot 哈希不匹配")

    # 特殊槽
    def special(i):
        off = hashOffset - i * hashSize
        return cd[off:off + hashSize]

    ent = next((s for s in slots if s["type"] == CSSLOT_ENTITLEMENTS), None)
    req = next((s for s in slots if s["type"] == CSSLOT_REQUIREMENTS), None)
    if ent and special(5) != hashlib.sha256(ent["blob"]).digest():
        res["ok"] = False
        res["problems"].append("slot -5 (entitlements) 哈希不符")
    if req and special(2) != hashlib.sha256(req["blob"]).digest():
        res["ok"] = False
        res["problems"].append("slot -2 (requirements) 哈希不符")
    if ent:
        try:
            res["entitlements"] = plistlib.loads(ent["blob"][8:].rstrip(b"\0"))
        except Exception as e:
            res["problems"].append(f"entitlements 解析失败 {e}")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app")
    ap.add_argument("--entitlements", default=None, help="entitlements plist 文件")
    ap.add_argument("--dump-entitlements", default=None, help="把最终使用的 entitlements 写到该路径")
    ap.add_argument("--no-keep-existing", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    ent = None
    if a.entitlements:
        ent = plistlib.load(open(a.entitlements, "rb"))
    rep = sign_app(a.app, entitlements=ent, verify=a.verify,
                   keep_existing=not a.no_keep_existing)
    if a.dump_entitlements:
        plistlib.dump(rep["entitlements"], open(a.dump_entitlements, "wb"))
        rep["entitlements_written"] = a.dump_entitlements

    import json
    text = json.dumps(rep, ensure_ascii=False, indent=2)
    print(text)
    if a.json:
        open(a.json, "w", encoding="utf8").write(text)
    if a.verify and not rep.get("verify", {}).get("ok"):
        sys.exit(3)


if __name__ == "__main__":
    main()
