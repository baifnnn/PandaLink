#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sign_unsigned.py —— 给「完全没有 LC_CODE_SIGNATURE」的 Mach-O 补上 ad-hoc 签名。

为什么不直接用 adhoc_sign.py：
    CI 里是 CODE_SIGNING_ALLOWED=NO 编出来的裸二进制，load command 里
    连 LC_CODE_SIGNATURE 槽都没有，adhoc_sign 找不到槽就直接退出。

本脚本多做两件事：
    1. 在 load command 区尾部**新增**一条 LC_CODE_SIGNATURE（该区间实测是
       零填充，5144..16384 全 0，塞 16 字节安全）。
    2. 追加签名后同步修正 __LINKEDIT 的 filesize / vmsize，否则 dyld 校验
       段边界会崩。

签名本体仍复用 adhoc_sign.py 的 superblob / CodeDirectory 构造，避免两套实现
哈希算法不一致。
"""
import os
import plistlib
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adhoc_sign as A

sys.stdout.reconfigure(encoding="utf-8")

PAGE = 0x4000

ENTITLEMENTS = {
    "application-identifier": "top.shareway.pandalink",
    "com.apple.security.network.client": True,
    "com.apple.security.network.server": True,
    "get-task-allow": True,
}


def find_segment(buf, want):
    off = 32
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == 0x19:
            name = buf[off + 8:off + 24].rstrip(b"\0").decode()
            if name == want:
                return off
        off += cmdsize
    return None


def ensure_lc_signature(buf):
    """返回 (buf, lc_off)。没有 LC_CODE_SIGNATURE 就在 load command 尾部新增一条。"""
    lc_off, _ = A.find_signature(buf)
    if lc_off is not None:
        return buf, lc_off

    ncmds, sizeofcmds = struct.unpack_from("<II", buf, 16)
    insert_at = 32 + sizeofcmds

    # 安全检查：新增位置必须落在零填充区，且不压到任何 section 内容
    if buf[insert_at:insert_at + 16] != b"\0" * 16:
        raise SystemExit(f"load command 尾部 {insert_at} 不是零填充，不能就地插入")

    b = bytearray(buf)
    struct.pack_into("<IIII", b, insert_at, A.LC_CODE_SIGNATURE, 16, 0, 0)
    struct.pack_into("<II", b, 16, ncmds + 1, sizeofcmds + 16)
    return bytes(b), insert_at


def patch_linkedit(buf, sig_end):
    """把 __LINKEDIT 的 filesize/vmsize 覆盖到包含新签名为止。"""
    seg = find_segment(buf, "__LINKEDIT")
    if seg is None:
        raise SystemExit("找不到 __LINKEDIT 段")

    b = bytearray(buf)
    vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", b, seg + 24)
    new_filesize = sig_end - fileoff
    round_ = lambda x: (x + PAGE - 1) // PAGE * PAGE
    struct.pack_into("<QQQQ", b, seg + 24, vmaddr, round_(new_filesize), fileoff, new_filesize)
    return bytes(b), {"fileoff": fileoff, "old_filesize": filesize, "new_filesize": new_filesize}


def sign(app_dir, verify=True):
    pl_path = os.path.join(app_dir, "Info.plist")
    pl = plistlib.load(open(pl_path, "rb"))
    ident = pl.get("CFBundleIdentifier", "unknown")
    exe_name = pl["CFBundleExecutable"]
    exe = os.path.join(app_dir, exe_name)

    raw = open(exe, "rb").read()
    if raw[:4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("需要 64 位小端 Mach-O")

    raw, lc_off = ensure_lc_signature(raw)

    ent = dict(ENTITLEMENTS)
    ent["application-identifier"] = ident
    # 允许用外部 plist 覆盖（CI 里由 scripts/PandaLink.entitlements 提供）
    ext = os.environ.get("PANDALINK_ENTITLEMENTS")
    if ext and os.path.exists(ext):
        ent = plistlib.load(open(ext, "rb"))
        ent.setdefault("application-identifier", ident)

    ent_blob = A.build_entitlements_blob(ent)
    req_blob = A.build_requirements()
    info_hash = A.hashlib.sha256(open(pl_path, "rb").read()).digest()
    specials = {
        -1: info_hash,
        -2: A.hashlib.sha256(req_blob).digest(),
        -5: A.hashlib.sha256(ent_blob).digest(),
    }

    # codeLimit = 现有文件长度对齐到 16
    codeLimit = (len(raw) + 15) & ~15
    if len(raw) < codeLimit:
        raw = raw + b"\0" * (codeLimit - len(raw))
    nCodeSlots = (codeLimit + A.PAGE_SIZE - 1) // A.PAGE_SIZE

    # ---- 第一遍：占位哈希，只为求出 superblob 的最终长度 ----
    dummy = [b"\0" * A.HASH_SIZE] * nCodeSlots
    cd_probe = A.build_code_directory(ident, codeLimit, nCodeSlots, dummy, specials)
    sb_probe = A.build_superblob([
        (A.CSSLOT_CODEDIRECTORY, cd_probe),
        (A.CSSLOT_REQUIREMENTS, req_blob),
        (A.CSSLOT_ENTITLEMENTS, ent_blob),
    ])
    sig_size = len(sb_probe)

    # ---- 第二遍：先把所有会进页哈希的字段定稿 ----
    b = bytearray(raw)
    # LC_CODE_SIGNATURE: dataoff = codeLimit, datasize = sig_size
    struct.pack_into("<II", b, lc_off + 8, codeLimit, sig_size)
    raw = bytes(b)
    raw, le = patch_linkedit(raw, codeLimit + sig_size)

    code_hashes = [A.hashlib.sha256(raw[i:min(i + A.PAGE_SIZE, codeLimit)]).digest()
                   for i in range(0, codeLimit, A.PAGE_SIZE)]
    assert len(code_hashes) == nCodeSlots, (len(code_hashes), nCodeSlots)

    cd = A.build_code_directory(ident, codeLimit, nCodeSlots, code_hashes, specials)
    sb = A.build_superblob([
        (A.CSSLOT_CODEDIRECTORY, cd),
        (A.CSSLOT_REQUIREMENTS, req_blob),
        (A.CSSLOT_ENTITLEMENTS, ent_blob),
    ])
    assert len(sb) == sig_size, (len(sb), sig_size)

    out = raw + sb
    open(exe, "wb").write(out)

    rep = {
        "app": app_dir, "executable": exe, "identifier": ident,
        "entitlements": ent,
        "codeLimit": codeLimit, "nCodeSlots": nCodeSlots,
        "signature_offset": codeLimit, "signature_size": sig_size,
        "linked_edit": le,
        "binary_size": len(out),
    }
    if verify:
        rep["verify"] = A.verify_signature(out)
    return rep


def main():
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("app")
    ap.add_argument("--json")
    a = ap.parse_args()

    rep = sign(a.app, verify=True)
    text = json.dumps(rep, ensure_ascii=False, indent=2)
    print(text)
    if a.json:
        open(a.json, "w", encoding="utf-8").write(text)
    if not rep["verify"]["ok"]:
        sys.exit(3)


if __name__ == "__main__":
    main()
