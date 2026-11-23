#!/usr/bin/env bash
#
# make_ipa.sh —— 把 xcodebuild 的 .app 打成 **已 ad-hoc 签名** 的 IPA，直接喂 TrollStore。
#
# 用法（仓库根目录）：
#   bash scripts/make_ipa.sh
#
# 前置：已经跑过
#   xcodegen generate
#   xcodebuild -project PandaLink.xcodeproj -scheme PandaLink \
#     -configuration Release -sdk iphoneos -derivedDataPath build \
#     CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
#     ARCHS=arm64 ONLY_ACTIVE_ARCH=NO build
#
# 为什么要自己签：
#   CODE_SIGNING_ALLOWED=NO 编出来的裸二进制连 LC_CODE_SIGNATURE 都没有，
#   TrollStore 装得进去但拿不到 entitlements（连不上车机热点、后台不留活）。
#   scripts/sign_unsigned.py 会补上 LC 槽 + __LINKEDIT 边界 + CodeDirectory。
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="$ROOT/dist"
mkdir -p "$DIST"

APP_PATH=""
candidate="$ROOT/build/Build/Products/Release-iphoneos/PandaLink.app"
if [[ -d "$candidate" ]]; then
  APP_PATH="$candidate"
else
  APP_PATH="$(find "$ROOT/build/Build/Products" -maxdepth 2 -name "PandaLink.app" -type d 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "$APP_PATH" || ! -d "$APP_PATH" ]]; then
  echo "✗ 找不到编译产物 PandaLink.app，先跑 xcodebuild" >&2
  exit 1
fi

echo "→ 找到 App: $APP_PATH"

BIN="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_PATH/Info.plist")"
echo "→ 可执行文件: $BIN"
/usr/bin/lipo -info "$APP_PATH/$BIN" || true

MINOS="$(/usr/libexec/PlistBuddy -c 'Print :MinimumOSVersion' "$APP_PATH/Info.plist" 2>/dev/null || echo "?")"
echo "→ MinimumOSVersion: $MINOS"
if [[ "$MINOS" != "16.1" ]]; then
  echo "⚠  MinimumOSVersion 不是 16.1（实际 $MINOS），TrollStore 在 iOS 16.1 上可能拒绝安装"
fi

# ---- 拷贝到工作区再签，避免污染 build 目录 ----
STAGE="$DIST/stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/Payload"
cp -R "$APP_PATH" "$STAGE/Payload/PandaLink.app"
WORK="$STAGE/Payload/PandaLink.app"

# 清掉可能存在的旧签名残留
rm -rf "$WORK/_CodeSignature" "$WORK/SC_Info" "$WORK/embedded.mobileprovision"

# ---- 图标兜底 ----
# 正常路径：Assets.xcassets 被 actool 编成 Assets.car + AppIcon 键。
# 兜底路径：如果 actool 没跑（或资产目录没进资源阶段），直接把散装 PNG 拷进 .app，
# 靠 Info.plist 的 CFBundleIconFiles 生效 —— 否则桌面只会显示空白网格占位。
if [[ -f "$WORK/Assets.car" ]]; then
  echo "→ 图标：Assets.car 已生成（$(/usr/bin/stat -f%z "$WORK/Assets.car") B）"
else
  echo "⚠  没有 Assets.car，走散装 PNG 兜底"
  copied=0
  for f in "$ROOT"/Sources/Resources/Icon-*.png; do
    if [[ -f "$f" ]]; then
      cp "$f" "$WORK/"
      copied=$((copied+1))
    fi
  done
  if [[ "$copied" -eq 0 ]]; then
    echo "✗ 散装图标也没有，App 将显示空白图标" >&2
  else
    echo "→ 已拷入 $copied 个 Icon-*.png"
  fi
fi

# ---- ad-hoc 签名（补 LC_CODE_SIGNATURE 槽 + entitlements）----
# entitlements 走外部 plist：iOS 16.1 + TrollStore 下 ad-hoc 签名保留特批权限
# （wifi-info / HotspotConfiguration），普通开发者证书拿不到这两项。
export PANDALINK_ENTITLEMENTS="$ROOT/scripts/PandaLink.entitlements"
python3 scripts/sign_unsigned.py "$WORK" \
  --json "$DIST/sign-report.json" \
  || { echo "✗ 签名失败" >&2; exit 1; }

echo "→ 签名自检结果："
python3 - "$DIST/sign-report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
v = r.get("verify", {})
print(f"   CodeDirectory flags={v.get('flags')}  slots={v.get('nCodeSlots')}  "
      f"codeLimit={v.get('codeLimit')}  hashType={v.get('hashType')}")
print(f"   bad_code_slots={v.get('bad_code_slots', 0)}  ok={v.get('ok')}")
print(f"   entitlements={sorted(r.get('entitlements', {}).keys())}")
if not v.get("ok"):
    print("   problems:", v.get("problems"))
    sys.exit(1)
PY

# ---- 打包 ----
IPA="$DIST/PandaLink.ipa"
rm -f "$IPA"
( cd "$STAGE" && /usr/bin/zip -qry "$IPA" Payload )
rm -rf "$STAGE"

echo "✓ 产物: $IPA"
/usr/bin/shasum -a 256 "$IPA"
/usr/bin/du -h "$IPA"
