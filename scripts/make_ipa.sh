#!/usr/bin/env bash
#
# make_ipa.sh —— 把 xcodebuild 的 .app 打成未签名 IPA，供 TrollStore 安装。
#
# 用法（在 ios/PandaLink 目录下）：
#   bash scripts/make_ipa.sh
#
# 前置：已经跑过
#   xcodegen generate
#   xcodebuild -project PandaLink.xcodeproj -scheme PandaLink \
#     -configuration Release -sdk iphoneos -derivedDataPath build \
#     CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
#     ARCHS=arm64 ONLY_ACTIVE_ARCH=NO build
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_NAMES=("PandaLink")
DIST="$ROOT/dist"
mkdir -p "$DIST"

APP_PATH=""
for name in "${APP_NAMES[@]}"; do
  # 优先 Release-iphoneos，其次任意 *.app
  candidate="$ROOT/build/Build/Products/Release-iphoneos/${name}.app"
  if [[ -d "$candidate" ]]; then APP_PATH="$candidate"; break; fi
done

if [[ -z "$APP_PATH" ]]; then
  # 兜底：在 build 目录里搜第一个 .app
  APP_PATH="$(find "$ROOT/build/Build/Products" -maxdepth 2 -name "*.app" -type d 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "$APP_PATH" || ! -d "$APP_PATH" ]]; then
  echo "✗ 找不到编译产物 .app，先跑 xcodebuild" >&2
  exit 1
fi

echo "→ 找到 App: $APP_PATH"

# 校验关键项，避免打出一个装不上 / 跑不起来的包
BIN="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_PATH/Info.plist")"
echo "→ 可执行文件: $BIN"

/usr/bin/lipo -info "$APP_PATH/$BIN" || true

MINOS="$(/usr/libexec/PlistBuddy -c 'Print :MinimumOSVersion' "$APP_PATH/Info.plist" 2>/dev/null || echo "?")"
echo "→ MinimumOSVersion: $MINOS"
if [[ "$MINOS" != "16.1" ]]; then
  echo "⚠  MinimumOSVersion 不是 16.1（实际 $MINOS），TrollStore 在 iOS 16.1 上可能拒绝安装"
fi

# 剥掉可能存在的签名残留（CODE_SIGNING_ALLOWED=NO 通常已无 _CodeSignature）
rm -rf "$APP_PATH/_CodeSignature" "$APP_PATH/SC_Info" "$APP_PATH/embedded.mobileprovision"

STAGE="$DIST/stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/Payload"
cp -R "$APP_PATH" "$STAGE/Payload/"

IPA="$DIST/PandaLink.ipa"
rm -f "$IPA"
( cd "$STAGE" && /usr/bin/zip -qry "$IPA" Payload )
rm -rf "$STAGE"

echo "✓ 产物: $IPA"
/usr/bin/shasum -a 256 "$IPA"
/usr/bin/du -h "$IPA"
