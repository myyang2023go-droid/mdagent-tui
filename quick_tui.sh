#!/bin/sh
# 一键装 mdagent TUI(Linux/macOS,免 root):下载 → 装 textual → 启动首跑向导
# 用法: curl -fsSL https://raw.githubusercontent.com/myyang2023go-droid/mdagent-tui/main/quick_tui.sh | sh
set -e
REPO=https://github.com/myyang2023go-droid/mdagent-tui

command -v python3 >/dev/null 2>&1 || {
  echo "[!] 需要 Python 3.8+: Debian/Ubuntu 先 sudo apt install python3 python3-pip"; exit 1; }
PYV=$(python3 -c 'import sys;print("%d%02d"%sys.version_info[:2])')
[ "$PYV" -lt 308 ] && { echo "[!] Python 版本过低(需 >=3.8),当前 $(python3 -V)"; exit 1; }

D=$(mktemp -d /tmp/mdagent.XXXXXX)
cd "$D"
echo "[1/3] 下载 $REPO ..."
curl -fsSL -o tui.tar.gz "$REPO/archive/refs/heads/main.tar.gz"
tar xzf tui.tar.gz && cd mdagent-tui-main
echo "[2/3] 安装依赖 textual ..."
python3 -m pip install --user textual \
  || python3 -m pip install --user --break-system-packages textual \
  || python3 -m pip install textual
echo "[3/3] 启动 TUI(首跑向导: 服务器回车 -> 选 2 贴 token -> 选开放目录)"
# curl|sh 管道跑时 stdin 被管道占用,input() 会立即 EOF——还给终端
if [ -c /dev/tty ]; then exec < /dev/tty; fi
python3 client/mdagent_tui.py
