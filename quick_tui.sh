#!/bin/sh
# 一键装 mdagent TUI(Linux/macOS,免 root):下载 → 装 textual → 启动首跑向导
# 用法(免向导,token 直接嵌进命令发给使用者):
#   curl -fsSL https://raw.githubusercontent.com/myyang2023go-droid/mdagent-tui/main/quick_tui.sh | sh -s -- --token mda_xxx --root ~/mdtest
# 不带参数则进首跑向导
set -e
REPO=https://github.com/myyang2023go-droid/mdagent-tui

command -v python3 >/dev/null 2>&1 || {
  echo "[!] 需要 Python 3.8+: Debian/Ubuntu 先 sudo apt install python3 python3-pip"; exit 1; }
PYV=$(python3 -c 'import sys;print("%d%02d"%sys.version_info[:2])')
[ "$PYV" -lt 308 ] && { echo "[!] Python 版本过低(需 >=3.8),当前 $(python3 -V)"; exit 1; }

D=$(mktemp -d /tmp/mdagent.XXXXXX)
cd "$D"
echo "[1/3] 下载 $REPO ..."
# 国内网络 github.com 常不通,依次回退:codeload → api.github.com → raw 逐文件
dl_archive() {
  curl -fsSL --connect-timeout 8 --max-time 90 -o tui.tar.gz \
    "$REPO/archive/refs/heads/main.tar.gz" && return 0
  curl -fsSL --connect-timeout 8 --max-time 90 -o tui.tar.gz \
    "https://codeload.github.com/myyang2023go-droid/mdagent-tui/tar.gz/refs/heads/main" && return 0
  curl -fsSL --connect-timeout 8 --max-time 90 -o tui.tar.gz \
    "https://api.github.com/repos/myyang2023go-droid/mdagent-tui/tarball/main" && return 0
  return 1
}
if dl_archive; then
  tar xzf tui.tar.gz
  cd "$(find . -maxdepth 1 -mindepth 1 -type d | head -1)"
else
  echo "[i] 归档源全不通,改用 raw.githubusercontent 逐文件下载 ..."
  RAW=https://raw.githubusercontent.com/myyang2023go-droid/mdagent-tui/main
  mkdir -p client
  curl -fsSL --connect-timeout 8 -o client/mdagent_tui.py "$RAW/client/mdagent_tui.py"
  curl -fsSL --connect-timeout 8 -o client/mdagent_client.py "$RAW/client/mdagent_client.py"
  curl -fsSL --connect-timeout 8 -o install.sh "$RAW/install.sh"
fi
echo "[2/4] 安装依赖 textual ..."
python3 -m pip install --user textual \
  || python3 -m pip install --user --break-system-packages textual \
  || python3 -m pip install textual
echo "[3/4] 安装 mdagent 命令(以后任何目录输 mdagent 即启动)..."
sh install.sh
echo "[4/4] 启动 TUI(首跑向导: 服务器回车 -> 选 1 账号密码登录 -> 选开放目录)"
# curl|sh 管道跑时 stdin 被管道占用,input() 会立即 EOF——还给终端
if [ -c /dev/tty ]; then exec < /dev/tty; fi
python3 client/mdagent_tui.py "$@"
