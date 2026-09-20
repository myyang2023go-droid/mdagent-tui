#!/bin/sh
# 装 mdagent 命令(免 root):复制 TUI 到 ~/.local/share/mdagent,
# 在 ~/.local/bin/mdagent 放启动器——之后任何目录输 mdagent 即启动。
# 升级 = 重跑一遍(幂等覆盖)。
set -e
SRC=$(cd "$(dirname "$0")" && pwd)
DEST="$HOME/.local/share/mdagent"
BIN="$HOME/.local/bin"
mkdir -p "$DEST" "$BIN"
cp "$SRC/client/mdagent_tui.py" "$SRC/client/mdagent_client.py" "$DEST/"

cat > "$BIN/mdagent" <<EOF
#!/bin/sh
exec python3 "$DEST/mdagent_tui.py" "\$@"
EOF
chmod +x "$BIN/mdagent"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *)
    for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
      [ -f "$RC" ] || touch "$RC"
      grep -q '.local/bin' "$RC" 2>/dev/null || \
        printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC"
    done
    echo "[i] ~/.local/bin 原本不在 PATH,已写入 ~/.bashrc(和 ~/.zshrc)"
    echo "    重开终端,或先执行: export PATH=\"\$HOME/.local/bin:\$PATH\""
    ;;
esac
echo "[ok] 装好了:任何目录输 mdagent 即启动(程序文件在 $DEST)"
