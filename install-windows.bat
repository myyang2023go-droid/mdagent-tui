@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === mdagent TUI Windows 一键安装 ===
echo (云端对话 + 文件操作;MD 上轨全链路需 Linux/WSL2,见 README)

py -3 --version >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
  goto :install
)
python --version >nul 2>nul
if %errorlevel%==0 (
  set "PY=python"
  goto :install
)
echo.
echo [!] 未检测到 Python,二选一装好后重新双击本脚本:
echo     winget install -e --id Python.Python.3.12
echo     或 https://www.python.org/downloads/ 安装时勾选 Add python.exe to PATH
pause
exit /b 1

:install
echo.
echo [1/3] 安装依赖 textual ...
%PY% -m pip install --user --upgrade textual
if not %errorlevel%==0 (
  echo [.] pip --user 失败,尝试直接安装 ...
  %PY% -m pip install --upgrade textual
)
echo.
echo [2/3] 安装 mdagent 命令(以后任何窗口输 mdagent 即启动)...
set "DEST=%APPDATA%\mdagent"
set "WA=%LOCALAPPDATA%\Microsoft\WindowsApps"
if not exist "%DEST%" mkdir "%DEST%"
copy /y client\mdagent_tui.py "%DEST%\" >nul
copy /y client\mdagent_client.py "%DEST%\" >nul
> "%WA%\mdagent.cmd" echo @%PY% "%DEST%\mdagent_tui.py" %%*
if not %errorlevel%==0 (
  echo [!] 命令安装失败,不影响本次直接启动
) else (
  echo [ok] mdagent 命令已装好。新开一个终端窗口,输 mdagent 即可启动。
)
echo.
echo [3/3] 本次直接启动 TUI(首跑向导: 服务器回车 - 选 1 账号密码登录 - 选开放目录)
%PY% client\mdagent_tui.py %*
pause
