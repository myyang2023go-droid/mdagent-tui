# mdagent-tui

云端 MD 智能体的终端客户端:脑子在云端,终端在你手上。

对话 / 项目记忆 / 文件读写(逐笔批准)/ 思维链展示,一个脚本全有;
本地只装一个依赖(textual),不碰系统、免 root。

```
❯ 帮我在当前目录写一个 README,介绍这个模拟方案
  ⏺ ✏️ write README.md
  ⚠ 云端智能体请求写入: README.md (412 字节)   [批准(y) / 拒绝(n)]
```

## 一键安装

**Linux / macOS**(一条命令):

```bash
curl -fsSL https://raw.githubusercontent.com/myyang2023go-droid/mdagent-tui/main/quick_tui.sh | sh
```

**Windows**:
[点此下载 ZIP](https://github.com/myyang2023go-droid/mdagent-tui/archive/refs/heads/main.zip)
→ 解压 → 双击 `install-windows.bat`

(Python < 3.8 装不了 textual 时,可用零依赖 REPL 版
`python3 client/mdagent_client.py`。)

## 首跑三步

启动后进入向导:

1. **服务器** —— 直接回车(用默认云端),或填自建服务器地址
2. **登录** —— 选 `1` 账号密码登录(推荐),或选 `2` 贴管理员发的 `mda_` 开头 token
3. **开放目录** —— 选一个工作目录,云端智能体只能读写这个目录里的文件

没有账号?在云端首页提交注册申请(自带大模型 API key),获批后即可登录。

## 安全模型

- **目录囚禁**:云端对本机的读写限定在你选的开放目录;路径越界直接拒
- **写操作逐笔批准**:每次写文件/改文件/删文件弹批准卡,100 秒不答自动拒
  (可用 `/auto` 切免确认,自负其责)
- **绝不野跑**:智能体想直接跑 MD 引擎(lmp/gmx/mpirun…)会被执行器硬拒;
  受管机器上须带 `supervise` 走编排门发车,全程看板留痕
- **令牌安全**:token 只存本机 `~/.mdagent_client.json`(权限 600);
  HTTPS 服务器做 SHA256 证书指纹 pinning,防中间人

## 常用命令(输入框里打 `/` 有菜单)

| 命令 | 作用 |
|---|---|
| `/project <名>` | 切会话项目(上下文独立,自动回放云端历史) |
| `/root <目录>` | 换开放给智能体的本地目录 |
| `/auto` | 写操作免确认开关 |
| `/goal` | 目标面板(多步任务进度) |
| `/apikey` | 换大模型 API Key |
| `/status` | 桥连接状态 + 每小时用量 |
| `/quit` | 退出 |

## 许可

MIT
