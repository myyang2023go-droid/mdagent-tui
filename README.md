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

推荐向导里选 `1` 直接账号密码登录(token 自动获取,不用粘贴)。
之后随时 `/login` 重新登录或换账号。

## 本地策略 mdagent.md(同 Claude Code 的 CLAUDE.md)

在开放目录放一个 `mdagent.md`,写你的规矩/偏好/项目背景:

```markdown
# 我的策略
- 回复用中文,先给结论再给细节
- LAMMPS 输入统一用 metal 单位制
- 每次跑完模拟自动出温度/能量曲线
```

之后每轮对话自动附带(云端标记为策略注入,**不进对话历史、不算轮次**);
`/policy` 随时查看,改完文件即生效。计算/仿真类任务,智能体会按内置纪律
先在开放目录建分类任务文件夹,并在其中维护任务级 `mdagent.md`(目标/参数/进度),
续做时先读它再继续。

## 续做旧项目(同 Claude Code 的 --resume)

```bash
mdagent --resume     # 列出你的项目(按最近活跃排序),输序号续做
mdagent -c           # 直接续做最近的项目
mdagent --project 名字   # 直接指定项目
```

进去之后也可以随时 `/resume`(列表选号)或 `/project 名字` 切换,
切了自动回放云端历史。

## 日常运行:输 mdagent

装好之后不再需要进目录跑脚本——任何位置、任何时候:

```
mdagent
```

Windows 同样新开终端输 `mdagent`。若提示找不到命令,Linux/macOS 重开终端
(或 `export PATH="$HOME/.local/bin:$PATH"`)。

没有账号?三选一注册:

- 浏览器打开 <https://47.94.209.90/mdagent/register.html> 填表提交(推荐)
- TUI 首跑向导里选 `3` 在终端注册
- 命令行:`curl -sk https://47.94.209.90/mdagent/v1/apply -H 'Content-Type: application/json' -d '{"username":"名字","password":"至少8位","provider":"kimi-coding","api_key":"sk-…"}'`

大模型服务六选一(自带 key,对话消耗自己的额度;`/apikey` 随时可换,
会自动打开对应控制台):Kimi(moonshot)、GLM(bigmodel)、Z.ai(zhipu)、
**DeepSeek**、通义 Qwen(阿里百炼)、MiniMax。

提交后等管理员批准,即可账号密码登录。

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
| `/login` | **账号密码登录**(token 自动取回,密码不回显;换号/重登都用它) |
| `/resume` | 挑旧项目续做(按最近活跃排序,输序号即切,历史自动回放) |
| `/project <名>` | 切会话项目(上下文独立,自动回放云端历史) |
| `/policy` | 查看/重载本地策略 `mdagent.md` |
| `/root <目录>` | 换开放给智能体的本地目录 |
| `/auto` | 写操作免确认开关 |
| `/goal` | 目标面板(多步任务进度) |
| `/apikey` | 换大模型 API Key |
| `/status` | 桥连接状态 + 每小时用量 |
| `/quit` | 退出 |

**任务跑着想停?按 `ESC`**(Claude Code 同款):云端温和收尾,
已完成的步骤不丢;打断后再发新指令即可。

## 许可

MIT
