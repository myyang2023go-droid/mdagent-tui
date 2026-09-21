# mdagent-tui

云端 MD 智能体的终端客户端:脑子在云端,终端在你手上。

对话 / 项目记忆 / 文件读写(逐笔批准)/ 思维链展示,一个脚本全有;
本地只装一个依赖(textual),不碰系统、免 root。

```
❯ 帮我在当前目录写一个 README,介绍这个模拟方案
  ⏺ ✏️ write README.md
  ⚠ 云端智能体请求写入: README.md (412 字节)   [批准(y) / 拒绝(n)]
```

## 认识 mdagent / Meet mdagent

**中文**

mdagent 是一个**为分子模拟(MD)而生的智能体**:大脑跑在云端,双手长在你电脑的终端里。
你用自然语言下指令,它建输入文件、分析数据、写报告;每次写你本地的文件都会弹批准卡,
你不点「批准」,一个字节都落不了盘。

它不只是个聊天壳,有三样真功夫:

- **项目记忆** —— 每个项目上下文独立(`--resume` 随时续做),云端记住你的方案、参数和进度;
  开放目录放一个 `mdagent.md`(同 Claude Code 的 CLAUDE.md),你的规矩每轮自动生效。
- **共享进化层** —— 智能体把踩过的坑沉淀成原子经验 → 场景 → 知识卡 → 行为策略,
  全员共享、持续蒸馏;`/evolution` 打开进化图谱,能亲眼看它变聪明。
- **绝不野跑** —— 分子动力学引擎(LAMMPS/GROMACS 等)一律不许直接跑;
  受管机器上走 `supervise` 编排上轨发车,看板留痕、自动守护,普通机器干脆硬拒。
  你的目录被囚禁在开放文件夹内,越界读写一律拒绝。

大模型六选一自带 key(Kimi / GLM / Z.ai / DeepSeek / 通义 / MiniMax),
对话烧自己的额度;注册账号 → 管理员批准 → 一条命令开用。

**English**

mdagent is an agent **built for molecular simulation**: its brain runs in the
cloud, its hands live in a terminal on your machine. You type natural
language; it prepares input files, analyzes data, writes reports — and every
write to your local disk pops an approval card first. No click, no bytes.

Beyond the chat shell, three things make it real:

- **Project memory** — each project keeps its own context (`--resume` anytime);
  the cloud remembers your plans, parameters and progress. Drop a
  `mdagent.md` (like Claude Code's CLAUDE.md) in your open dir and your rules
  apply on every turn.
- **Shared evolution layer** — the agent distills every stumble into
  atoms → scenarios → knowledge cards → behavior strategies, shared by all
  users and continuously refined. `/evolution` opens the graph so you can
  literally watch it get smarter.
- **No wild runs** — MD engines (LAMMPS/GROMACS/…) are never executed
  directly. On managed machines, `supervise` launches through an orchestrated,
  dashboard-tracked pipeline; elsewhere the run is flat-out refused. Your
  files stay jailed inside the open directory — reads or writes outside it
  are rejected.

Bring your own LLM key (Kimi / GLM / Z.ai / DeepSeek / Qwen / MiniMax) and
chat on your own quota. Register → admin approves → one command and you're in.


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

## 每次启动 = 全新会话

直接 `mdagent` 打开的是**全新干净会话**(不回放旧对话,云端上下文独立);
续做旧项目用 `--resume` / `/project`,载入时会**自动附带该项目任务文件夹里的
`mdagent.md`(目标/参数/进度),每轮注入。

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
| `/copy` | **免鼠标复制**:空 = 最近一条回复;`/copy 5` = 最近 5 条;`/copy all` = 全部(直达系统剪贴板,粘贴到哪都行) |
| `/paste` | 把系统剪贴板内容放进输入框(终端粘贴失灵时的备胎) |
| `/goal` | 目标面板(多步任务进度) |
| `/apikey` | 换大模型 API Key |
| `/status` | 桥连接状态 + 每小时用量 |
| `/evolution` | 打开智能体**进化图谱**(浏览器):原子→场景→提案→知识卡→行为策略的蒸馏链,数据来自云端共享进化层 |
| `/quit` | 退出 |

**任务跑着想停?按 `ESC`**(Claude Code 同款):云端温和收尾,
已完成的步骤不丢;打断后再发新指令即可。

## 许可

MIT
