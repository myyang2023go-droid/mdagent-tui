#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mdagent TUI 客户端:终端里的工作台,脑子在云端。
单文件、仅一个第三方依赖(textual)、零智能体 IP——只有联网/对话/本地文件执行器。

用法:
  python3 mdagent_tui.py --token mda_xxx          # 首次
  python3 mdagent_tui.py                          # 之后免参数
  mdagent --resume                                # 挑旧项目续做(-c = 最近的)
  mdagent --project 名字                          # 直接指定项目

本地策略(同 Claude Code 的 CLAUDE.md):在开放目录放一个 mdagent.md,
写你的规矩/偏好/项目背景,每轮对话自动注入云端(标记为策略,不进对话历史,
不算轮次);/policy 查看。计算/仿真类任务智能体会按纪律先建分类任务文件夹,
并在其中维护任务级 mdagent.md 记录目标/参数/进度,--resume 续做接着读。

界面(Claude Code 风格 clean-room 外壳,Textual 渲染):全宽 transcript
(用户 ❯ 前缀、智能体 markdown 流式 ▌、思维链暗色斜体流、文件操作 ⏺ 行)
+ 底部圆角输入框 + 底部状态条(spinner/项目/目录/用量);目标与文件操作
面板收进 Ctrl+G 侧坞;云端要写本地文件时弹琥珀色批准卡,按 y 批准 / n 拒绝
(100s 未答自动拒)。任务跑着时按 ESC 可打断(Claude Code 同款,
云端温和收尾,已完成的步骤不丢)。

命令(输入框里打):
  /login         账号密码登录(token 自动取回,密码不回显;换号/重登都用它)
  /resume        挑旧项目续做(按最近活跃排序;也收序号/名字,/resume 3)
  /project <名>  切换会话项目(不同项目上下文独立,切了自动回放云端历史)
  /policy        查看/重载本地策略 mdagent.md
  /root <目录>   切换开放给智能体的本地目录
  /auto          写操作免确认开关(默认关,逐笔批准)
  /goal          目标面板(查看当前任务进度)
  /status        桥状态 + 每小时用量
  /quit          退出(或 Ctrl+C)

安全模型(与网页版/REPL 版相同):
  云端证书指纹 pinning(防中间人冒充服务器);本地文件囚禁在开放目录
  (resolve 静态判定 + O_NOFOLLOW + /proc/self/fd 打开后回验挡 TOCTOU);
  写文件逐笔批准;op_id 去重防 requeue 重放;配置 ~/.mdagent_client.json 600。
"""
import argparse
import asyncio
import collections
import functools
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

try:
    from rich.markdown import Markdown as RichMarkdown
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.widgets import Button, Input, Static
except ImportError:
    sys.stderr.write("缺少依赖 textual,先装: pip3 install --user textual\n"
                     "(装不了就改用纯 REPL 版 mdagent_client.py)\n")
    raise SystemExit(2)

_BUILTIN_SERVER = "https://47.94.209.90/mdagent"
CONFIG = os.path.join(os.path.expanduser("~"), ".mdagent_client.json")  # 三个客户端共用
MAX_FILE_BYTES = 1024 * 1024


def _kit_get(key):
    """本地管线套件配置(install.sh 生成 /etc/mdagent-kit.json;缺文件=未装)。"""
    try:
        with open(os.environ.get("MDAGENT_KIT_CONFIG",
                                 "/etc/mdagent-kit.json"),
                  encoding="utf-8") as f:
            v = json.load(f).get(key)
        if isinstance(v, str) and v.strip():
            return os.path.expanduser(v.strip())
    except Exception:
        pass
    return None


# 本机 MD 编排管线(通用门): supervise 发车经它以 mdorch 身份进看板/收养
MDRUN_GATE = (_kit_get("mdrun_gate")
              or "/usr/local/md-bin/mdrun_gate.py")
GATE_USER = _kit_get("gate_user") or "mdorch"
CLOUD_CASES = _kit_get("cloud_cases") or os.path.join(
    os.path.expanduser("~"), "mdsim-data", "cases", "cloud")

# 服务器地址与证书 SHA256 指纹(有效期至 2027-05-01;换证需重新下载本文件)。
# kit 配置 server_default/cert_sha256 可覆盖;连非默认服务器且未配指纹 → 走系统 CA 校验
DEFAULT_SERVER = _kit_get("server_default") or _BUILTIN_SERVER
_BUILTIN_CERT = ("F1:75:DF:A3:B5:0F:69:7A:BA:88:C8:23:80:5D:44:11:"
                 "E2:2C:AE:83:33:C5:99:47:A2:01:60:AB:63:BA:7C:69")
CERT_SHA256 = (_kit_get("cert_sha256")
               or (_BUILTIN_CERT if DEFAULT_SERVER == _BUILTIN_SERVER
                   else None))

class _PinnedConn(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        if not CERT_SHA256:
            return
        der = self.sock.getpeercert(binary_form=True)
        fp = ":".join("%02X" % b for b in hashlib.sha256(der).digest())
        if fp != CERT_SHA256:
            raise ssl.SSLError("云端证书指纹不匹配(可能中间人)!实得 %s…" % fp[:23])


class _PinnedHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedConn, req, context=self._context)


if CERT_SHA256:
    _SSL_CTX = ssl._create_unverified_context()  # 自签跳过 CA 链,认证靠指纹比对
    _OPENER = urllib.request.build_opener(_PinnedHandler(context=_SSL_CTX))
else:
    _OPENER = urllib.request.build_opener()      # 自定义服务器未配指纹:系统 CA


def _load_cfg():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            c = json.load(f)
        if c.get("token"):
            return c
    except Exception:
        pass
    return None


def _save_cfg(server, token, root):
    c = {"server": (server or DEFAULT_SERVER).strip().rstrip("/"),
         "token": token.strip(),
         "root": (root or "").strip() or os.getcwd()}
    fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=1)
    return c


def _http(method, path, body=None, timeout=70):
    cfg = STATE["cfg"] or _load_cfg()
    if not cfg:
        raise RuntimeError("云端未配置(删掉 %s 重跑可重新填)" % CONFIG)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(cfg["server"] + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + cfg["token"])
    with _OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _err_text(e):
    """HTTPError → 服务端的 detail 文案(429 限额/并发等提示直接可见)。"""
    if isinstance(e, urllib.error.HTTPError):
        try:
            d = json.loads(e.read().decode("utf-8", "replace"))
            return d.get("detail") or ("HTTP %s" % e.code)
        except Exception:
            return "HTTP %s" % e.code
    return str(e)




# (provider_id, 显示名, 控制台取 key 的网址)——注册流与 /apikey 共用
PROVIDER_MENU = [
    ("kimi-coding", "Kimi(moonshot)",
     "https://platform.moonshot.cn/console/api-keys"),
    ("bigmodel-anthropic", "GLM(bigmodel)",
     "https://open.bigmodel.cn/usercenter/apikeys"),
    ("zai-coding-cn", "Z.ai(zhipu)",
     "https://z.ai/manage/apikey"),
    ("deepseek", "DeepSeek",
     "https://platform.deepseek.com/api_keys"),
    ("qwen-token-plan-cn", "通义Qwen(阿里百炼)",
     "https://bailian.console.aliyun.com/"),
    ("minimax-cn", "MiniMax",
     "https://platform.minimaxi.com/user-center/basic-information/interface-key"),
]


def _register_flow(server):
    """终端内注册:收集字段 POST /v1/apply,提交后退出等审批(与网页注册页同接口)。"""
    import getpass
    print("  注册新账号(与网页注册页 %s/mdagent/register.html 等效):" % server.rstrip("/"))
    username = input("  用户名(3-16位,小写字母开头): ").strip()
    password = getpass.getpass("  密码(至少8位,不回显): ")
    print("  大模型服务(自带 key,对话消耗它):")
    for i, (_pid, label, _u) in enumerate(PROVIDER_MENU, 1):
        print("    %d) %s" % (i, label))
    pv = input("  选 [1]: ").strip() or "1"
    i = int(pv) - 1 if pv.isdigit() else -1
    provider = PROVIDER_MENU[i][0] if 0 <= i < len(PROVIDER_MENU) \
        else "kimi-coding"
    api_key = getpass.getpass("  API Key(没有可填 8 位以上任意字符,批准后再换): ")
    contact = input("  联系方式(选填,回车跳过): ").strip()
    reason = input("  申请理由(选填,回车跳过): ").strip()
    data = json.dumps({"username": username, "password": password,
                       "provider": provider, "api_key": api_key,
                       "contact": contact, "reason": reason}).encode()
    req = urllib.request.Request(server.rstrip("/") + "/v1/apply",
                                 data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=15) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        print("  已提交:%s" % d.get("msg", ""))
        print("  等管理员批准后,重新运行本程序向导选 1 登录(或 TUI 里 /login)。")
    except Exception as e:
        print("  注册失败:%s(未保存任何配置,可重试)" % _err_text(e))


def _verify_token(server, token):
    """贴 token 时当场向服务器验一次,防贴错/半截存进配置(向导 2 号路径用)。"""
    req = urllib.request.Request(server.rstrip("/") + "/v1/usage")
    req.add_header("Authorization", "Bearer " + token)
    try:
        with _OPENER.open(req, timeout=15) as r:
            json.loads(r.read().decode("utf-8", "replace"))
        return True, ""
    except Exception as e:
        return False, _err_text(e)

def _login(server, username, password):
    """账号密码登录换 token(无 token 的裸 POST,仍走证书 pinning)。"""
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(server.rstrip("/") + "/v1/login",
                                 data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        raise RuntimeError(_err_text(e))


# ---------- 本地文件执行器 ----------
class Jail:
    """目录囚禁:resolve 静态判定 + 打开后 /proc/self/fd 回验(挡 rename TOCTOU)。"""

    def __init__(self, root):
        self.root = Path(root).resolve()

    def resolve(self, rel):
        p = (self.root / rel).resolve()
        try:
            p.relative_to(self.root)
        except ValueError:
            raise PermissionError("路径越出开放目录: %s" % rel)
        return p

    def fd_in_jail(self, fd):
        if not os.path.exists("/proc/self/fd"):
            return True
        try:
            Path(os.path.realpath("/proc/self/fd/%d" % fd)).relative_to(self.root)
            return True
        except ValueError:
            return False


STATE = {
    "cfg": None,
    "jail": None,
    "seen": collections.OrderedDict(),   # op_id 去重(防 requeue 重放)
    "pending": {},                       # op_id -> 待批准写
    "auto": False,                       # 自动审批(写文件免批准条,默认关)
    "lock": threading.Lock(),
    "last_poll": 0.0,
    "extra_readable": set(),             # 上轨 case 目录(只读放行, 越 jail)
    "gate": None,                        # mdrun_gate 探测缓存(None=未探测)
    "policy": "",                        # 本地 mdagent.md 策略(每轮随消息上送)
}


def _read_policy():
    """读开放目录根下的 mdagent.md(同 Claude Code 的 CLAUDE.md):
    每轮作为 policy 字段随消息上送,云端标记为策略注入,不进对话历史。"""
    j = STATE.get("jail")
    if not j:
        return ""
    try:
        p = j.root / "mdagent.md"
        if not p.is_file():
            return ""
        return p.read_text(encoding="utf-8", errors="replace")[:12000]
    except Exception:
        return ""


def _gate_available():
    """本机是否有 MD 编排管线(通用门 sudo 权限 + cloud cases 根)。探测一次缓存。
    注: 须全量 `sudo -n -l` 再 grep——`sudo -l <cmd>` 默认按 runas=root 校验,
    我们的门条目是 (gate_user), 逐条查会误判无权。"""
    if STATE["gate"] is not None:
        return STATE["gate"]
    ok = False
    try:
        r = subprocess.run(["sudo", "-n", "-l"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=10)
        ok = (r.returncode == 0 and MDRUN_GATE in r.stdout
              and os.path.isdir(CLOUD_CASES))
    except Exception:
        ok = False
    STATE["gate"] = ok
    return ok


def _slug(s, default="run"):
    s = re.sub(r"[^\w.\-一-鿿]+", "-", str(s or "")).strip("-.")
    return s[:60] or default


def _extra_resolve(pathstr):
    """越 jail 的只读放行: 绝对路径落在某个上轨 case 目录下才准。
    返回 (path, base_root); 不放行则抛 PermissionError。"""
    p = os.path.realpath(pathstr)
    for root in STATE["extra_readable"]:
        if p == root or p.startswith(root + os.sep):
            return p, root
    raise PermissionError("路径越出开放目录: %s" % pathstr)


def _docx_text(raw):
    """docx(zip)→纯文本: word/document.xml 去标签。只解压只读,不执行任何东西,
    无需 exec 批准。xml 读限 4MB(防 zip 炸弹),产出文本由调用方按 1MB 截。"""
    import html as _html
    import io as _io
    import zipfile as _zipfile
    with _zipfile.ZipFile(_io.BytesIO(raw)) as z:
        with z.open("word/document.xml") as f:
            xml = f.read(4 * 1024 * 1024).decode("utf-8", "replace")
    xml = xml.replace("</w:p>", "\n")
    text = _html.unescape(re.sub(r"<[^>]+>", "", xml))
    return re.sub(r"\n{3,}", "\n\n", text).strip()

def _fd_under(fd, base):
    if not os.path.exists("/proc/self/fd"):
        return True
    try:
        Path(os.path.realpath("/proc/self/fd/%d" % fd)).relative_to(base)
        return True
    except ValueError:
        return False


def _do_op(op):
    oid, name = op.get("id"), op.get("op")
    args = op.get("args") or {}
    with STATE["lock"]:
        if oid in STATE["seen"]:
            return {"op_id": oid, "ok": False, "error": "重复 op,已忽略(防重放)"}
        STATE["seen"][oid] = None
        while len(STATE["seen"]) > 500:
            STATE["seen"].popitem(last=False)
    try:
        jail = STATE["jail"]
        if name == "list":
            try:
                d = jail.resolve(args.get("path") or ".")
            except PermissionError:
                d, _ = _extra_resolve(args.get("path") or ".")
                d = Path(d)
            if not d.is_dir():
                raise FileNotFoundError("目录不存在: %s" % args.get("path"))
            data = {"entries": sorted("%s%s" % (p.name, "/" if p.is_dir() else "")
                                      for p in d.iterdir())[:500]}
        elif name == "read":
            try:
                p = jail.resolve(args.get("path") or "")
                base = jail.root
            except PermissionError:
                ep, base = _extra_resolve(args.get("path") or "")
                p = Path(ep)
            if not p.is_file():
                raise FileNotFoundError("文件不存在: %s" % args.get("path"))
            fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as f:
                if not _fd_under(f.fileno(), base):
                    raise PermissionError("路径越出开放目录(打开后回验)")
                limit = (8 if p.suffix.lower() == ".docx" else 1) * MAX_FILE_BYTES
                raw = f.read(limit + 1)  # 流式截断,不信 st_size
            if p.suffix.lower() == ".docx":
                if len(raw) > 8 * MAX_FILE_BYTES:
                    raise ValueError("docx 超过 8MB,不支持")
                content = _docx_text(raw)[:MAX_FILE_BYTES]
            elif p.suffix.lower() == ".pdf":
                import shutil as _shutil
                pdft = _shutil.which("pdftotext")
                if not pdft:
                    if len(raw) > MAX_FILE_BYTES:
                        raise ValueError("文件超过 1MB,不支持(本机无 pdftotext)")
                    content = raw.decode("utf-8", errors="replace")
                r = subprocess.run([pdft, "-enc", "UTF-8", str(p), "-"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=30)
                content = r.stdout.decode("utf-8", "replace")[:MAX_FILE_BYTES]
            else:
                if len(raw) > MAX_FILE_BYTES:
                    raise ValueError("文件超过 1MB,不支持")
                content = raw.decode("utf-8", errors="replace")
            try:
                disp = str(p.relative_to(jail.root))
            except ValueError:
                disp = str(p)  # 上轨 case 目录(jail 外只读放行)
            data = {"path": disp, "content": content}
        elif name == "glob":
            data = _do_glob(args)
        elif name == "grep":
            data = _do_grep(args)
        elif name == "edit":
            data = _do_edit(oid, args)
        elif name == "mkdir":
            p = jail.resolve(args.get("path") or "")
            p.mkdir(parents=True, exist_ok=True)
            data = {"created": str(p.relative_to(jail.root))}
        elif name == "write":
            data = _do_write(oid, args)
        elif name == "delete":
            data = _do_delete(oid, args)
        elif name == "exec":
            data = _do_exec(oid, args)
        else:
            return {"op_id": oid, "ok": False, "error": "未知操作 " + str(name)}
        return {"op_id": oid, "ok": True, "data": data}
    except Exception as ex:
        return {"op_id": oid, "ok": False, "error": str(ex)}


def _fs_walk(jail, sub):
    """jail 内安全遍历:跳软链与 .mdagent_run,限 2000 文件/5 秒。"""
    t0 = time.time()
    nf = 0
    stack = [str(sub)]
    while stack:
        d = stack.pop()
        try:
            for e in os.scandir(d):
                if time.time() - t0 > 5 or nf > 2000:
                    return
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if e.name == ".mdagent_run":
                        continue
                    stack.append(e.path)
                else:
                    nf += 1
                    yield e.path
        except OSError:
            continue


def _do_glob(args):
    import glob as _glob
    jail = STATE["jail"]
    pat = str(args.get("pattern") or "").strip()
    if not pat:
        raise ValueError("pattern 不能为空")
    sub = jail.resolve(args.get("path") or ".")
    hits = []
    for p in _glob.glob(pat, root_dir=str(sub), recursive=True):
        rp = (sub / p).resolve()
        try:
            rp.relative_to(jail.root)
        except ValueError:
            continue
        hits.append(str(rp.relative_to(jail.root)))
        if len(hits) >= 500:
            break
    return {"matches": sorted(hits), "count": len(hits)}


def _do_grep(args):
    jail = STATE["jail"]
    sub = jail.resolve(args.get("path") or ".")
    try:
        mx = max(1, min(int(args.get("max") or 100), 200))
    except (TypeError, ValueError):
        mx = 100
    rx = re.compile(str(args.get("pattern") or ""))
    out = []
    files = [str(sub)] if sub.is_file() else _fs_walk(jail, sub)
    for fp in files:
        if len(out) >= mx:
            break
        try:
            if os.path.getsize(fp) > 2 * MAX_FILE_BYTES:
                continue
            with open(fp, "rb") as f:
                raw = f.read(2 * MAX_FILE_BYTES + 1)
            if len(raw) > 2 * MAX_FILE_BYTES or b"\0" in raw[:1024]:
                continue
            rel = str(Path(fp).relative_to(jail.root))
            for i, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                if rx.search(line):
                    out.append({"file": rel, "line": i, "text": line[:300]})
                    if len(out) >= mx:
                        break
        except OSError:
            continue
    return {"matches": out, "count": len(out),
            "truncated": len(out) >= mx}


def _do_edit(oid, args):
    """精确改一处:old 须唯一,批准卡带前后对比。对齐 Claude Code Edit 语义。"""
    old, new = args.get("old"), args.get("new")
    if not isinstance(old, str) or not old:
        raise ValueError("old 不能为空")
    if not isinstance(new, str):
        raise ValueError("new 缺失")
    jail = STATE["jail"]
    p = jail.resolve(args.get("path") or "")
    if not p.is_file():
        raise FileNotFoundError("文件不存在: %s" % args.get("path"))
    fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        if not _fd_under(f.fileno(), jail.root):
            raise PermissionError("路径越出开放目录(打开后回验)")
        raw = f.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("文件超过 1MB,不支持")
    content = raw.decode("utf-8", errors="replace")
    n = content.count(old)
    if n == 0:
        raise ValueError("old 在文件中未找到(未做任何修改)")
    if n > 1:
        raise ValueError("old 出现 %d 次,不唯一,拒绝盲改(带更多上下文再试)" % n)
    new_content = content.replace(old, new, 1)
    nb = len(new_content.encode("utf-8"))
    i = content.find(old)
    a = max(0, i - 60)
    preview = ("修改 %s\n- %s\n+ %s" % (
        p, old[:120].replace("\n", "\\n"), new[:120].replace("\n", "\\n")))
    req = {"path": str(p), "bytes": nb, "preview": preview, "kind": "edit",
           "event": threading.Event(), "decision": None, "ts": time.time()}
    if STATE["auto"]:
        req["decision"] = "approve"
        req["event"].set()
    else:
        with STATE["lock"]:
            STATE["pending"][oid] = req
    try:
        req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
        if req["decision"] != "approve":
            raise PermissionError("用户拒绝了这次修改(或 100s 内未批准)")
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if not _fd_under(f.fileno(), jail.root):
                raise PermissionError("路径越出开放目录(打开后回验)")
            f.truncate(0)
            f.write(new_content)
        _sys("已修改: %s" % p)
        return {"edited": str(p.relative_to(jail.root)), "bytes": nb}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


def _do_write(oid, args):
    content = str(args.get("content", ""))
    nb = len(content.encode("utf-8"))
    if nb > MAX_FILE_BYTES:
        raise ValueError("内容超过 1MB,不支持")
    p = STATE["jail"].resolve(args.get("path") or "")
    if len(content) > 300:
        preview = "%s\n……(中间省略 %d 字)……\n%s" % (
            content[:200], len(content) - 300, content[-100:])
    else:
        preview = content
    req = {"path": str(p), "bytes": nb, "preview": preview, "kind": "write",
           "event": threading.Event(), "decision": None, "ts": time.time()}
    if STATE["auto"]:
        req["decision"] = "approve"
        req["event"].set()
    else:
        with STATE["lock"]:
            STATE["pending"][oid] = req
    try:
        req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
        if req["decision"] != "approve":
            raise PermissionError("用户拒绝了这次写入(或 100s 内未批准)")
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o644)  # 回验后再 truncate
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if not STATE["jail"].fd_in_jail(f.fileno()):
                raise PermissionError("路径越出开放目录(打开后回验)")
            f.truncate(0)
            f.write(content)
        _sys("已写入: %s (%d 字节)" % (p, nb))
        return {"written": str(p.relative_to(STATE["jail"].root)), "bytes": nb}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


def _do_delete(oid, args):
    """删除文件/空目录。不可恢复,永远逐笔批准(不吃 /auto 免确认)。"""
    p = STATE["jail"].resolve(args.get("path") or "")
    if not p.exists() and not p.is_symlink():
        raise FileNotFoundError("不存在: %s" % args.get("path"))
    if p.is_dir() and not p.is_symlink():
        if any(p.iterdir()):
            raise ValueError("目录非空,不支持递归删除: %s" % args.get("path"))
        nb, preview = 0, "(空目录)"
    else:
        nb = p.stat().st_size
        preview = "文件 %d 字节" % nb
        if nb and nb <= MAX_FILE_BYTES and p.is_file():
            fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as f:
                if not STATE["jail"].fd_in_jail(f.fileno()):
                    raise PermissionError("路径越出开放目录(打开后回验)")
                head = f.read(200).decode("utf-8", errors="replace")
            preview = "文件 %d 字节,开头:\n%s" % (nb, head)
    req = {"path": str(p), "bytes": nb, "preview": preview, "kind": "delete",
           "event": threading.Event(), "decision": None, "ts": time.time()}
    with STATE["lock"]:
        STATE["pending"][oid] = req
    try:
        req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
        if req["decision"] != "approve":
            raise PermissionError("用户拒绝了这次删除(或 100s 内未批准)")
        if p.is_dir() and not p.is_symlink():
            p.rmdir()
        else:
            p.unlink()
        _sys("已删除: %s" % p)
        return {"deleted": str(p.relative_to(STATE["jail"].root))}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


# MD 引擎命令识别:命令位(行首/;&|/`/$( 后)、嵌套 shell 引号后,以及
# nohup/timeout/env/nice 等包装器之后——只查命令位会被 `nohup lmp …` 绕过。
# 绝不野跑铁律的执行器级硬闸:不带 supervise 的 MD 引擎调用一律拒。
_MD_ENGINE_RE = re.compile(
    r"(?:^|[;&|`]\s*|\$\(\s*[\"']?\s*"
    r"|\b(?:nohup|nice|ionice|setsid|stdbuf|taskset|numactl|timeout|env)"
    r"(?:\s+\S+)*\s+"
    r"|\b(?:bash|zsh|dash|sh)\s+(?:-[a-zA-Z]+\s+)*-c\s+[\"']\s*)"
    r"(?:[^\s;&|]*/)?"
    r"(lmp[\w.-]*|gmx[\w.-]*|mdrun[\w.-]*|mpirun[\w.-]*|mpiexec[\w.-]*"
    r"|namd[\w.-]*|sander[\w.-]*|pmemd[\w.-]*)"
    r"(?:\s|$)")


def _reject_wild_md(cmd):
    """命中引擎且未上轨 → 返回拒绝理由;未命中返回 None。"""
    if _MD_ENGINE_RE.search(cmd):
        return ("绝不野跑:检测到 MD 引擎命令(lmp/gmx/mdrun 等),必须带 "
                "supervise:true 经编排管线上轨发车(重跑/补跑/短测同样);"
                "被拒即停,不要绕道直跑")
    return None


def _reject_wild_md_in_script(cmd):
    """二道闸:bash/sh 跑的 .sh 脚本(含 ./x.sh 直执)读内容扫引擎命令,
    注释行忽略——防把野跑包进脚本绕过命令位检查(只扫一级,够覆盖现实路径)。"""
    cands = set(re.findall(r"\S+\.sh\b", cmd))
    for m in re.finditer(r"(?:^|\s)(?:/bin/)?(?:ba|z)?sh\s+(\S+)", cmd):
        cands.add(m.group(1))
    jail = STATE["jail"]
    for name in cands:
        try:
            p = jail.resolve(name)
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")[:262144]
        except Exception:
            continue
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            why = _reject_wild_md(line)
            if why:
                return ("绝不野跑:脚本 %s 内含 MD 引擎命令;MD 一律 "
                        "supervise:true 上轨发车,不许拆进脚本绕过" % name)
    return None


def _do_exec(oid, args):
    """后台执行 shell 命令(bash,cwd=开放根目录),立即返回,日志进 .mdagent_run/。
    长任务(模拟几小时)撑不住桥 110s 超时,所以一律异步:起进程→返 run_id/日志路径,
    云端之后用 localfs_read 读日志跟进。/auto 开时免批准,否则弹批准卡。
    supervise:true 且本机有 MD 管线时走上轨发车(_do_exec_gate)。"""
    cmd = str(args.get("cmd") or "").strip()
    if not cmd:
        raise ValueError("cmd 不能为空")
    if args.get("supervise"):
        if not _gate_available():
            raise PermissionError(
                "绝不野跑:supervise 上轨需要本机 MD 编排管线(mdrun_gate),"
                "本机不可用,已拒绝直跑(装好管线或换有管线的机器再发)")
        return _do_exec_gate(oid, args, cmd)
    why = _reject_wild_md(cmd) or _reject_wild_md_in_script(cmd)
    if why:
        raise PermissionError(why)
    return _do_exec_direct(oid, args, cmd)


def _do_exec_direct(oid, args, cmd):
    try:
        timeout_s = max(1, min(int(args.get("timeout_s") or 7200), 86400))
    except (TypeError, ValueError):
        timeout_s = 7200
    jail = STATE["jail"]
    (jail.root / ".mdagent_run").mkdir(exist_ok=True)
    log_rel = ".mdagent_run/%s.log" % oid[:12]
    req = {"path": cmd, "bytes": 0,
           "preview": "工作目录: %s\n超时上限: %d 秒\n日志: %s" % (jail.root, timeout_s, log_rel),
           "kind": "exec", "event": threading.Event(), "decision": None,
           "ts": time.time()}
    if STATE["auto"]:
        req["decision"] = "approve"
        req["event"].set()
    else:
        with STATE["lock"]:
            STATE["pending"][oid] = req
    try:
        req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
        if req["decision"] != "approve":
            raise PermissionError("用户拒绝了这次命令执行(或 100s 内未批准)")
        lf = open(jail.root / log_rel, "w", encoding="utf-8")
        lf.write("$ %s\n\n" % cmd)
        lf.flush()
        proc = subprocess.Popen(["/bin/bash", "-c", cmd], cwd=str(jail.root),
                                stdout=lf, stderr=subprocess.STDOUT,
                                start_new_session=True)
        threading.Thread(target=_watch_exec, args=(proc, lf, timeout_s),
                         daemon=True).start()
        _sys("已启动: %s (pid %d,日志 %s)" % (cmd[:60], proc.pid, log_rel))
        return {"run_id": oid[:12], "pid": proc.pid, "log": log_rel,
                "status": "running", "via": "direct"}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


def _do_exec_gate(oid, args, cmd):
    """上轨发车: 从 cmd 解析 lammps -in 输入, 组 req 交 mdrun_gate 以 mdorch
    身份起跑(进看板 + 编排器收养队列)。批准后同步等门结果(门内有 ≤45s
    看护观察窗); 成功后 case 目录动态加入只读放行, 云端可读日志跟进。"""
    m = re.search(r"(?:^|\s)-in\s+(\S+)", cmd)
    if not m:
        raise ValueError("supervise 发车需要 cmd 形如 `lmp -in 输入文件`"
                         "(命令里未找到 -in)")
    jail = STATE["jail"]
    in_path = jail.resolve(m.group(1))
    if not in_path.is_file():
        raise FileNotFoundError("lammps 输入不存在: %s" % m.group(1))
    content = in_path.read_text(encoding="utf-8", errors="replace")
    extra = {}
    refs = re.findall(r"^\s*read_(?:data|restart)\s+(\S+)", content, re.M)
    # pair_coeff 势文件 / molecule 模板(带扩展名的 token)也随行,防发车即 file-not-found
    for ln in content.splitlines():
        if re.match(r"^\s*pair_coeff\b", ln):
            toks = ln.split()[2:]
        elif re.match(r"^\s*molecule\b", ln):
            toks = ln.split()[2:]
        else:
            continue
        for tok in toks:
            if "." in tok and "/" not in tok.strip('"'):
                refs.append(tok.strip('"'))
    for ref in refs:
        try:
            rp = jail.resolve(ref)
        except PermissionError:
            continue
        if rp.is_file():
            extra[os.path.basename(ref)] = rp.read_text(encoding="utf-8",
                                                         errors="replace")
    case_slug = _slug(args.get("case"), "run")
    proj_slug = _slug(jail.root.name, "cloud")
    case_id = "%s-%s" % (case_slug, oid[:8])
    prod_dir = os.path.join(CLOUD_CASES, proj_slug, case_id)
    req = {"path": cmd, "bytes": 0,
           "preview": ("看护发车(上轨):\n算例: %s\n产物目录: %s\n"
                       "输入文件: %s(%d 字节) + %d 个数据文件\n"
                       "批准后由编排管线看护(崩溃自愈/看板)")
           % (case_id, prod_dir, m.group(1), len(content), len(extra)),
           "kind": "exec", "event": threading.Event(), "decision": None,
           "ts": time.time()}
    if STATE["auto"]:
        req["decision"] = "approve"
        req["event"].set()
    else:
        with STATE["lock"]:
            STATE["pending"][oid] = req
    try:
        req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
        if req["decision"] != "approve":
            raise PermissionError("用户拒绝了这次命令执行(或 100s 内未批准)")
        # op id 净化:云端字符串不当文件名成分(复审 P2-7)
        safe_oid = re.sub(r"[^A-Za-z0-9_-]", "x", oid[:12]) or "op"
        req_p = "/tmp/mdrun_req_%s.json" % safe_oid
        res_p = "/tmp/mdrun_res_%s.json" % safe_oid
        with open(req_p, "w", encoding="utf-8") as f:
            json.dump({"prod_dir": prod_dir, "input_content": content,
                       "case_id": case_id, "project": proj_slug,
                       "extra_files": extra}, f, ensure_ascii=False)
        r = subprocess.run(["sudo", "-n", "-u", GATE_USER, MDRUN_GATE,
                            req_p, res_p],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=100)
        try:
            with open(res_p, encoding="utf-8") as f:
                res = json.load(f)
        except Exception:
            raise RuntimeError("门未返回结果(rc=%s): %s"
                               % (r.returncode, (r.stderr or "")[-200:]))
        if not res.get("success"):
            raise RuntimeError("编排门拒绝发车: %s" % res.get("error"))
        real_pd = os.path.realpath(res["prod_dir"])
        STATE["extra_readable"].add(real_pd)
        board = "已进看板(cloud-client)"
        if res.get("adopt_queued"):
            board += ",已排编排器收养队列"
        elif res.get("completed"):
            board += "(算例瞬完,无需看护)"
        _sys("上轨发车: %s → %s" % (case_id, real_pd))
        return {"run_id": oid[:12], "via": "gate",
                "case_id": res["case_id"], "prod_dir": real_pd,
                "pids": res.get("pids", []),
                "completed": bool(res.get("completed")),
                "log": os.path.join(real_pd, res.get("log_file",
                                                     "production.stdout")),
                "board": board, "status": "running"}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


def _watch_exec(proc, lf, timeout_s):
    """盯子进程:正常结束写退出码;超时杀整个进程组(模拟常会 fork 子进程)。"""
    try:
        rc = proc.wait(timeout=timeout_s)
        lf.write("\n[退出码 %d]\n" % rc)
    except subprocess.TimeoutExpired:
        lf.write("\n[超时 %d 秒,已强杀]\n" % timeout_s)
        try:
            os.killpg(proc.pid, 9)
        except Exception:
            pass
        proc.wait()
    except Exception as ex:
        lf.write("\n[监视异常: %s]\n" % ex)
    finally:
        lf.close()


def _bridge_loop():
    while True:
        if not STATE["cfg"]:
            time.sleep(3)
            continue
        try:
            r = _http("GET", "/v1/bridge/poll?wait=50", timeout=60)
            STATE["last_poll"] = time.time()
        except Exception:
            time.sleep(3)
            continue
        op = r.get("op")
        if not op:
            continue
        result = _do_op(op)
        _log_op(op, result)
        try:
            _http("POST", "/v1/bridge/result", result, timeout=15)
        except Exception:
            pass


_OP_ICON = {"list": "📂", "read": "📖", "write": "✏️", "mkdir": "📁",
             "edit": "✎", "glob": "🔍", "grep": "🔎",
            "delete": "🗑", "exec": "⚡"}


def _log_op(op, result):
    """文件操作动态:transcript 里挂 ⏺ 行 + 侧坞 OpsPanel 记一行。"""
    if _APP is None:
        return
    if not result.get("ok"):
        op = dict(op, _err=result.get("error") or "")
    args = op.get("args") or {}
    what = args.get("path") or args.get("cmd") or args.get("pattern") or ""
    line = "%s %s %s %s" % (time.strftime("%H:%M"),
                            _OP_ICON.get(op.get("op") or "?", "•"),
                            op.get("op") or "?", what)
    try:
        _APP.call_from_thread(_APP.add_op, op, line, bool(result.get("ok")))
    except Exception:
        pass


# ---------- TUI(Textual,Claude Code 风格 clean-room 外壳) ----------
# 视觉语言(公开界面行为重写,不含任何 CC 代码):无气泡全宽 transcript,
# 用户消息 ❯ 前缀,文件操作 ⏺ 行,思维链暗色斜体,底部输入框+状态条,
# 目标/文件操作面板收进 Ctrl+G 侧坞(默认隐藏,功能一个不丢)。
_APP = None
_PROJECT = "default"

_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# 欢迎 logo(自有品牌 MD-EXP)
_LOGO = [
    "▐▙   ▟▌ █▀▛▖ ▖",
    "▐▌▘ ▝▐▌ █  █▞ ",
    "▐▌█ █▐▌ █  █  ",
    "▐▌·▀·▐▌ █  █▚ ",
    "▐▌   ▐▌ █▄▜▘ ▘",
    "    ᴱˣᵖ       ",
]


class Banner(Static):
    """启动欢迎:MDᴱˣᵖ 积木 logo + 一句话指引。"""

    def __init__(self, server, root):
        t = Text()
        for line in _LOGO:
            t.append("  " + line + "\n", style="bold #5686FE")
        t.append("  云端 MD 智能体 · 终端工作台\n", style="bold #C9D1E0")
        t.append("  脑子在云端(%s)\n" % server, style="#5F6B7A")
        t.append("  拖选文字 → Ctrl+C 复制 · 想要滚轮: /mouse · /login 登录\n",
                 style="#3A4152")
        t.append("  开放目录 %s · 写/删逐笔批准 · /help 看命令\n" % root,
                 style="#5F6B7A")
        super().__init__(t, classes="banner")


def _sys(msg):
    """桥线程/逻辑层都能调:有 App 走 call_from_thread,没有就 stdout。"""
    if _APP is not None:
        try:
            _APP.call_from_thread(_APP.add_sys, str(msg))
            return
        except Exception:
            pass
    print(msg)


class SysLine(Static):
    def __init__(self, text):
        super().__init__(Text("  " + text, style="italic #5F6B7A"),
                         classes="sys")


class UserLine(Static):
    """用户消息:❯ 琥珀前缀 + 加粗正文,无气泡。"""

    def __init__(self, text):
        t = Text()
        t.append("❯ ", style="bold #D29922")
        t.append(text, style="bold #E6EAF2")
        super().__init__(t, classes="userline")


class OpLine(Static):
    """文件操作动态(⏺ 行):成功暗绿、被拒/失败红。"""

    def __init__(self, op, ok):
        name = op.get("op") or "?"
        path = (op.get("args") or {}).get("path") or ""
        t = Text()
        t.append("  ⏺ ", style="#3FB950" if ok else "#F85149")
        t.append("%s %s" % (_OP_ICON.get(name, "•"), name), style="#97A0B0")
        t.append(" " + path, style="#5F6B7A")
        t.append("  " + time.strftime("%H:%M"), style="#3A4152")
        if not ok:
            t.append("  ✗ " + str(op.get("_err") or "被拒绝/失败"),
                     style="#F85149")
        super().__init__(t, classes="opline")


class ThinkBlock(Static):
    """思维链流:暗色斜体,流式显示尾窗;完成后由 StreamCard 换成可展开面板。"""

    def show(self, text):
        tail = text[-4000:]
        self.update(Text("  ✶ " + tail.replace("\n", " "),
                         style="italic #5F6B7A"))
        self.display = True

    def hide(self):
        self.display = False


class MdBody(Static):
    """智能体 markdown 正文。rich Markdown 渲染对象不含纯文本,
    Static 默认取词拿不到 → 自实现 get_selection(同宽重渲染取字)。"""

    def __init__(self, md_text=""):
        super().__init__("", classes="agentbody")
        self._md = ""
        self.set_md(md_text)

    def set_md(self, md_text):
        self._md = md_text
        self.update(RichMarkdown(md_text))

    def get_selection(self, selection):
        from rich.console import Console
        width = max(10, self.content_region.width or 80)
        con = Console(width=width, force_terminal=False, no_color=True)
        with con.capture() as cap:
            con.print(RichMarkdown(self._md), end="")
        return selection.extract(cap.get()), "\n"


class StreamCard(Vertical):
    """智能体流式块:上=思维链(暗),下=正文 markdown;done 后思维链折叠。"""

    def __init__(self):
        super().__init__(classes="streamcard")
        self.think = ThinkBlock("")
        self.body = MdBody()
        self._thinking_seen = ""

    def on_mount(self):
        self.think.hide()

    def set_thinking(self, text):
        if text != self._thinking_seen:
            self._thinking_seen = text
            self.think.show(text)

    def set_text(self, md_text, streaming):
        self.body.set_md(md_text + (" ▌" if streaming else ""))

    def finish(self, final):
        if self._thinking_seen:
            # 思考全文收进可展开面板(点标题/聚焦后 Enter 展开)
            from textual.widgets import Collapsible
            self.think.hide()
            col = Collapsible(
                Static(Text(self._thinking_seen[-8000:],
                            style="italic #5F6B7A")),
                title="✶ 思考过程(%d 字,点开看全文)" % len(self._thinking_seen),
                collapsed=True)
            self.mount(col, before=self.body)
        else:
            self.think.hide()
        self.body.set_md(final)

    def compose(self):
        yield self.think
        yield self.body


class AgentBody(MdBody):
    """历史回放的智能体消息:全宽 markdown(可框选)。"""


class ApprovalCard(Horizontal):
    """写/删批准卡:y/n 键或按钮;100s 未答云端侧自动拒(桥线程超时)。"""
    pass


# (命令, 参数, 说明) —— / 菜单与 /help 共用的唯一事实源
_COMMANDS = [
    ("/project", "<名>", "换会话项目(上下文独立,自动回放云端历史)"),
    ("/resume", "[序号]", "挑旧项目续做(按最近活跃排序,历史自动回放)"),
    ("/policy", "", "查看/重载本地策略 mdagent.md"),
    ("/archive", "[名]", "归档项目(会话+项目空间收进云端归档区,缺省=当前)"),
    ("/restore", "<名>", "恢复最近一次归档的项目"),
    ("/root", "<目录>", "换开放给智能体的本地目录"),
    ("/auto", "", "写操作免确认开关(默认关,逐笔批准)"),
    ("/goal", "", "目标面板:当前任务子目标展开"),
    ("/apikey", "", "换大模型 API Key(自动打开 Kimi 网页登录复制)"),
    ("/login", "", "账号密码登录(token 自动获取,免粘贴)"),
    ("/mouse", "", "鼠标捕获开关(关=直接框选复制,滚轮点击失效)"),
    ("/status", "", "桥连接状态 + 每小时用量"),
    ("/help", "", "全部命令"),
    ("/quit", "", "退出"),
]


class CommandInput(Input):
    """带 / 命令菜单的输入框:打 / 弹菜单,↑↓ 选,Tab 补全,Esc 关。"""

    BINDINGS = [
        Binding("up", "cmd_up", show=False),
        Binding("down", "cmd_down", show=False),
        Binding("tab", "cmd_tab", show=False),
        Binding("escape", "cmd_esc", show=False),
    ]

    def action_cmd_up(self):
        if getattr(self.app, "_cmd_open", False):
            self.app._cmd_move(-1)

    def action_cmd_down(self):
        if getattr(self.app, "_cmd_open", False):
            self.app._cmd_move(1)

    def action_cmd_tab(self):
        if getattr(self.app, "_cmd_open", False):
            self.app._cmd_complete()
        else:
            self.screen.focus_next()

    def action_cmd_esc(self):
        if getattr(self.app, "_cmd_open", False):
            self.app._close_cmd_menu()
        elif getattr(self.app, "busy", False):
            self.app.action_interrupt()   # ESC = 打断当前任务(Claude Code 同款)


_GOAL_HINT = "当前项目没有进行中的目标\n(多步任务智能体会自动在工作目录建 GOAL.md)"


def _render_goal(content):
    """GOAL.md → 富文本:# 目标:标题行 + - [x]/[>]/[ ] 子目标清单 + 进度条。"""
    title, subs = "", []
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r"^#\s*目标[:：]\s*(.+)$", line)
        if m and not title:
            title = m.group(1).strip()
            continue
        m = re.match(r"^-\s*\[([xX> ])\]\s*(.+)$", line)
        if m:
            subs.append((m.group(1).lower(), m.group(2).strip()))
    t = Text()
    if not title and not subs:
        t.append(content[:400] or "(空)", style="#97A0B0")
        return t
    if title:
        t.append("🎯 " + title + "\n\n", style="bold #EAF0FB")
    if subs:
        done = sum(1 for mk, _ in subs if mk == "x")
        pct = done * 100 // len(subs)
        bar = "▰" * (pct // 10) + "▱" * (10 - pct // 10)
        t.append("%s %d%% (%d/%d)\n\n" % (bar, pct, done, len(subs)),
                 style="#5686FE")
        icon = {"x": ("✅", "#3FB950"), ">": ("🔄", "#D29922"),
                " ": ("⬜", "#5F6B7A")}
        for mk, txt in subs:
            ic, sty = icon.get(mk, icon[" "])
            t.append("%s %s\n" % (ic, txt), style=sty)
    return t


class GoalPanel(Static):
    def __init__(self):
        super().__init__(Text(_GOAL_HINT, style="#5F6B7A"), id="goal")
        self.border_title = "🎯 目标"

    def show(self, content):
        self.update(_render_goal(content))

    def clear(self):
        self.update(Text(_GOAL_HINT, style="#5F6B7A"))


class OpsPanel(Static):
    def __init__(self):
        super().__init__(Text("还没有文件操作", style="#5F6B7A"), id="ops")
        self.border_title = "📁 文件操作"
        self.lines = collections.deque(maxlen=60)

    def add(self, line, ok):
        self.lines.append((line, ok))
        t = Text()
        for ln, ok2 in self.lines:
            t.append(ln + "\n", style="#97A0B0" if ok2 else "#F85149")
        self.update(t)


class StatusBar(Static):
    """底部状态条(Claude Code 式):spinner+活动 · 在线 · 项目 · 目录 · 用量 · 审批。"""

    def render(self):
        online = bool(STATE["cfg"]) and (time.time() - STATE["last_poll"]) < 70
        t = Text()
        app = self.app
        if getattr(app, "busy", False):
            frame = _SPIN[getattr(app, "_spin_i", 0) % len(_SPIN)]
            t.append(" %s " % frame, style="#D29922")
            t.append(app.phase or "思考中…", style="#D29922")
            t.append("  ·  ", style="#3A4152")
        else:
            t.append(" ● ", style="#3FB950" if online else "#F85149")
            t.append("在线" if online else "离线", style="#97A0B0")
            t.append("  ·  ", style="#3A4152")
        t.append("⛁ %s" % _PROJECT, style="#5686FE")
        t.append("  ·  ", style="#3A4152")
        t.append("%s" % (STATE["jail"].root if STATE["jail"] else "?"),
                 style="#5F6B7A")
        u = getattr(app, "usage", None) or {}
        lim = u.get("limit_per_hour") or 0
        t.append("  ·  用量 %s%s" % (u.get("chats_24h", "?"),
                                      "/%s·时" % lim if lim else " ·不限"),
                 style="#5F6B7A")
        gs = getattr(app, "goal_summary", None)
        if gs:
            t.append("  ·  🎯 %d/%d" % gs, style="#5686FE")
        if STATE["auto"]:
            t.append("  ·  ⚠自动审批开", style="#D29922")
        t.append("  ·  Ctrl+G 目标面板", style="#3A4152")
        return t


class MdAgentApp(App):
    TITLE = "mdagent"

    def copy_to_clipboard(self, text: str) -> None:
        """拖选后 Ctrl+C 走这里:老终端不认 OSC52,优先用 xclip 写真剪贴板。"""
        import shutil
        import subprocess
        xclip = shutil.which("xclip")
        if xclip:
            try:
                subprocess.run([xclip, "-selection", "clipboard"],
                               input=text.encode(), timeout=3, check=True)
                self.notify("已复制 %d 字" % len(text))
                return
            except Exception:
                pass
        super().copy_to_clipboard(text)

    CSS = """
    Screen { background: #0F1115; }
    #status { height: 1; background: #161B27; }
    #main { height: 1fr; }
    #chat { padding: 1 2 0 2; }
    .userline { margin-top: 1; }
    .agentbody { margin-bottom: 1; padding-left: 2; }
    .opline { margin-bottom: 0; }
    .sys { padding-left: 0; margin-bottom: 0; }
    .banner { margin: 0 0 1 0; }
    .streamcard { height: auto; margin-bottom: 1; }
    .streamcard ThinkBlock { max-height: 8; padding-left: 0; overflow-y: hidden; }
    #approval-slot { height: auto; }
    #approval {
        border: round #D29922; background: #1A1F2B;
        padding: 0 1; margin: 0 2 0 2; height: auto;
    }
    #approval Static { padding: 0 1; }
    #cmd-menu {
        display: none; height: auto; margin: 0 2;
        padding: 0 1; border: round #3A4152; background: #12151D;
    }
    #composer { height: auto; }
    #side { width: 44; border-left: solid #232A3B; padding: 1 0 0 1; }
    #goal {
        border: round #2E4A8F; height: auto; max-height: 55%;
        padding: 0 1; margin-bottom: 1;
    }
    #ops { border: round #232A3B; height: 1fr; padding: 0 1; }
    Input {
        border: round #3A4152; background: #12151D; color: #E6EAF2;
        margin: 0 2 0 2;
    }
    Input:focus { border: round #D29922; }
    Button { margin: 0 1; min-width: 8; }
    #btn-ok { background: #2E4A8F; }
    #btn-no { background: #3A2028; }
    """
    BINDINGS = [
        Binding("ctrl+c", "copy_or_quit", "复制/退出", priority=True),
        Binding("ctrl+q", "quit_app", "退出", priority=True),
        Binding("ctrl+g", "toggle_side", "目标面板"),
        Binding("y", "approve", show=False),
        Binding("n", "deny", show=False),
    ]

    def action_copy_or_quit(self):
        """有拖选 → 复制进剪贴板;没选 → 退出(沿用终端 Ctrl+C 直觉)。"""
        sel = self.screen.get_selected_text()
        if sel:
            self.copy_to_clipboard(sel)
            self.screen.clear_selection()
        else:
            self.action_quit_app()

    def __init__(self):
        super().__init__()
        self.usage = None
        self.goal_summary = None   # (done, total),状态条 🎯 进度
        self.phase = ""
        self.busy = False
        self._spin_i = 0
        self.confirm = None          # "auto_on" 等输入框确认流程
        self.keywiz = None           # /apikey 两步向导:{"step","provider"}
        self.login = None            # /login 两步:{"step","user"}
        self.resume = None           # /resume 待选:{"items":[…]}
        self._job_id = None          # 当前轮询中的 job(ESC 打断用)
        self.approval = None         # (oid, req)
        self.stream_card = None
        self._goal_mtime = None
        self._cmd_open = False       # / 命令菜单
        self._cmd_matches = []
        self._cmd_idx = 0

    def compose(self) -> ComposeResult:
        with Horizontal(id="main"):
            yield VerticalScroll(id="chat")
            with Vertical(id="side"):
                yield GoalPanel()
                yield OpsPanel()
        yield Vertical(id="approval-slot")
        yield Static(id="cmd-menu")
        yield CommandInput(placeholder="输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · "
                                       "拖选后 Ctrl+C 复制 · Ctrl+G 目标",
                           id="composer")
        yield StatusBar(id="status")

    def on_mount(self):
        global _APP
        _APP = self
        self.query_one("#side").display = False   # Claude Code 式:默认无侧栏
        # 默认关鼠标捕获:开箱即可原生拖选复制(代价滚轮失效,/mouse 可开回)
        try:
            drv = self._driver
            if drv is not None:
                drv._disable_mouse_support()
        except Exception:
            pass
        asyncio.get_event_loop().create_task(self._mount(
            Banner(STATE["cfg"]["server"], str(STATE["jail"].root))))
        self.set_interval(0.3, self._check_pending)
        self.set_interval(0.12, self._spin)
        self.set_interval(2, self._tick)
        self.set_interval(3, self._poll_goal)
        asyncio.get_event_loop().create_task(self._load_history(_PROJECT))
        STATE["policy"] = _read_policy()
        if STATE["policy"]:
            self.add_sys("本地策略已加载: mdagent.md(%d 字,每轮自动附带,"
                         "不进对话历史;/policy 查看)" % len(STATE["policy"]))
        else:
            self.add_sys("提示: 在开放目录放一个 mdagent.md(同 Claude Code 的 "
                         "CLAUDE.md)可固化你的规矩,每轮自动生效。")
        self.query_one("#composer", Input).focus()

    def _spin(self):
        self._spin_i += 1
        if self.busy:
            self.query_one("#status", StatusBar).refresh()

    def action_toggle_side(self):
        side = self.query_one("#side")
        side.display = not side.display
        self.query_one("#composer", Input).focus()

    def add_op(self, op, line, ok):
        self.query_one("#ops", OpsPanel).add(line, ok)
        asyncio.get_event_loop().create_task(self._mount(OpLine(op, ok)))

    async def _poll_goal(self):
        loop = asyncio.get_event_loop()
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/goal?project="
                + urllib.parse.quote(_PROJECT, safe=""), None, 10))
        except Exception:
            return
        panel = self.query_one("#goal", GoalPanel)
        if d.get("exists"):
            content = d.get("content") or ""
            subs = re.findall(r"^-\s*\[([xX> ])\]", content, re.M)
            done = sum(1 for m in subs if m.lower() == "x")
            self.goal_summary = (done, len(subs)) if subs else None
            if d.get("mtime") != self._goal_mtime:
                self._goal_mtime = d.get("mtime")
                panel.show(content)
        else:
            self.goal_summary = None
            if self._goal_mtime is not None:
                self._goal_mtime = None
                panel.clear()

    # ---- 消息挂载 ----
    async def _mount(self, widget):
        chat = self.query_one("#chat", VerticalScroll)
        await chat.mount(widget)
        chat.scroll_end(animate=False)

    def add_sys(self, msg):
        asyncio.get_event_loop().create_task(self._mount(SysLine(msg)))

    def add_user(self, text):
        asyncio.get_event_loop().create_task(self._mount(UserLine(text)))

    def add_agent(self, md_text):
        asyncio.get_event_loop().create_task(
            self._mount(AgentBody(md_text)))

    # ---- / 命令菜单 ----
    def on_input_changed(self, event: Input.Changed):
        v = event.value.strip()
        # 空格判断用原始值:Tab 补全出的 "/project " 带尾空格,不应再开菜单
        if v.startswith("/") and " " not in event.value:
            ms = [c for c in _COMMANDS if c[0].startswith(v.lower())]
            if ms:
                if not self._cmd_open or ms != self._cmd_matches:
                    self._cmd_idx = 0
                self._cmd_matches = ms
                self._cmd_open = True
                self._render_cmd_menu()
                return
        self._close_cmd_menu()

    def _render_cmd_menu(self):
        t = Text()
        for i, (cmd, arg, desc) in enumerate(self._cmd_matches):
            sel = i == self._cmd_idx
            t.append(" ▶ " if sel else "   ",
                     style="#D29922" if sel else "#3A4152")
            t.append(cmd, style="bold #E6EAF2" if sel else "#97A0B0")
            if arg:
                t.append(" " + arg, style="#5686FE" if sel else "#3A4152")
            t.append("  " + desc + "\n",
                     style="#C9D1E0" if sel else "#5F6B7A")
        try:
            menu = self.query_one("#cmd-menu", Static)
        except Exception:
            return   # 卸载中(退出/切屏)迟到的 Changed,丢弃
        menu.update(t)
        menu.display = True

    def _close_cmd_menu(self):
        self._cmd_open = False
        try:
            self.query_one("#cmd-menu", Static).display = False
        except Exception:
            pass

    def _cmd_move(self, delta):
        if self._cmd_matches:
            self._cmd_idx = (self._cmd_idx + delta) % len(self._cmd_matches)
            self._render_cmd_menu()

    def _cmd_complete(self):
        if not self._cmd_matches:
            return
        cmd, arg, _ = self._cmd_matches[self._cmd_idx]
        inp = self.query_one("#composer", Input)
        inp.value = cmd + (" " if arg else "")
        inp.action_end()
        if not arg:
            self._close_cmd_menu()   # 无参命令补全即完整,再按 Enter 执行

    # ---- 输入路由 ----
    def on_input_submitted(self, event: Input.Submitted):
        text = event.value.strip()
        event.input.value = ""
        if self._cmd_open and " " not in text:
            exact = [c for c in self._cmd_matches
                     if c[0] == text.lower() and not c[1]]
            if exact:
                self._close_cmd_menu()   # 完整无参命令:直接执行(落到下面路由)
            else:
                self._cmd_complete()     # 片段:回车=补全选中项
                event.input.value = self._cmd_matches[self._cmd_idx][0] + \
                    (" " if self._cmd_matches[self._cmd_idx][1] else "")
                event.input.action_end()
                return
        if self.approval is not None:
            # 有批准卡挂着:输入框输入也算数(输入 y/n)
            self._resolve_approval(text.lower() in ("y", "yes"))
            return
        if self.confirm:
            self._resolve_confirm(text)
            return
        if self.login:
            self._login_step(text)
            return
        if self.keywiz:
            self._keywiz_step(text)
            return
        if self.resume:
            self._resume_step(text)
            return
        if not text:
            return
        if text.startswith("/"):
            self._command(text)
            return
        if self.busy:
            self.add_sys("上一个任务还在跑,等它完成…")
            return
        self.add_user(text)
        asyncio.get_event_loop().create_task(self._send(text))

    # ---- 对话 ----
    async def _send(self, text):
        loop = asyncio.get_event_loop()
        self.busy = True
        self.phase = "提交中…"
        card = StreamCard()
        await self._mount(card)
        card.set_text("…", streaming=True)
        self.stream_card = card
        try:
            r = await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/chat",
                {"project": _PROJECT, "message": text,
                 "policy": STATE.get("policy") or ""}, 20))
        except Exception as e:
            self._stream_end()
            self.add_sys("提交失败: %s" % _err_text(e))
            return
        jid = r.get("job_id")
        self._job_id = jid
        if not jid:
            self._stream_end()
            self.add_sys("提交失败: %s" % r)
            return
        while True:
            await asyncio.sleep(1.0)
            try:
                j = await loop.run_in_executor(None, functools.partial(
                    _http, "GET", "/v1/jobs/" + jid, None, 15))
            except Exception as e:
                self._stream_end()
                self.add_sys("查询失败: %s" % _err_text(e))
                return
            st = j.get("status")
            if st == "done":
                reply = j.get("reply") or "(空回复)"
                self._stream_end(reply)
                return
            if st == "error":
                self._stream_end()
                self.add_sys("云端出错: %s" % (j.get("error") or "?"))
                return
            if self.stream_card is not None:
                thinking = j.get("thinking") or ""
                if thinking:
                    self.stream_card.set_thinking(thinking)
                partial = j.get("partial") or ""
                if partial:
                    self.stream_card.set_text(partial, streaming=True)
                if thinking or partial:
                    self.query_one("#chat", VerticalScroll).scroll_end(
                        animate=False)
            self.phase = j.get("activity") or "思考中(%s)…" % st

    def _stream_end(self, final=None):
        if self.stream_card is not None:
            try:
                if final is not None:
                    self.stream_card.finish(final)
                else:
                    self.stream_card.remove()
            except Exception:
                pass
            self.stream_card = None
        self.phase = ""
        self.busy = False
        self._job_id = None

    async def _load_history(self, project):
        loop = asyncio.get_event_loop()
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _http, "GET",
                "/v1/conversations/" + urllib.parse.quote(project, safe="")
                + "?turns=50", None, 15))
        except Exception as e:
            self.add_sys("历史回放失败: %s" % _err_text(e))
            return
        turns = d.get("turns") or []
        if turns:
            self.add_sys("—— 项目「%s」云端历史 %d 条 ——" % (project, len(turns)))
            for t in turns:
                if t.get("role") == "user":
                    self.add_user(t.get("text", ""))
                elif t.get("role") == "assistant":
                    self.add_agent(t.get("text", ""))
        else:
            self.add_sys("项目「%s」还没有历史。对话/记忆/进化都在云端你的独立空间;"
                         "本地文件写入逐笔批准。" % project)

    # ---- 命令 ----
    def _command(self, line):
        global _PROJECT
        parts = line[1:].split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("quit", "exit", "q"):
            self.exit()
        elif cmd == "root":
            if not arg:
                self.add_sys("用法: /root <目录>")
                return
            try:
                j = Jail(arg)
            except Exception as e:
                self.add_sys("切换失败: %s" % e)
                return
            STATE["jail"] = j
            cfg = STATE["cfg"]
            if cfg:
                _save_cfg(cfg["server"], cfg["token"], str(j.root))
                cfg["root"] = str(j.root)
            self.add_sys("开放目录已切换: %s" % j.root)
            STATE["policy"] = _read_policy()
            self.add_sys("本地策略 mdagent.md: %s" % (
                "已加载 %d 字" % len(STATE["policy"]) if STATE["policy"]
                else "此目录没有(放一个即可自动生效)"))
            if j.root.parent == j.root or j.root == Path.home():
                self.add_sys("!! 警告: 开放的是整盘/家目录,其中文件可被远程读取,"
                             "写入仍需逐笔批准;建议只开放项目目录")
        elif cmd == "project":
            if not arg:
                self.add_sys("用法: /project <名>")
                return
            _PROJECT = arg
            self.add_sys("会话项目: %s(上下文独立),回放云端历史…" % arg)
            asyncio.get_event_loop().create_task(self._load_history(arg))
        elif cmd == "archive":
            target = arg or _PROJECT
            asyncio.get_event_loop().create_task(self._archive_cmd(target))
        elif cmd == "restore":
            if not arg:
                self.add_sys("用法: /restore <项目名>")
                return
            asyncio.get_event_loop().create_task(self._restore_cmd(arg))
        elif cmd == "auto":
            if STATE["auto"]:
                STATE["auto"] = False
                self.add_sys("写操作免确认: 关")
            else:
                self.confirm = "auto_on"
                self.add_sys("开启后写文件不再逐笔询问(仍限开放目录内)。"
                             "确认请在输入框输入 yes,其它取消")
        elif cmd == "resume":
            asyncio.get_event_loop().create_task(self._resume_cmd(arg))
        elif cmd == "policy":
            STATE["policy"] = _read_policy()
            if STATE["policy"]:
                self.add_sys("mdagent.md(%s)共 %d 字,每轮自动附带。前 600 字:\n%s"
                             % (STATE["jail"].root / "mdagent.md",
                                len(STATE["policy"]), STATE["policy"][:600]))
            else:
                self.add_sys("开放目录没有 mdagent.md,建一个即自动生效: %s"
                             % (STATE["jail"].root / "mdagent.md"))
        elif cmd == "login":
            self.login = {"step": "user"}
            inp = self.query_one("#composer", Input)
            inp.password = False
            inp.placeholder = "用户名(直接回车取消 /login)"
            self.add_sys("登录:输入用户名(直接回车取消)")
        elif cmd == "apikey":
            self.add_sys("换大模型 API Key:选服务(回车 = 1 Kimi),"
                         "选中后自动在浏览器打开它的控制台:")
            for i, (_pid, label, _u) in enumerate(PROVIDER_MENU, 1):
                self.add_sys("  %d) %s" % (i, label))
            self.keywiz = {"step": "provider"}
        elif cmd == "mouse":
            try:
                drv = self._driver
                if drv is not None and getattr(drv, "_mouse", False):
                    drv._disable_mouse_support()
                    self.add_sys("鼠标捕获: 关 —— 直接框选 + Ctrl+Shift+C 复制;"
                                 "滚轮/点击失效。再敲 /mouse 开回")
                elif drv is not None:
                    drv._enable_mouse_support()
                    self.add_sys("鼠标捕获: 开 —— 点击/滚轮恢复;"
                                 "复制用 Shift+框选")
            except Exception as e:
                self.add_sys("鼠标切换失败: %s" % e)
        elif cmd == "status":
            asyncio.get_event_loop().create_task(self._status_cmd())
        elif cmd == "goal":
            # 任务/目标查看:侧坞打开 + 当前目标印进 transcript
            self.query_one("#side").display = True
            asyncio.get_event_loop().create_task(self._goal_cmd())
        elif cmd in ("help", "h", "?"):
            self.add_sys("命令: " + " │ ".join(
                c + (" " + a if a else "") + " " + d
                for c, a, d in _COMMANDS) + " │ 打 / 弹菜单")
        else:
            self.add_sys("未知命令 %s;/help 看全部" % cmd)

    async def _archive_cmd(self, project):
        loop = asyncio.get_event_loop()
        try:
            r = await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/conversations/%s/archive"
                % urllib.parse.quote(project, safe=""), None, 15))
            self.add_sys("已归档 %s(ts %s,含 %s);/restore %s 可恢复"
                         % (project, r.get("archived_ts"),
                            "+".join(r.get("moved") or []), project))
        except Exception as e:
            self.add_sys("归档失败: %s" % _err_text(e))

    async def _restore_cmd(self, project):
        loop = asyncio.get_event_loop()
        try:
            r = await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/conversations/%s/restore"
                % urllib.parse.quote(project, safe=""), None, 15))
            self.add_sys("已恢复 %s(%s)" % (project,
                                            "+".join(r.get("restored") or [])))
        except Exception as e:
            self.add_sys("恢复失败: %s" % _err_text(e))

    async def _goal_cmd(self):
        loop = asyncio.get_event_loop()
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/goal?project="
                + urllib.parse.quote(_PROJECT, safe=""), None, 10))
        except Exception as e:
            self.add_sys("目标查询失败: %s" % _err_text(e))
            return
        if d.get("exists"):
            asyncio.get_event_loop().create_task(
                self._mount(Static(_render_goal(d.get("content") or ""),
                                   classes="agentbody")))
        else:
            self.add_sys(_GOAL_HINT.split("\n")[0])

    async def _status_cmd(self):
        loop = asyncio.get_event_loop()
        try:
            s = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/bridge/status", None, 10))
            u = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/usage", None, 10))
            self.usage = u
            lim = u.get("limit_per_hour") or 0
            self.add_sys("桥在线: %s │ 用量: %s %s │ 服务器: %s" % (
                s.get("online"), u.get("chats_24h"),
                "/%s 每小时" % lim if lim else "(不限量)",
                (STATE["cfg"] or {}).get("server")))
        except Exception as e:
            self.add_sys("状态查询失败: %s" % _err_text(e))

    def _resolve_confirm(self, text):
        what = self.confirm
        self.confirm = None
        if what == "auto_on":
            STATE["auto"] = text.strip().lower() == "yes"
            self.add_sys("写操作免确认: %s"
                         % ("开(谨慎!)" if STATE["auto"] else "关"))

    # ---- /login 两步登录 ----
    def _login_step(self, text):
        st = self.login
        inp = self.query_one("#composer", Input)
        if st["step"] == "user":
            if not text.strip():
                self._login_cancel()
                return
            st["user"] = text.strip()
            st["step"] = "pwd"
            inp.password = True
            inp.placeholder = "密码(不回显),回车登录"
            self.add_sys("密码(输入不回显),回车登录;直接回车取消")
            return
        self.login = None
        inp.password = False
        inp.placeholder = "输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · 拖选后 Ctrl+C 复制 · Ctrl+G 目标"
        if not text:
            self.add_sys("已取消")
            return
        asyncio.get_event_loop().create_task(self._login_do(st["user"], text))

    async def _resume_cmd(self, arg):
        loop = asyncio.get_event_loop()
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/conversations", None, 15))
        except Exception as e:
            self.add_sys("取项目列表失败: %s" % _err_text(e))
            return
        items = d.get("detail") or []
        if not items:
            self.add_sys("云端还没有你的项目,直接开聊即可;新项目用 /project <名>")
            return
        if arg:
            self._resume_pick(arg, items)
            return
        self.add_sys("—— 你的项目(按最近活跃) ——")
        for i, it in enumerate(items[:20], 1):
            ts = time.strftime("%m-%d %H:%M",
                               time.localtime(it.get("mtime") or 0))
            self.add_sys("%2d. %-28s 最后活跃 %s" % (i, it.get("name"), ts))
        self.resume = {"items": items[:20]}
        self.add_sys("输序号续做对应项目(也可输项目名;直接回车取消)")

    def _resume_pick(self, text, items):
        global _PROJECT
        name = ""
        if isinstance(text, str) and text.isdigit():
            i = int(text) - 1
            if 0 <= i < len(items):
                name = items[i].get("name") or ""
        if not name:
            name = text if any(it.get("name") == text for it in items) else ""
        if not name:
            self.add_sys("没选到「%s」对应的项目,再试 /resume" % text)
            return
        _PROJECT = name
        self.add_sys("已续上项目「%s」,回放云端历史…" % name)
        asyncio.get_event_loop().create_task(self._load_history(name))

    def _resume_step(self, text):
        items = (self.resume or {}).get("items") or []
        self.resume = None
        if not text:
            self.add_sys("已取消 /resume")
            return
        self._resume_pick(text, items)

    def _login_cancel(self):
        self.login = None
        inp = self.query_one("#composer", Input)
        inp.password = False
        inp.placeholder = "输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · 拖选后 Ctrl+C 复制 · Ctrl+G 目标"
        self.add_sys("已取消 /login")

    async def _login_do(self, user, pwd):
        loop = asyncio.get_event_loop()
        server = (STATE["cfg"] or {}).get("server") or DEFAULT_SERVER
        self.add_sys("登录中(输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · 拖选后 Ctrl+C 复制 · Ctrl+G 目标 @ 输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · 拖选后 Ctrl+C 复制 · Ctrl+G 目标)…" % (user, server))
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _login, server, user, pwd))
        except Exception as e:
            self.add_sys("登录失败: 输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · 拖选后 Ctrl+C 复制 · Ctrl+G 目标" % e)
            return
        root = str(STATE["jail"].root) if STATE["jail"] else os.getcwd()
        STATE["cfg"] = _save_cfg(server, d["token"], root)
        self.add_sys("登录成功: 输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · 拖选后 Ctrl+C 复制 · Ctrl+G 目标(token 已存本机,旧 token 作废)"
                     % d.get("username", user))

    # ---- /apikey 两步向导 ----
    def _keywiz_step(self, text):
        wiz = self.keywiz
        inp = self.query_one("#composer", Input)
        if wiz["step"] == "provider":
            sel = text.strip()
            i = int(sel) - 1 if sel.isdigit() else -2
            if 0 <= i < len(PROVIDER_MENU):
                pid, _label, url = PROVIDER_MENU[i]
            else:
                pid = sel or "kimi-coding"
                url = dict((m[0], m[2]) for m in PROVIDER_MENU).get(pid, "")
            if url:
                self.add_sys("正在浏览器打开控制台(%s),登录后复制 API key "
                             "回来粘贴;没打开就手动访问: %s" % (pid, url))
                threading.Thread(target=lambda: webbrowser.open(url),
                                 daemon=True).start()
            else:
                self.add_sys("provider=%s(无已知控制台网址,直接贴 key)" % pid)
            wiz["provider"] = pid
            wiz["step"] = "key"
            inp.password = True      # key 不回显
            inp.placeholder = "粘贴 sk- 开头的 API Key(不回显),回车提交"
            self.add_sys("第 2 步:粘贴 API Key(输入不回显),回车提交;"
                         "直接回车取消")
            return
        self.keywiz = None
        inp.password = False
        inp.placeholder = ("输入消息 · / 命令菜单 · 粘贴 Ctrl+Shift+V · "
                           "拖选后 Ctrl+C 复制 · Ctrl+G 目标")
        key = text.strip()
        if not key:
            self.add_sys("已取消")
            return
        asyncio.get_event_loop().create_task(
            self._apikey_save(wiz["provider"], key))

    async def _apikey_save(self, provider, key):
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/me/apikey",
                {"provider": provider, "api_key": key}, 15))
            self.add_sys("API Key 已更新(provider=%s),云端三处同步生效"
                         % provider)
        except Exception as e:
            self.add_sys("API Key 更新失败: %s" % _err_text(e))

    # ---- 写批准 ----
    def _check_pending(self):
        if self.approval is not None or self.query("#approval"):
            # 卡片已挂(含 resolve 后 widget 异步拆除的空窗),不重复挂载
            return
        with STATE["lock"]:
            # decision 已定的(消费者还没弹出)不再重复弹卡
            item = next((kv for kv in STATE["pending"].items()
                         if kv[1].get("decision") is None), None)
        if not item:
            return
        self.approval = item
        _, req = item
        if req.get("kind") == "delete":
            head = "⚠ 云端智能体请求删除(不可恢复): %s" % req["path"]
            title = "删除批准 · 100s 未答自动拒绝"
        elif req.get("kind") == "exec":
            head = "⚠ 云端智能体请求执行命令: %s" % req["path"]
            title = "命令批准 · 100s 未答自动拒绝"
        else:
            head = "⚠ 云端智能体请求写入: %s (%d 字节)" % (req["path"],
                                                         req["bytes"])
            title = "写批准 · 100s 未答自动拒绝"
        card = ApprovalCard(
            Static(Text(head, style="bold #E6B450")),
            Static(Text("\n".join("  " + l for l in
                                  str(req["preview"]).split("\n")[:6]),
                        style="#C9D1E0")),
            Horizontal(Button("批准 (y)", id="btn-ok", compact=True),
                       Button("拒绝 (n)", id="btn-no", compact=True)),
            id="approval")
        card.border_title = title
        self.query_one("#approval-slot").mount(card)

    def _resolve_approval(self, ok):
        ap = self.approval
        self.approval = None
        if not ap:
            return
        _, req = ap
        req["decision"] = "approve" if ok else "deny"
        req["event"].set()
        for w in self.query("#approval"):
            w.remove()
        self.add_sys("已%s: %s" % ("批准" if ok else "拒绝", req["path"]))
        self.query_one("#composer", Input).focus()

    def action_approve(self):
        if self.approval is not None and not isinstance(self.focused, Input):
            self._resolve_approval(True)

    def action_deny(self):
        if self.approval is not None and not isinstance(self.focused, Input):
            self._resolve_approval(False)

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-ok":
            self._resolve_approval(True)
        elif event.button.id == "btn-no":
            self._resolve_approval(False)

    def action_interrupt(self):
        """ESC 打断:向云端发取消信号;本地继续跟随,收尾文案由服务端回。"""
        if not self.busy or not self._job_id:
            return
        jid = self._job_id
        self.add_sys("⏹ 正在打断…")

        async def _c():
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, functools.partial(
                        _http, "POST", "/v1/jobs/%s/cancel" % jid, None, 15))
            except Exception as e:
                self.add_sys("打断请求失败: %s" % _err_text(e))
        asyncio.get_event_loop().create_task(_c())

    def action_quit_app(self):
        self.exit()

    # ---- 状态条 ----
    async def _tick(self):
        n = getattr(self, "_tick_n", 0) + 1
        self._tick_n = n
        if STATE["cfg"] and n % 15 == 1:
            loop = asyncio.get_event_loop()
            try:
                self.usage = await loop.run_in_executor(
                    None, functools.partial(_http, "GET", "/v1/usage", None, 10))
            except Exception:
                pass
        self.query_one("#status", StatusBar).refresh()


def main():
    global _PROJECT
    ap = argparse.ArgumentParser(description="mdagent TUI 客户端(终端里的云端智能体)")
    ap.add_argument("--server", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--root", default=None)
    ap.add_argument("--project", "-p", default=None,
                    help="直接指定会话项目")
    ap.add_argument("--resume", action="store_true",
                    help="启动时挑旧项目续做(列出按最近活跃排序)")
    ap.add_argument("-c", "--continue", dest="cont", action="store_true",
                    help="直接续做最近的项目")
    args = ap.parse_args()

    cfg = _load_cfg() or {}
    if args.token or args.server or args.root:
        cfg = _save_cfg(args.server or cfg.get("server") or DEFAULT_SERVER,
                        args.token or cfg.get("token") or "",
                        args.root or cfg.get("root") or "")
    if args.token:
        ok, msg = _verify_token(cfg["server"], cfg["token"])
        if not ok:
            sys.exit("token 校验失败(%s),未保存" % msg)
    if not cfg.get("token"):
        # 首次配置:进全屏前用普通 input 问完(免得在 TUI 里做表单)。
        # EOF 兜底:curl|sh 管道跑时 stdin 是管道,input 立即 EOF——指路直跑
        try:
            print("首次配置(只问一次,存 %s,权限 600):" % CONFIG)
            server = input("  服务器 [%s]: " % DEFAULT_SERVER).strip() or DEFAULT_SERVER
            preset_token = ""
            if server.startswith("mda_"):
                preset_token = server
                server = DEFAULT_SERVER
                print("  (检测到你贴的是 token:已当 token 用,服务器取默认 %s)" % server)
            if not server.startswith(("http://", "https://")):
                sys.exit("服务器地址须 http(s):// 开头(收到 %r),未保存配置"
                         % server[:40])
            print("  1) 账号密码登录(推荐,审批通过后即可用)")
            print("  2) 直接贴 token(mda_ 开头,管理员发的)")
            print("  3) 注册新账号(提交申请,等管理员批准)")
            choice = input("  选 [1]: ").strip() or "1"
            token = ""
            if choice == "3":
                _register_flow(server)
                return
            if choice == "1":
                import getpass
                user = input("  用户名: ").strip()
                pwd = getpass.getpass("  密码: ")
                try:
                    d = _login(server, user, pwd)
                    token = d["token"]
                    print("  登录成功(token 已自动获取)")
                except Exception as ex:
                    sys.exit("登录失败: %s" % ex)
            else:
                token = preset_token or input("  token: ").strip()
                ok, msg = _verify_token(server, token)
                if not ok:
                    sys.exit("token 校验失败(%s)——未保存配置,重跑再贴一次" % msg)
                print("  token 校验通过")
            root = input("  开放给智能体的目录 [%s]: " % os.getcwd()).strip() or os.getcwd()
            if not token.startswith("mda_"):
                sys.exit("token 格式不对(mda_ 开头)")
            cfg = _save_cfg(server, token, root)
        except EOFError:
            sys.exit("\n[!] 没有可用的交互输入(命令可能经管道运行,如 curl … | sh)。\n"
                     "    请进入解压后的目录直接运行: python3 client/mdagent_tui.py")
    STATE["cfg"] = cfg
    STATE["jail"] = Jail(cfg.get("root") or os.getcwd())
    if STATE["jail"].root.parent == STATE["jail"].root or \
            STATE["jail"].root == Path.home():
        print("!! 警告: 开放的是整盘/家目录,其中文件可被远程读取;"
              "建议只开放项目目录(可用 /root 换)")

    if args.project:
        _PROJECT = args.project
        print("会话项目: %s(启动后自动回放云端历史)" % _PROJECT)
    if args.resume or args.cont:
        try:
            d = _http("GET", "/v1/conversations", None, 15)
            items = d.get("detail") or []
            if not items:
                print("云端还没有你的项目,直接开聊即可")
            elif args.cont:
                _PROJECT = items[0]["name"]
                print("续做最近项目「%s」" % _PROJECT)
            else:
                print("你的项目(按最近活跃排序):")
                for i, it in enumerate(items[:20], 1):
                    print("  %2d. %-28s 最后活跃 %s"
                          % (i, it.get("name"),
                             time.strftime("%m-%d %H:%M",
                                           time.localtime(it.get("mtime") or 0))))
                sel = input("续做哪个 [1]: ").strip() or "1"
                i = int(sel) - 1 if sel.isdigit() else -1
                if not (0 <= i < len(items[:20])):
                    sys.exit("序号无效")
                _PROJECT = items[i]["name"]
                print("已选「%s」(启动后自动回放云端历史)" % _PROJECT)
        except EOFError:
            sys.exit("\n[!] 无交互输入(管道运行),请改用 --project <名>")
        except Exception as e:
            print("(取项目列表失败: %s,沿用默认项目)" % _err_text(e))
    threading.Thread(target=_bridge_loop, daemon=True).start()
    try:
        MdAgentApp().run()
    except KeyboardInterrupt:
        pass
    print("已断开,再见。")


if __name__ == "__main__":
    main()
