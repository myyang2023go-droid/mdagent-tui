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
    sys.stderr.write("Missing dependency textual; install it: pip3 install --user textual\n"
                     "(or use the zero-dep REPL version mdagent_client.py)\n")
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
            raise ssl.SSLError("Server cert fingerprint MISMATCH (possible MITM)! got %s…" % fp[:23])


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
        raise RuntimeError("Cloud not configured (delete %s and rerun to set up)" % CONFIG)
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
    ("qwen-token-plan-cn", "Qwen Tongyi (Aliyun Bailian)",
     "https://bailian.console.aliyun.com/"),
    ("minimax-cn", "MiniMax",
     "https://platform.minimaxi.com/user-center/basic-information/interface-key"),
]


def _register_flow(server):
    """终端内注册:收集字段 POST /v1/apply,提交后退出等审批(与网页注册页同接口)。"""
    import getpass
    print("  Register a new account (same as %s/mdagent/register.html):" % server.rstrip("/"))
    username = input("  Username (3-16 chars, lowercase first): ").strip()
    password = getpass.getpass("  Password (min 8 chars, hidden): ")
    print("  LLM provider (bring your own key):")
    for i, (_pid, label, _u) in enumerate(PROVIDER_MENU, 1):
        print("    %d) %s" % (i, label))
    pv = input("  Select [1]: ").strip() or "1"
    i = int(pv) - 1 if pv.isdigit() else -1
    provider = PROVIDER_MENU[i][0] if 0 <= i < len(PROVIDER_MENU) \
        else "kimi-coding"
    api_key = getpass.getpass("  API key (any 8+ chars if you don't have one yet): ")
    contact = input("  Contact (optional, Enter to skip): ").strip()
    reason = input("  Reason (optional, Enter to skip): ").strip()
    data = json.dumps({"username": username, "password": password,
                       "provider": provider, "api_key": api_key,
                       "contact": contact, "reason": reason}).encode()
    req = urllib.request.Request(server.rstrip("/") + "/v1/apply",
                                 data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=15) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        print("  Submitted: %s" % d.get("msg", ""))
        print("  After admin approval, rerun and pick 1 to login (or /login in TUI).")
    except Exception as e:
        print("  Register failed: %s (nothing saved, you can retry)" % _err_text(e))


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
            raise PermissionError("Path escapes the open dir: %s" % rel)
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


def _alt_scroll(on):
    """xterm 备用屏滚轮模式(DECSET 1007):鼠标捕获关着时,终端把滚轮
    转成 ↑↓ 键发给程序——原生框选复制保留的同时滚轮可用。"""
    seq = "\x1b[?1007h" if on else "\x1b[?1007l"
    try:
        if _APP is not None and getattr(_APP, "_driver", None) is not None:
            _APP._driver.write(seq)
        else:
            sys.stdout.write(seq)
            sys.stdout.flush()
    except Exception:
        pass


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
    raise PermissionError("Path escapes the open dir: %s" % pathstr)


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
            return {"op_id": oid, "ok": False, "error": "duplicate op, ignored (anti-replay)"}
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
                raise FileNotFoundError("dir not found: %s" % args.get("path"))
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
                raise FileNotFoundError("file not found: %s" % args.get("path"))
            fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as f:
                if not _fd_under(f.fileno(), base):
                    raise PermissionError("path escapes open dir (post-open check)")
                limit = (8 if p.suffix.lower() == ".docx" else 1) * MAX_FILE_BYTES
                raw = f.read(limit + 1)  # 流式截断,不信 st_size
            if p.suffix.lower() == ".docx":
                if len(raw) > 8 * MAX_FILE_BYTES:
                    raise ValueError("docx over 8MB unsupported")
                content = _docx_text(raw)[:MAX_FILE_BYTES]
            elif p.suffix.lower() == ".pdf":
                import shutil as _shutil
                pdft = _shutil.which("pdftotext")
                if not pdft:
                    if len(raw) > MAX_FILE_BYTES:
                        raise ValueError("file over 1MB unsupported (no local pdftotext)")
                    content = raw.decode("utf-8", errors="replace")
                r = subprocess.run([pdft, "-enc", "UTF-8", str(p), "-"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=30)
                content = r.stdout.decode("utf-8", "replace")[:MAX_FILE_BYTES]
            else:
                if len(raw) > MAX_FILE_BYTES:
                    raise ValueError("file over 1MB unsupported")
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
            return {"op_id": oid, "ok": False, "error": "unknown op " + str(name)}
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
        raise ValueError("pattern must not be empty")
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
        raise ValueError("old must not be empty")
    if not isinstance(new, str):
        raise ValueError("new missing")
    jail = STATE["jail"]
    p = jail.resolve(args.get("path") or "")
    if not p.is_file():
        raise FileNotFoundError("file not found: %s" % args.get("path"))
    fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        if not _fd_under(f.fileno(), jail.root):
            raise PermissionError("path escapes open dir (post-open check)")
        raw = f.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("file over 1MB unsupported")
    content = raw.decode("utf-8", errors="replace")
    n = content.count(old)
    if n == 0:
        raise ValueError("old not found in file (nothing changed)")
    if n > 1:
        raise ValueError("old appears %d times, not unique; include more context and retry" % n)
    new_content = content.replace(old, new, 1)
    nb = len(new_content.encode("utf-8"))
    i = content.find(old)
    a = max(0, i - 60)
    preview = ("edit %s\n- %s\n+ %s" % (
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
            raise PermissionError("user denied this edit (or 100s approval timeout)")
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if not _fd_under(f.fileno(), jail.root):
                raise PermissionError("path escapes open dir (post-open check)")
            f.truncate(0)
            f.write(new_content)
        _sys("edited: %s" % p)
        return {"edited": str(p.relative_to(jail.root)), "bytes": nb}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


def _do_write(oid, args):
    content = str(args.get("content", ""))
    nb = len(content.encode("utf-8"))
    if nb > MAX_FILE_BYTES:
        raise ValueError("content over 1MB unsupported")
    p = STATE["jail"].resolve(args.get("path") or "")
    if len(content) > 300:
        preview = "%s\n...(%d chars omitted)...\n%s" % (
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
            raise PermissionError("user denied this write (or 100s approval timeout)")
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o644)  # 回验后再 truncate
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if not STATE["jail"].fd_in_jail(f.fileno()):
                raise PermissionError("path escapes open dir (post-open check)")
            f.truncate(0)
            f.write(content)
        _sys("wrote: %s (%d bytes)" % (p, nb))
        return {"written": str(p.relative_to(STATE["jail"].root)), "bytes": nb}
    finally:
        with STATE["lock"]:
            STATE["pending"].pop(oid, None)


def _do_delete(oid, args):
    """删除文件/空目录。不可恢复,永远逐笔批准(不吃 /auto 免确认)。"""
    p = STATE["jail"].resolve(args.get("path") or "")
    if not p.exists() and not p.is_symlink():
        raise FileNotFoundError("not found: %s" % args.get("path"))
    if p.is_dir() and not p.is_symlink():
        if any(p.iterdir()):
            raise ValueError("dir not empty, recursive delete unsupported: %s" % args.get("path"))
        nb, preview = 0, "(empty dir)"
    else:
        nb = p.stat().st_size
        preview = "file %d bytes" % nb
        if nb and nb <= MAX_FILE_BYTES and p.is_file():
            fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as f:
                if not STATE["jail"].fd_in_jail(f.fileno()):
                    raise PermissionError("path escapes open dir (post-open check)")
                head = f.read(200).decode("utf-8", errors="replace")
            preview = "file %d bytes, head:\n%s" % (nb, head)
    req = {"path": str(p), "bytes": nb, "preview": preview, "kind": "delete",
           "event": threading.Event(), "decision": None, "ts": time.time()}
    with STATE["lock"]:
        STATE["pending"][oid] = req
    try:
        req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
        if req["decision"] != "approve":
            raise PermissionError("user denied this delete (or 100s approval timeout)")
        if p.is_dir() and not p.is_symlink():
            p.rmdir()
        else:
            p.unlink()
        _sys("deleted: %s" % p)
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
        return ("No wild runs: MD engine command (lmp/gmx/mdrun...) detected;"
                " must go through the supervised pipeline with supervise:true"
                " (reruns/short tests included). Stop when rejected; no bypass")
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
                return ("No wild runs: script %s contains an MD engine command; MD must"
                        " always run supervised with supervise:true" % name)
    return None


def _do_exec(oid, args):
    """后台执行 shell 命令(bash,cwd=开放根目录),立即返回,日志进 .mdagent_run/。
    长任务(模拟几小时)撑不住桥 110s 超时,所以一律异步:起进程→返 run_id/日志路径,
    云端之后用 localfs_read 读日志跟进。/auto 开时免批准,否则弹批准卡。
    supervise:true 且本机有 MD 管线时走上轨发车(_do_exec_gate)。"""
    cmd = str(args.get("cmd") or "").strip()
    if not cmd:
        raise ValueError("cmd must not be empty")
    if args.get("supervise"):
        if not _gate_available():
            raise PermissionError(
                "No wild runs: supervise needs the local MD pipeline (mdrun_gate),"
                " unavailable here; direct run refused (install it or use a"
                " machine that has it)")
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
           "preview": "workdir: %s\ntimeout: %ds\nlog: %s" % (jail.root, timeout_s, log_rel),
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
            raise PermissionError("user denied this exec (or 100s approval timeout)")
        lf = open(jail.root / log_rel, "w", encoding="utf-8")
        lf.write("$ %s\n\n" % cmd)
        lf.flush()
        proc = subprocess.Popen(["/bin/bash", "-c", cmd], cwd=str(jail.root),
                                stdout=lf, stderr=subprocess.STDOUT,
                                start_new_session=True)
        threading.Thread(target=_watch_exec, args=(proc, lf, timeout_s),
                         daemon=True).start()
        _sys("started: %s (pid %d, log %s)" % (cmd[:60], proc.pid, log_rel))
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
        raise ValueError("supervise needs cmd like `lmp -in input.file`"
                         "(no -in found in cmd)")
    jail = STATE["jail"]
    in_path = jail.resolve(m.group(1))
    if not in_path.is_file():
        raise FileNotFoundError("lammps input not found: %s" % m.group(1))
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
           "preview": ("supervised launch:\ncase: %s\nprod dir: %s\n"
                       "input: %s (%d bytes) + %d data files\n"
                       "after approval the pipeline supervises (auto-recover/dashboard)")
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
            raise PermissionError("user denied this exec (or 100s approval timeout)")
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
            raise RuntimeError("gate returned nothing (rc=%s): %s"
                               % (r.returncode, (r.stderr or "")[-200:]))
        if not res.get("success"):
            raise RuntimeError("pipeline gate refused: %s" % res.get("error"))
        real_pd = os.path.realpath(res["prod_dir"])
        STATE["extra_readable"].add(real_pd)
        board = "on dashboard (cloud-client)"
        if res.get("adopt_queued"):
            board += ", queued for adopter"
        elif res.get("completed"):
            board += "(finished instantly, no supervision needed)"
        _sys("supervised launch: %s → %s" % (case_id, real_pd))
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
        lf.write("\n[exit code %d]\n" % rc)
    except subprocess.TimeoutExpired:
        lf.write("\n[timeout %ds, killed]\n" % timeout_s)
        try:
            os.killpg(proc.pid, 9)
        except Exception:
            pass
        proc.wait()
    except Exception as ex:
        lf.write("\n[watch error: %s]\n" % ex)
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
        t.append("  MD Agent · Terminal Workbench\n", style="bold #C9D1E0")
        t.append("  Brain in the cloud (%s)\n" % server, style="#5F6B7A")
        t.append("  Drag-select then Ctrl+C to copy · Wheel/arrows to scroll · /login to sign in\n",
                 style="#3A4152")
        t.append("  Open dir %s · every write/delete needs approval · /help for commands\n" % root,
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
            t.append("  ✗ " + str(op.get("_err") or "rejected/failed"),
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
                title="✶ Thinking (%d chars, expand for full)" % len(self._thinking_seen),
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
    ("/project", "<name>", "switch project (own context, history replayed)"),
    ("/resume", "[n]", "resume a past project (by recent activity)"),
    ("/policy", "", "show/reload local policy mdagent.md"),
    ("/archive", "[name]", "archive project (default = current)"),
    ("/restore", "<name>", "restore the last archived project"),
    ("/root", "<dir>", "change the local open directory"),
    ("/auto", "", "toggle write auto-approve (default off)"),
    ("/goal", "", "goal panel: current task sub-goals"),
    ("/apikey", "", "change LLM API key (opens provider console)"),
    ("/login", "", "sign in with username/password"),
    ("/mouse", "", "toggle mouse capture (off = native select/copy)"),
    ("/evolution", "", "open the agent evolution graph in browser"),
    ("/status", "", "bridge status + hourly usage"),
    ("/help", "", "all commands"),
    ("/quit", "", "quit"),
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
        else:
            self.app.scroll_chat(-2)

    def action_cmd_down(self):
        if getattr(self.app, "_cmd_open", False):
            self.app._cmd_move(1)
        else:
            self.app.scroll_chat(2)

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


_GOAL_HINT = "No active goal in this project\n(the agent writes GOAL.md in the work dir for multi-step tasks)"


def _render_goal(content):
    """GOAL.md → 富文本:# 目标:标题行 + - [x]/[>]/[ ] 子目标清单 + 进度条。"""
    title, subs = "", []
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r"^#\s*(目标|Goal|GOAL)[:：]\s*(.+)$", line)
        if m and not title:
            title = m.group(1).strip()
            continue
        m = re.match(r"^-\s*\[([xX> ])\]\s*(.+)$", line)
        if m:
            subs.append((m.group(1).lower(), m.group(2).strip()))
    t = Text()
    if not title and not subs:
        t.append(content[:400] or "", style="#97A0B0")
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
        self.border_title = "🎯 Goals"

    def show(self, content):
        self.update(_render_goal(content))

    def clear(self):
        self.update(Text(_GOAL_HINT, style="#5F6B7A"))


class OpsPanel(Static):
    def __init__(self):
        super().__init__(Text("No file ops yet", style="#5F6B7A"), id="ops")
        self.border_title = "📁 File ops"
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
            t.append(app.phase or "Thinking…", style="#D29922")
            t.append("  ·  ", style="#3A4152")
        else:
            t.append(" ● ", style="#3FB950" if online else "#F85149")
            t.append("online" if online else "offline", style="#97A0B0")
            t.append("  ·  ", style="#3A4152")
        t.append("⛁ %s" % _PROJECT, style="#5686FE")
        t.append("  ·  ", style="#3A4152")
        t.append("%s" % (STATE["jail"].root if STATE["jail"] else "?"),
                 style="#5F6B7A")
        u = getattr(app, "usage", None) or {}
        lim = u.get("limit_per_hour") or 0
        t.append("  ·  chats %s%s" % (u.get("chats_24h", "?"),
                                      "/%s per hour" % lim if lim else " · unlimited"),
                 style="#5F6B7A")
        gs = getattr(app, "goal_summary", None)
        if gs:
            t.append("  ·  🎯 %d/%d" % gs, style="#5686FE")
        if STATE["auto"]:
            t.append("  ·  ⚠ auto-approve ON", style="#D29922")
        t.append("  ·  Ctrl+G goals", style="#3A4152")
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
                self.notify("Copied %d chars" % len(text))
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
        Binding("ctrl+c", "copy_or_quit", "copy/quit", priority=True),
        Binding("ctrl+q", "quit_app", "quit", priority=True),
        Binding("ctrl+g", "toggle_side", "goals"),
        Binding("pageup", "chat_pageup", "page up", show=False),
        Binding("pagedown", "chat_pagedown", "page down", show=False),
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
        yield CommandInput(placeholder="Message · / command menu · Paste Ctrl+Shift+V · "
                                       "select+Ctrl+C copy · Ctrl+G goals",
                           id="composer")
        yield StatusBar(id="status")

    def on_mount(self):
        global _APP
        _APP = self
        self.query_one("#side").display = False   # Claude Code 式:默认无侧栏
        # 默认关鼠标捕获:开箱即可原生拖选复制;同时开 1007 备用屏滚轮,
        # 终端把滚轮转成 ↑↓ → 菜单关着时滚聊天区(两全)
        try:
            drv = self._driver
            if drv is not None:
                drv._disable_mouse_support()
        except Exception:
            pass
        _alt_scroll(True)
        asyncio.get_event_loop().create_task(self._mount(
            Banner(STATE["cfg"]["server"], str(STATE["jail"].root))))
        self.set_interval(0.3, self._check_pending)
        self.set_interval(0.12, self._spin)
        self.set_interval(2, self._tick)
        self.set_interval(3, self._poll_goal)
        asyncio.get_event_loop().create_task(self._load_history(_PROJECT))
        STATE["policy"] = _read_policy()
        if STATE["policy"]:
            self.add_sys("Local policy loaded: mdagent.md (%d chars, attached every turn,"
                         " never stored in chat history; /policy to view)" % len(STATE["policy"]))
        else:
            self.add_sys("Tip: put a mdagent.md in the open dir (like Claude Code's "
                         "CLAUDE.md) to pin your rules, applied every turn.")
        self.query_one("#composer", Input).focus()

    def _spin(self):
        self._spin_i += 1
        if self.busy:
            self.query_one("#status", StatusBar).refresh()

    def on_unmount(self):
        _alt_scroll(False)

    def scroll_chat(self, lines):
        """↑↓/滚轮(1007 转键)滚动对话区。"""
        try:
            c = self.query_one("#chat", VerticalScroll)
            if lines:
                c.scroll_relative(y=lines, animate=False)
        except Exception:
            pass

    def action_chat_pageup(self):
        try:
            self.query_one("#chat", VerticalScroll).scroll_page_up(animate=False)
        except Exception:
            pass

    def action_chat_pagedown(self):
        try:
            self.query_one("#chat", VerticalScroll).scroll_page_down(animate=False)
        except Exception:
            pass

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
            self.add_sys("A task is still running, wait for it… (ESC to interrupt)")
            return
        self.add_user(text)
        asyncio.get_event_loop().create_task(self._send(text))

    # ---- 对话 ----
    async def _send(self, text):
        loop = asyncio.get_event_loop()
        self.busy = True
        self.phase = "Submitting…"
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
            self.add_sys("Submit failed: %s" % _err_text(e))
            return
        jid = r.get("job_id")
        self._job_id = jid
        if not jid:
            self._stream_end()
            self.add_sys("Submit failed: %s" % r)
            return
        while True:
            await asyncio.sleep(1.0)
            try:
                j = await loop.run_in_executor(None, functools.partial(
                    _http, "GET", "/v1/jobs/" + jid, None, 15))
            except Exception as e:
                self._stream_end()
                self.add_sys("Poll failed: %s" % _err_text(e))
                return
            st = j.get("status")
            if st == "done":
                reply = j.get("reply") or "(empty reply)"
                self._stream_end(reply)
                return
            if st == "error":
                self._stream_end()
                self.add_sys("Cloud error: %s" % (j.get("error") or "?"))
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
            self.phase = j.get("activity") or "Working (%s)…" % st

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
            self.add_sys("History replay failed: %s" % _err_text(e))
            return
        turns = d.get("turns") or []
        if turns:
            self.add_sys("—— project '%s': %d turns of cloud history ——" % (project, len(turns)))
            for t in turns:
                if t.get("role") == "user":
                    self.add_user(t.get("text", ""))
                elif t.get("role") == "assistant":
                    self.add_agent(t.get("text", ""))
        else:
            self.add_sys("Project '%s' has no history yet. Chat/memory/evolution live in your"
                         " private cloud space; local writes need approval." % project)

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
                self.add_sys("Usage: /root <dir>")
                return
            try:
                j = Jail(arg)
            except Exception as e:
                self.add_sys("Switch failed: %s" % e)
                return
            STATE["jail"] = j
            cfg = STATE["cfg"]
            if cfg:
                _save_cfg(cfg["server"], cfg["token"], str(j.root))
                cfg["root"] = str(j.root)
            self.add_sys("Open dir switched: %s" % j.root)
            STATE["policy"] = _read_policy()
            self.add_sys("Local policy mdagent.md: %s" % (
                "%d chars loaded" % len(STATE["policy"]) if STATE["policy"]
                else "none in this dir (drop one in to enable)"))
            if j.root.parent == j.root or j.root == Path.home():
                self.add_sys("!! WARNING: you opened the whole disk/home dir; files in it can be"
                             " read remotely. Better open a project dir only")
        elif cmd == "project":
            if not arg:
                self.add_sys("Usage: /project <name>")
                return
            _PROJECT = arg
            self.add_sys("Project: %s (own context), replaying cloud history…" % arg)
            asyncio.get_event_loop().create_task(self._load_history(arg))
        elif cmd == "archive":
            target = arg or _PROJECT
            asyncio.get_event_loop().create_task(self._archive_cmd(target))
        elif cmd == "restore":
            if not arg:
                self.add_sys("Usage: /restore <project>")
                return
            asyncio.get_event_loop().create_task(self._restore_cmd(arg))
        elif cmd == "auto":
            if STATE["auto"]:
                STATE["auto"] = False
                self.add_sys("Write auto-approve: OFF")
            else:
                self.confirm = "auto_on"
                self.add_sys("Turn on to skip per-write approval (still jailed to the open dir)."
                             "Type yes to confirm, anything else cancels")
        elif cmd == "resume":
            asyncio.get_event_loop().create_task(self._resume_cmd(arg))
        elif cmd == "policy":
            STATE["policy"] = _read_policy()
            if STATE["policy"]:
                self.add_sys("mdagent.md (%s) %d chars total, attached every turn. First 600 chars:\n%s"
                             % (STATE["jail"].root / "mdagent.md",
                                len(STATE["policy"]), STATE["policy"][:600]))
            else:
                self.add_sys("No mdagent.md in the open dir; create one to enable: %s"
                             % (STATE["jail"].root / "mdagent.md"))
        elif cmd == "login":
            self.login = {"step": "user"}
            inp = self.query_one("#composer", Input)
            inp.password = False
            inp.placeholder = "Username (empty Enter cancels /login)"
            self.add_sys("Login: enter username (empty Enter cancels)")
        elif cmd == "apikey":
            self.add_sys("Change LLM API key: pick a provider (Enter = 1 Kimi);"
                         " its console opens in your browser:")
            for i, (_pid, label, _u) in enumerate(PROVIDER_MENU, 1):
                self.add_sys("  %d) %s" % (i, label))
            self.keywiz = {"step": "provider"}
        elif cmd == "mouse":
            try:
                drv = self._driver
                if drv is not None and getattr(drv, "_mouse", False):
                    drv._disable_mouse_support()
                    _alt_scroll(True)
                    self.add_sys("Mouse capture OFF — native select/copy; wheel still scrolls"
                                 " via mode 1007 (or PgUp/PgDn). /mouse to toggle")
                elif drv is not None:
                    _alt_scroll(False)
                    drv._enable_mouse_support()
                    self.add_sys("Mouse capture ON — click/wheel back;"
                                 " copy with Shift+drag select")
            except Exception as e:
                self.add_sys("Mouse toggle failed: %s" % e)
        elif cmd in ("evolution", "\u8fdb\u5316"):
            server = (STATE["cfg"] or {}).get("server") or DEFAULT_SERVER
            url = server.rstrip("/") + "/evolution.html"
            self.add_sys("Evolution graph: opening %s "
                         "(paste your mda_ token when asked; kept in page sessionStorage)"
                         % url)
            self.add_sys("If the browser didn't open, visit: %s" % url)
            threading.Thread(target=lambda: webbrowser.open(url),
                             daemon=True).start()
        elif cmd == "status":
            asyncio.get_event_loop().create_task(self._status_cmd())
        elif cmd == "goal":
            # 任务/目标查看:侧坞打开 + 当前目标印进 transcript
            self.query_one("#side").display = True
            asyncio.get_event_loop().create_task(self._goal_cmd())
        elif cmd in ("help", "h", "?"):
            self.add_sys("Commands: " + " │ ".join(
                c + (" " + a if a else "") + " " + d
                for c, a, d in _COMMANDS) + " │ type / for menu")
        else:
            self.add_sys("Unknown command %s; /help lists all" % cmd)

    async def _archive_cmd(self, project):
        loop = asyncio.get_event_loop()
        try:
            r = await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/conversations/%s/archive"
                % urllib.parse.quote(project, safe=""), None, 15))
            self.add_sys("Archived %s (ts %s, with %s); /restore %s to bring back"
                         % (project, r.get("archived_ts"),
                            "+".join(r.get("moved") or []), project))
        except Exception as e:
            self.add_sys("Archive failed: %s" % _err_text(e))

    async def _restore_cmd(self, project):
        loop = asyncio.get_event_loop()
        try:
            r = await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/conversations/%s/restore"
                % urllib.parse.quote(project, safe=""), None, 15))
            self.add_sys("Restored %s (%s)" % (project,
                                            "+".join(r.get("restored") or [])))
        except Exception as e:
            self.add_sys("Restore failed: %s" % _err_text(e))

    async def _goal_cmd(self):
        loop = asyncio.get_event_loop()
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/goal?project="
                + urllib.parse.quote(_PROJECT, safe=""), None, 10))
        except Exception as e:
            self.add_sys("Goal fetch failed: %s" % _err_text(e))
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
            self.add_sys("Bridge online: %s │ usage: %s %s │ server: %s" % (
                s.get("online"), u.get("chats_24h"),
                "/%s per hour" % lim if lim else "(unlimited)",
                (STATE["cfg"] or {}).get("server")))
        except Exception as e:
            self.add_sys("Status failed: %s" % _err_text(e))

    def _resolve_confirm(self, text):
        what = self.confirm
        self.confirm = None
        if what == "auto_on":
            STATE["auto"] = text.strip().lower() == "yes"
            self.add_sys("Write auto-approve: %s"
                         % ("ON (careful!)" if STATE["auto"] else "OFF"))

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
            inp.placeholder = "Password (hidden), Enter to login"
            self.add_sys("Password (hidden), Enter to login; empty Enter cancels")
            return
        self.login = None
        inp.password = False
        inp.placeholder = "Message · / command menu · Paste Ctrl+Shift+V · Ctrl+G goals"
        if not text:
            self.add_sys("Cancelled")
            return
        asyncio.get_event_loop().create_task(self._login_do(st["user"], text))

    async def _resume_cmd(self, arg):
        loop = asyncio.get_event_loop()
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _http, "GET", "/v1/conversations", None, 15))
        except Exception as e:
            self.add_sys("Failed to fetch projects: %s" % _err_text(e))
            return
        items = d.get("detail") or []
        if not items:
            self.add_sys("No projects yet on the cloud; just start chatting (or /project <name>)")
            return
        if arg:
            self._resume_pick(arg, items)
            return
        self.add_sys("—— Your projects (by recent activity) ——")
        for i, it in enumerate(items[:20], 1):
            ts = time.strftime("%m-%d %H:%M",
                               time.localtime(it.get("mtime") or 0))
            self.add_sys("%2d. %-28s active %s" % (i, it.get("name"), ts))
        self.resume = {"items": items[:20]}
        self.add_sys("Enter a number to resume (name also works; empty Enter cancels)")

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
            self.add_sys("No project matched '%s', try /resume again" % text)
            return
        _PROJECT = name
        self.add_sys("Resumed project '%s', replaying history…" % name)
        asyncio.get_event_loop().create_task(self._load_history(name))

    def _resume_step(self, text):
        items = (self.resume or {}).get("items") or []
        self.resume = None
        if not text:
            self.add_sys("Cancelled /resume")
            return
        self._resume_pick(text, items)

    def _login_cancel(self):
        self.login = None
        inp = self.query_one("#composer", Input)
        inp.password = False
        inp.placeholder = "Message · / command menu · Paste Ctrl+Shift+V · Ctrl+G goals"
        self.add_sys("Cancelled /login")

    async def _login_do(self, user, pwd):
        loop = asyncio.get_event_loop()
        server = (STATE["cfg"] or {}).get("server") or DEFAULT_SERVER
        self.add_sys("Logging in as %s @ %s…" % (user, server))
        try:
            d = await loop.run_in_executor(None, functools.partial(
                _login, server, user, pwd))
        except Exception as e:
            self.add_sys("Login failed: %s" % _err_text(e))
            return
        root = str(STATE["jail"].root) if STATE["jail"] else os.getcwd()
        STATE["cfg"] = _save_cfg(server, d["token"], root)
        self.add_sys("Login OK: %s (token saved locally, old token revoked)"
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
                self.add_sys("Opening console (%s) in browser; copy the API key back"
                             " here. If it didn't open, visit: %s" % (pid, url))
                threading.Thread(target=lambda: webbrowser.open(url),
                                 daemon=True).start()
            else:
                self.add_sys("provider=%s (no known console URL, just paste the key)" % pid)
            wiz["provider"] = pid
            wiz["step"] = "key"
            inp.password = True      # key 不回显
            inp.placeholder = "Paste the sk- API key (hidden), Enter to submit"
            self.add_sys("Step 2: paste the API key (hidden), Enter to submit;"
                         " empty Enter cancels")
            return
        self.keywiz = None
        inp.password = False
        inp.placeholder = ("Message · / command menu · Paste Ctrl+Shift+V · "
                           "select+Ctrl+C copy · Ctrl+G goals")
        key = text.strip()
        if not key:
            self.add_sys("Cancelled")
            return
        asyncio.get_event_loop().create_task(
            self._apikey_save(wiz["provider"], key))

    async def _apikey_save(self, provider, key):
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, functools.partial(
                _http, "POST", "/v1/me/apikey",
                {"provider": provider, "api_key": key}, 15))
            self.add_sys("API key updated (provider=%s), synced cloud-side"
                         % provider)
        except Exception as e:
            self.add_sys("API key update failed: %s" % _err_text(e))

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
            head = "⚠ Cloud agent requests DELETE (irreversible): %s" % req["path"]
            title = "Delete approval · auto-deny in 100s"
        elif req.get("kind") == "exec":
            head = "⚠ Cloud agent requests EXEC: %s" % req["path"]
            title = "Exec approval · auto-deny in 100s"
        else:
            head = "⚠ Cloud agent requests WRITE: %s (%d bytes)" % (req["path"],
                                                         req["bytes"])
            title = "Write approval · auto-deny in 100s"
        card = ApprovalCard(
            Static(Text(head, style="bold #E6B450")),
            Static(Text("\n".join("  " + l for l in
                                  str(req["preview"]).split("\n")[:6]),
                        style="#C9D1E0")),
            Horizontal(Button("Approve (y)", id="btn-ok", compact=True),
                       Button("Deny (n)", id="btn-no", compact=True)),
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
        self.add_sys("%s: %s" % ("approved" if ok else "denied", req["path"]))
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
        self.add_sys("⏹ Interrupting…")

        async def _c():
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, functools.partial(
                        _http, "POST", "/v1/jobs/%s/cancel" % jid, None, 15))
            except Exception as e:
                self.add_sys("Interrupt failed: %s" % _err_text(e))
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
    ap = argparse.ArgumentParser(description="mdagent TUI client - cloud agent in your terminal")
    ap.add_argument("--server", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--root", default=None)
    ap.add_argument("--project", "-p", default=None,
                    help="start with this project")
    ap.add_argument("--resume", action="store_true",
                    help="pick a past project to resume at startup")
    ap.add_argument("-c", "--continue", dest="cont", action="store_true",
                    help="resume the most recent project")
    args = ap.parse_args()

    cfg = _load_cfg() or {}
    if args.token or args.server or args.root:
        cfg = _save_cfg(args.server or cfg.get("server") or DEFAULT_SERVER,
                        args.token or cfg.get("token") or "",
                        args.root or cfg.get("root") or "")
    if args.token:
        ok, msg = _verify_token(cfg["server"], cfg["token"])
        if not ok:
            sys.exit("Token check failed (%s), not saved" % msg)
    if not cfg.get("token"):
        # 首次配置:进全屏前用普通 input 问完(免得在 TUI 里做表单)。
        # EOF 兜底:curl|sh 管道跑时 stdin 是管道,input 立即 EOF——指路直跑
        try:
            print("First-time setup (asked once; saved to %s, mode 600):" % CONFIG)
            server = input("  Server [%s]: " % DEFAULT_SERVER).strip() or DEFAULT_SERVER
            preset_token = ""
            if server.startswith("mda_"):
                preset_token = server
                server = DEFAULT_SERVER
                print("  (That looks like a token; using it as token with default server %s)" % server)
            if not server.startswith(("http://", "https://")):
                sys.exit("Server must start with http(s):// (got %r), config not saved"
                         % server[:40])
            print("  1) Login with username/password (recommended)")
            print("  2) Paste a token (mda_..., issued by admin)")
            print("  3) Register a new account (needs admin approval)")
            choice = input("  Select [1]: ").strip() or "1"
            token = ""
            if choice == "3":
                _register_flow(server)
                return
            if choice == "1":
                import getpass
                user = input("  Username: ").strip()
                pwd = getpass.getpass("  Password: ")
                try:
                    d = _login(server, user, pwd)
                    token = d["token"]
                    print("  Login OK (token fetched)")
                except Exception as ex:
                    sys.exit("Login failed: %s" % ex)
            else:
                token = preset_token or input("  token: ").strip()
                ok, msg = _verify_token(server, token)
                if not ok:
                    sys.exit("Token check failed (%s) - not saved; rerun and paste again" % msg)
                print("  Token OK")
            root = input("  Dir to open to the agent [%s]: " % os.getcwd()).strip() or os.getcwd()
            if not token.startswith("mda_"):
                sys.exit("Bad token format (must start with mda_)")
            cfg = _save_cfg(server, token, root)
        except EOFError:
            sys.exit("\n[!] No interactive input (piped run, e.g. curl … | sh).\n"
                     "    Run it from the extracted dir instead: python3 client/mdagent_tui.py")
    STATE["cfg"] = cfg
    STATE["jail"] = Jail(cfg.get("root") or os.getcwd())
    if STATE["jail"].root.parent == STATE["jail"].root or \
            STATE["jail"].root == Path.home():
        print("!! WARNING: whole disk/home dir opened; files can be read remotely;"
              " better open a project dir (/root to change)")

    if args.project:
        _PROJECT = args.project
        print("Project: %s (cloud history replayed on start)" % _PROJECT)
    if args.resume or args.cont:
        try:
            d = _http("GET", "/v1/conversations", None, 15)
            items = d.get("detail") or []
            if not items:
                print("No projects on the cloud yet; just start chatting")
            elif args.cont:
                _PROJECT = items[0]["name"]
                print("Resuming most recent project '%s'" % _PROJECT)
            else:
                print("Your projects (by recent activity):")
                for i, it in enumerate(items[:20], 1):
                    print("  %2d. %-28s active %s"
                          % (i, it.get("name"),
                             time.strftime("%m-%d %H:%M",
                                           time.localtime(it.get("mtime") or 0))))
                sel = input("Resume which [1]: ").strip() or "1"
                i = int(sel) - 1 if sel.isdigit() else -1
                if not (0 <= i < len(items[:20])):
                    sys.exit("Invalid number")
                _PROJECT = items[i]["name"]
                print("Selected '%s' (cloud history replayed on start)" % _PROJECT)
        except EOFError:
            sys.exit("\n[!] No interactive input (piped run); use --project <name> instead")
        except Exception as e:
            print("(failed to fetch projects: %s, staying on default)" % _err_text(e))
    threading.Thread(target=_bridge_loop, daemon=True).start()
    try:
        MdAgentApp().run()
    except KeyboardInterrupt:
        pass
    print("Disconnected. Bye.")


if __name__ == "__main__":
    main()
