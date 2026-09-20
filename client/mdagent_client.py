#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mdagent-client —— 云端 MD 智能体的本地客户端(Codex 模式)。
在你自己机器上跑:聊天 + 让云端智能体读写你指定的本地目录。
纯标准库,Python 3.8+,Windows/Linux/macOS 通用,无需安装任何依赖。

用法:
  python mdagent_client.py --token mda_xxx            # 首次(保存配置)
  python mdagent_client.py                            # 之后直接跑
  python mdagent_client.py --root D:\\我的项目         # 指定开放给智能体的目录

REPL 命令:
  /root <目录>   切换开放目录(默认=启动目录)
  /auto          写操作免确认开关(默认关:每次写入都要你 y 批准)
  /status        看连接/桥状态
  /quit          退出

安全:智能体只能碰 --root 内的文件;写文件前你会看到内容摘要,逐笔批准。
"""
import argparse
import collections
import hashlib
import http.client
import json
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

_BUILTIN_SERVER = "https://47.94.209.90/mdagent"
CONFIG = os.path.join(os.path.expanduser("~"), ".mdagent_client.json")
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


DEFAULT_SERVER = _kit_get("server_default") or _BUILTIN_SERVER

# MD 引擎命令识别(命令位/包装器后/嵌套 shell):绝不野跑铁律的执行器级硬闸,与 TUI 版同款
_MD_ENGINE_RE = re.compile(
    r"(?:^|[;&|`]\s*|\$\(\s*[\"']?\s*"
    r"|\b(?:nohup|nice|ionice|setsid|stdbuf|taskset|numactl|timeout|env)"
    r"(?:\s+\S+)*\s+"
    r"|\b(?:bash|zsh|dash|sh)\s+(?:-[a-zA-Z]+\s+)*-c\s+[\"']\s*)"
    r"(?:[^\s;&|]*/)?"
    r"(lmp[\w.-]*|gmx[\w.-]*|mdrun[\w.-]*|mpirun[\w.-]*|mpiexec[\w.-]*"
    r"|namd[\w.-]*|sander[\w.-]*|pmemd[\w.-]*)"
    r"(?:\s|$)")

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


# 服务器证书 SHA256 指纹 pinning(纯 -k 不验证会让中间人冒充服务器偷 token、
# 推恶意文件操作)。kit 配置 cert_sha256 可覆盖;连非默认服务器且未配指纹
# → 走系统 CA 校验
_BUILTIN_CERT = ("F1:75:DF:A3:B5:0F:69:7A:BA:88:C8:23:80:5D:44:11:"
                 "E2:2C:AE:83:33:C5:99:47:A2:01:60:AB:63:BA:7C:69")
CERT_SHA256 = (_kit_get("cert_sha256")
               or (_BUILTIN_CERT if DEFAULT_SERVER == _BUILTIN_SERVER
                   else None))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        if not CERT_SHA256:
            return
        der = self.sock.getpeercert(binary_form=True)
        fp = ":".join("%02X" % b for b in hashlib.sha256(der).digest())
        if fp != CERT_SHA256:
            raise ssl.SSLError(
                "服务器证书指纹不匹配(可能中间人攻击)!期望 %s…,实得 %s…"
                % (CERT_SHA256[:23], fp[:23]))


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


if CERT_SHA256:
    _SSL_CTX = ssl._create_unverified_context()  # 自签跳过 CA 链,认证靠指纹比对
    _OPENER = urllib.request.build_opener(_PinnedHTTPSHandler(context=_SSL_CTX))
else:
    _OPENER = urllib.request.build_opener()      # 自定义服务器未配指纹:系统 CA

# 服务器可控字符串(op 路径/内容/agent 回复)打印前剥控制字符:
# 防 \n 伪造批准历史、ANSI 清屏/OSC52 剪贴板劫持(红队λ)
_CTL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CTL_KEEP_NL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")


def _safe(s, keep_nl=False):
    return (_CTL_KEEP_NL if keep_nl else _CTL_RE).sub("?", str(s))


def _http(method, url, token=None, body=None, timeout=70):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with _OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class Jail:
    """目录囚禁:一切路径解析后必须落在 root 内(符号链接也挡)。
    resolve 是静态判定;打开文件时再经 /proc/self/fd 回验真实路径,
    挡本机攻击者原子 rename 换目录的 TOCTOU 竞态(红队λ)。"""

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
        """打开后回验:fd 的真实路径仍在 root 内才可信(Linux;/proc 缺失时跳过)。"""
        if not os.path.exists("/proc/self/fd"):
            return True
        real = os.path.realpath("/proc/self/fd/%d" % fd)
        try:
            Path(real).relative_to(self.root)
            return True
        except ValueError:
            return False


class Client:
    def __init__(self, server, token, root):
        self.server = server.rstrip("/")
        self.token = token
        self.jail = Jail(root)
        self.auto_write = False
        self.stop_flag = threading.Event()
        self.seen_ops = collections.OrderedDict()  # op_id 去重,防 requeue 重放(红队ι)
        self.approval_q = queue.Queue()            # 写批准请求,主线程统一处理

    # ---------- 文件操作(桥线程回调) ----------
    def do_op(self, op):
        oid, name, args = op["id"], op["op"], op.get("args") or {}
        if oid in self.seen_ops:
            return {"op_id": oid, "ok": False, "error": "重复 op,已忽略(防重放)"}
        self.seen_ops[oid] = None
        while len(self.seen_ops) > 500:
            self.seen_ops.popitem(last=False)
        try:
            if name == "list":
                data = self._op_list(args)
            elif name == "read":
                data = self._op_read(args)
            elif name == "mkdir":
                data = self._op_mkdir(args)
            elif name == "write":
                data = self._op_write(args)  # 可能等用户 y/n
            elif name == "exec":
                data = self._op_exec(oid, args)  # 可能等用户 y/n
            elif name == "glob":
                data = self._op_glob(args)
            elif name == "grep":
                data = self._op_grep(args)
            elif name == "edit":
                data = self._op_edit(args)
            elif name == "delete":
                return {"op_id": oid, "ok": False,
                        "error": "REPL 版不支持删除;请改用终端 TUI 版(mdagent)"}
            else:
                return {"op_id": oid, "ok": False, "error": "未知操作 " + name}
            return {"op_id": oid, "ok": True, "data": data}
        except Exception as ex:
            return {"op_id": oid, "ok": False, "error": str(ex)}

    def _op_list(self, args):
        d = self.jail.resolve(args.get("path") or ".")
        if not d.is_dir():
            raise FileNotFoundError("目录不存在: %s" % args.get("path"))
        return {"entries": sorted("%s%s" % (p.name, "/" if p.is_dir() else "")
                                  for p in d.iterdir())[:500]}


    def _op_read(self, args):
        p = self.jail.resolve(args.get("path") or "")
        if not p.is_file():
            raise FileNotFoundError("文件不存在: %s" % args.get("path"))
        # O_NOFOLLOW 挡末段软链;打开后 fd 回验挡父目录 rename 竞态(TOCTOU)
        fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            if not self.jail.fd_in_jail(f.fileno()):
                raise PermissionError("路径越出开放目录(打开后回验): %s" % args.get("path"))
            limit = (32 if p.suffix.lower() == ".pdf" else
                    (8 if p.suffix.lower() == ".docx" else 1)) * MAX_FILE_BYTES
            raw = f.read(limit + 1)  # 流式截断,不信 st_size(/proc 类虚报)
        if p.suffix.lower() == ".docx":
            if len(raw) > 8 * MAX_FILE_BYTES:
                raise ValueError("docx 超过 8MB,不支持")
            content = _docx_text(raw)[:MAX_FILE_BYTES]
        elif p.suffix.lower() == ".pdf":
            import base64 as _b64
            import shutil as _shutil
            import subprocess as _sp
            pdft = _shutil.which("pdftotext")
            if len(raw) > (32 if pdft else 8) * MAX_FILE_BYTES:
                raise ValueError("PDF 超过 %dMB,不支持" % (32 if pdft else 8))
            if pdft:
                r = _sp.run([pdft, "-enc", "UTF-8", str(p), "-"],
                            stdout=_sp.PIPE, stderr=_sp.DEVNULL, timeout=30)
                content = r.stdout.decode("utf-8", "replace")[:MAX_FILE_BYTES]
            else:
                # 本机无 pdftotext:把字节传云端解(用户机器常没有 poppler)
                try:
                    d = _http("POST", "%s/v1/tools/pdf2text" % self.server,
                              self.token,
                              {"content": _b64.b64encode(raw).decode("ascii")},
                              timeout=60)
                    content = str(d.get("text") or "")[:MAX_FILE_BYTES]
                except Exception as ex:
                    raise RuntimeError("PDF 解析失败(本机无 pdftotext,"
                                       "云端回退也失败): %s" % ex)
        else:
            if len(raw) > MAX_FILE_BYTES:
                raise ValueError("文件超过 1MB,不支持")
            content = raw.decode("utf-8", errors="replace")
        return {"path": str(p.relative_to(self.jail.root)),
                "content": content}

    def _op_mkdir(self, args):
        p = self.jail.resolve(args.get("path") or "")
        p.mkdir(parents=True, exist_ok=True)
        return {"created": str(p.relative_to(self.jail.root))}

    def _fs_walk(self, sub):
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

    def _op_glob(self, args):
        import glob as _glob
        pat = str(args.get("pattern") or "").strip()
        if not pat:
            raise ValueError("pattern 不能为空")
        sub = self.jail.resolve(args.get("path") or ".")
        hits = []
        try:
            gen = _glob.glob(pat, root_dir=str(sub), recursive=True)
        except TypeError:   # py<3.10 无 root_dir 形参
            import glob as _g2
            gen = _g2.glob(os.path.join(str(sub), pat), recursive=True)
            gen = (os.path.relpath(p, str(sub)) for p in gen)
        for p in gen:
            rp = (sub / p).resolve()
            try:
                rp.relative_to(self.jail.root)
            except ValueError:
                continue
            hits.append(str(rp.relative_to(self.jail.root)))
            if len(hits) >= 500:
                break
        return {"matches": sorted(hits), "count": len(hits)}

    def _op_grep(self, args):
        sub = self.jail.resolve(args.get("path") or ".")
        try:
            mx = max(1, min(int(args.get("max") or 100), 200))
        except (TypeError, ValueError):
            mx = 100
        rx = re.compile(str(args.get("pattern") or ""))
        out = []
        files = [str(sub)] if sub.is_file() else self._fs_walk(sub)
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
                rel = str(Path(fp).relative_to(self.jail.root))
                for i, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                    if rx.search(line):
                        out.append({"file": rel, "line": i, "text": line[:300]})
                        if len(out) >= mx:
                            break
            except OSError:
                continue
        return {"matches": out, "count": len(out), "truncated": len(out) >= mx}

    def _op_edit(self, args):
        """精确改一处:old 须唯一,批准卡带前后对比。"""
        old, new = args.get("old"), args.get("new")
        if not isinstance(old, str) or not old:
            raise ValueError("old 不能为空")
        if not isinstance(new, str):
            raise ValueError("new 缺失")
        p = self.jail.resolve(args.get("path") or "")
        if not p.is_file():
            raise FileNotFoundError("文件不存在: %s" % args.get("path"))
        fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            if not self.jail.fd_in_jail(f.fileno()):
                raise PermissionError("路径越出开放目录(打开后回验): %s" % args.get("path"))
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
        if not self.auto_write:
            i = content.find(old)
            preview = ("%s\n- %s\n+ %s" % (
                p, old[:120].replace("\n", "\\n"),
                new[:120].replace("\n", "\\n")))
            req = {"path": str(p), "bytes": len(new_content.encode("utf-8")),
                   "preview": preview, "kind": "edit",
                   "event": threading.Event(), "ok": False}
            self.approval_q.put(req)
            req["event"].wait(100)
            if not req["ok"]:
                raise PermissionError("用户拒绝了这次修改(或 100s 内未批准)")
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if not self.jail.fd_in_jail(f.fileno()):
                raise PermissionError("路径越出开放目录(打开后回验)")
            f.truncate(0)
            f.write(new_content)
        print("[已修改] %s" % _safe(p))
        return {"edited": str(p.relative_to(self.jail.root))}

    def _op_write(self, args):
        content = str(args.get("content", ""))
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError("内容超过 1MB,不支持")
        p = self.jail.resolve(args.get("path") or "")
        if not self.auto_write:
            # 批准在主线程做(桥线程碰 stdin 会和 REPL 抢输入,红队λ);
            # 桥线程最多等 100s(须 < 云端 CALL_TIMEOUT 110s)
            if len(content) > 300:
                preview = "%s\n……(中间省略 %d 字)……\n%s" % (
                    content[:200], len(content) - 300, content[-100:])
            else:
                preview = content
            req = {"path": str(p), "bytes": len(content.encode("utf-8")),
                   "preview": preview.replace("\n", "\\n"),
                   "event": threading.Event(), "ok": False}
            self.approval_q.put(req)
            req["event"].wait(100)
            if not req["ok"]:
                raise PermissionError("用户拒绝了这次写入(或 100s 内未批准)")
        p.parent.mkdir(parents=True, exist_ok=True)
        # 先 O_WRONLY 不带 TRUNC:回验通过再 truncate,避免验证失败已把文件清空
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if not self.jail.fd_in_jail(f.fileno()):
                raise PermissionError("路径越出开放目录(打开后回验): %s" % args.get("path"))
            f.truncate(0)
            f.write(content)
        print("[已写入] %s" % _safe(p))
        return {"written": str(p.relative_to(self.jail.root)),
                "bytes": len(content.encode("utf-8"))}

    def _op_exec(self, oid, args):
        """后台执行 shell 命令(bash,cwd=开放根目录),立即返回 run_id/日志路径。
        /auto 开时免批准,否则主线程弹批准(完整命令可见)。"""
        import subprocess
        cmd = str(args.get("cmd") or "").strip()
        if not cmd:
            raise ValueError("cmd 不能为空")
        if args.get("supervise"):
            raise ValueError("看护发车(supervise)仅终端 TUI 版(mdagent)支持,"
                             "已拒绝;去掉 supervise 可直跑")
        # 绝不野跑铁律:MD 引擎命令一律拒(本 REPL 版无上轨能力,请用 TUI 版)
        if _MD_ENGINE_RE.search(cmd):
            raise PermissionError(
                "绝不野跑:MD 引擎命令(lmp/gmx/mdrun 等)必须经 TUI 版(mdagent)"
                "带 supervise:true 上轨发车,本 REPL 版已硬拒")
        why = self._wild_md_in_script(cmd)
        if why:
            raise PermissionError(why)
        try:
            timeout_s = max(1, min(int(args.get("timeout_s") or 7200), 86400))
        except (TypeError, ValueError):
            timeout_s = 7200
        # op id 净化:云端字符串不当文件名成分(复审 P2-7)
        safe_oid = re.sub(r"[^A-Za-z0-9_-]", "x", oid[:12]) or "op"
        log_rel = ".mdagent_run/%s.log" % safe_oid
        if not self.auto_write:
            req = {"path": "$ " + cmd,
                   "bytes": 0,
                   "preview": "工作目录: %s\n超时上限: %d 秒\n日志: %s" % (
                       self.jail.root, timeout_s, log_rel),
                   "kind": "exec",
                   "event": threading.Event(), "ok": False}
            self.approval_q.put(req)
            req["event"].wait(100)  # 须 < 云端 CALL_TIMEOUT 110s
            if not req["ok"]:
                raise PermissionError("用户拒绝了这次命令执行(或 100s 内未批准)")
        rundir = self.jail.root / ".mdagent_run"
        rundir.mkdir(exist_ok=True)
        lf = open(rundir / ("%s.log" % oid[:12]), "w", encoding="utf-8")
        lf.write("$ %s\n\n" % cmd)
        lf.flush()
        proc = subprocess.Popen(["/bin/bash", "-c", cmd],
                                cwd=str(self.jail.root),
                                stdout=lf, stderr=subprocess.STDOUT,
                                start_new_session=True)
        threading.Thread(target=self._watch_exec, args=(proc, lf, timeout_s),
                         daemon=True).start()
        print("[已启动] %s (pid %d,日志 %s)" % (_safe(cmd[:60]), proc.pid, log_rel))
        return {"run_id": oid[:12], "pid": proc.pid, "log": log_rel,
                "status": "running"}

    def _wild_md_in_script(self, cmd):
        """二道闸:bash/sh 跑的 .sh 脚本读内容扫引擎命令,注释行忽略
        (防把野跑包进脚本绕过命令位检查;与 TUI 版同款)。"""
        cands = set(re.findall(r"\S+\.sh\b", cmd))
        for m in re.finditer(r"(?:^|\s)(?:/bin/)?(?:ba|z)?sh\s+(\S+)", cmd):
            cands.add(m.group(1))
        for name in cands:
            try:
                p = self.jail.resolve(name)
                if not p.is_file():
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")[:262144]
            except Exception:
                continue
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if _MD_ENGINE_RE.search(line):
                    return ("绝不野跑:脚本 %s 内含 MD 引擎命令;MD 一律 "
                            "supervise:true 上轨发车(TUI 版),不许拆进脚本绕过"
                            % name)
        return None

    @staticmethod
    def _watch_exec(proc, lf, timeout_s):
        import subprocess
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

    # ---------- 写批准(只在主线程跑,独占 stdin) ----------
    def _drain_approvals(self):
        while True:
            try:
                req = self.approval_q.get_nowait()
            except queue.Empty:
                return
            req["ok"] = self._ask_approval(req)
            req["event"].set()

    def _ask_approval(self, req):
        print("\n" + "=" * 56)
        if req.get("kind") == "exec":
            print("云端智能体请求执行命令:")
            print("  命令: %s" % _safe(req["path"]))
        else:
            print("云端智能体请求写文件:")
            print("  路径: %s" % _safe(req["path"]))
            print("  大小: %d 字节" % req["bytes"])
        print("  详情: %s" % _safe(req["preview"]))
        try:
            return input("允许? [y/N] ").strip().lower() == "y"
        except (EOFError, KeyboardInterrupt):
            return False

    # ---------- 桥线程:长轮询 ----------
    def bridge_loop(self):
        while not self.stop_flag.is_set():
            try:
                r = _http("GET", "%s/v1/bridge/poll?wait=50" % self.server,
                          self.token, timeout=60)
            except Exception:
                time.sleep(3)
                continue
            op = r.get("op")
            if not op:
                continue
            result = self.do_op(op)
            try:
                _http("POST", "%s/v1/bridge/result" % self.server,
                      self.token, result, timeout=15)
            except Exception:
                pass

    # ---------- 聊天 ----------
    def chat(self, project, message):
        r = _http("POST", "%s/v1/chat" % self.server, self.token,
                  {"project": project, "message": message}, timeout=20)
        jid = r["job_id"]
        sys.stdout.write("思考中")
        sys.stdout.flush()
        for _ in range(720):          # 上限 1 小时,防服务端不回 done 无限轮询
            time.sleep(5)
            self._drain_approvals()  # job 进行中的写批准在这里问(主线程独占 stdin)
            sys.stdout.write(".")
            sys.stdout.flush()
            j = _http("GET", "%s/v1/jobs/%s" % (self.server, jid),
                      self.token, timeout=15)
            if j["status"] == "done":
                print("\r" + " " * 20 + "\r", end="")
                self._drain_approvals()
                return j.get("reply", "")
            if j["status"] == "error":
                print()
                return "[出错] %s" % j.get("error", "未知错误")

    def run(self):
        t = threading.Thread(target=self.bridge_loop, daemon=True)
        t.start()
        print("已连接 %s" % self.server)
        print("开放目录: %s   (写操作%s)" % (
            self.jail.root, "免确认" if self.auto_write else "逐笔批准"))
        print("输入消息即对话;/root /auto /status /quit 可用\n")
        project = "default"
        while True:
            self._drain_approvals()
            try:
                line = input("你: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            if line.startswith("/"):
                parts = line[1:].split(None, 1)
                cmd = parts[0].lower()
                if cmd in ("quit", "exit", "q"):
                    break
                elif cmd == "root" and len(parts) > 1:
                    self.jail = Jail(parts[1])
                    print("开放目录已切换: %s" % self.jail.root)
                    if (self.jail.root.parent == self.jail.root
                            or self.jail.root == Path.home()):
                        print("!! 警告: 开放范围是整个盘/家目录,其中文件可被远程读取,"
                              "写入仍需你逐笔批准;建议只开放项目目录")
                elif cmd == "auto":
                    if not self.auto_write:
                        ans = input("开启后写文件不再逐笔询问,确认? [yes/N] ").strip()
                        self.auto_write = ans.lower() == "yes"
                    else:
                        self.auto_write = False
                    print("写操作免确认: %s" % ("开(谨慎!)" if self.auto_write else "关"))
                elif cmd == "status":
                    try:
                        s = _http("GET", "%s/v1/bridge/status" % self.server,
                                  self.token, timeout=10)
                        u = _http("GET", "%s/v1/usage" % self.server,
                                  self.token, timeout=10)
                        lim = u.get("limit_per_hour") or 0
                        print("桥在线: %s | 用量: %s %s" % (
                            s.get("online"), u.get("chats_24h"),
                            "/%s 每小时" % lim if lim else "(不限量)"))
                    except Exception as ex:
                        print("状态查询失败: %s" % ex)
                elif cmd == "project" and len(parts) > 1:
                    project = parts[1]
                    print("会话项目: %s(上下文独立)" % project)
                else:
                    print("命令: /root <目录> /auto /status /project <名> /quit")
                continue
            try:
                reply = self.chat(project, line)
            except urllib.error.HTTPError as ex:
                body = ex.read().decode("utf-8", "replace")[:200]
                print("[HTTP %s] %s" % (ex.code, body))
                continue
            except Exception as ex:
                print("[网络错误] %s" % ex)
                continue
            print("\n智能体: %s\n" % _safe(reply, keep_nl=True))
        self.stop_flag.set()
        print("已断开,再见。")


def main():
    ap = argparse.ArgumentParser(description="mdagent 云端智能体客户端")
    ap.add_argument("--server", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--root", default=None, help="开放给智能体的本地目录(默认=当前目录)")
    args = ap.parse_args()

    cfg = {}
    if os.path.exists(CONFIG):
        try:
            cfg = json.load(open(CONFIG, encoding="utf-8"))
        except ValueError:
            pass
    server = args.server or cfg.get("server") or DEFAULT_SERVER
    token = args.token or cfg.get("token")
    root = args.root or cfg.get("root") or os.getcwd()
    if not token:
        print("首次配置:1) 账号密码登录(推荐)  2) 直接贴 token(mda_ 开头)")
        choice = input("选 [1]: ").strip() or "1"
        if choice == "1":
            import getpass
            user = input("用户名: ").strip()
            pwd = getpass.getpass("密码: ")
            try:
                d = _http("POST", server.rstrip("/") + "/v1/login",
                          body={"username": user, "password": pwd}, timeout=15)
                token = d["token"]
                print("登录成功(token 已自动获取)")
            except Exception as ex:
                sys.exit("登录失败: %s" % ex)
        else:
            token = input("token: ").strip()
        if not token.startswith("mda_"):
            sys.exit("token 格式不对(mda_ 开头)")
        fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"server": server, "token": token, "root": root},
                      f, ensure_ascii=False, indent=1)
    if args.token or args.server or args.root:
        # os.open 一步带 600,无 dump→chmod 之间 644 可读竞态(红队λ)
        fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"server": server, "token": token, "root": root},
                      f, ensure_ascii=False, indent=1)
    Client(server, token, root).run()


if __name__ == "__main__":
    main()
