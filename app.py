#!/usr/bin/env python3
"""Clash 订阅转发服务（subwrap）。

转发服务（公网经 NPM 访问）：
  - GET /s/<token> 实时反向代理上游订阅，不存文件、不做缓存；
  - 上游 URL（含账号密码）只存于服务端配置，从不下发、不记日志；
  - 经 Tailscale 隧道访问上游，明文 HTTP 只走隧道内。

管理界面（仅内网访问 http://群晖IP:18081/admin）：
  - 独立管理密码登录；可换分享 token（一键吊销）、改上游地址、测连通、看访问记录；
  - 首次启动从环境变量读取配置并持久化到 /data/config.json，之后在网页里改。
"""

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import struct
import threading
import time
import zlib
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse, urlsplit, urlunsplit
from urllib.request import Request, urlopen

try:
    from qrcodegen import QrCode  # 单文件 MIT 库，随仓库一起发布
    _QR_OK = True
except ImportError:  # pragma: no cover
    QrCode = None
    _QR_OK = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("subwrap")

# ---------------- 配置 ----------------
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8081"))
FETCH_TIMEOUT = int(os.environ.get("FETCH_TIMEOUT", "25"))
CONFIG_PATH = os.environ.get("CONFIG_PATH", "/data/config.json")

_cfg_lock = threading.Lock()
_config = {}          # 生效中的配置：links / upstream_url / admin_pw / public_base
_server_secret = secrets.token_bytes(32)   # 每启动随机，会话与 CSRF 派生自它
_access_log = deque(maxlen=50)             # 访问记录（内存，只记链接备注不记 token）


def _hash_pw(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}\x00subwrap-admin\x00{password}".encode()).hexdigest()


def load_config():
    """启动时：有 config.json 就用它；否则从环境变量初始化并落盘。"""
    global _config
    cfg = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (FileNotFoundError, ValueError):
        cfg = {}
    if not cfg.get("links") and not cfg.get("upstream_url"):
        # 全新初始化：从环境变量 seeding
        cfg = {
            "links": [],
            "upstream_url": os.environ.get("UPSTREAM_URL", "").strip(),
            "admin_salt": secrets.token_hex(8),
            "admin_pw": "",
            "public_base": os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/"),
        }
        token = os.environ.get("SUB_TOKEN", "").strip()
        if token:
            cfg["links"].append(_new_link("默认", token=token))
        pw = os.environ.get("ADMIN_PASSWORD", "")
        if pw:
            cfg["admin_pw"] = _hash_pw(pw, cfg["admin_salt"])
        _save_config(cfg)
    # 兼容旧版单 token 配置：迁移为 links 表
    if not cfg.get("links") and cfg.get("sub_token"):
        cfg["links"] = [_new_link("默认", token=cfg.pop("sub_token"))]
        _save_config(cfg)
    cfg.setdefault("links", [])
    # 忘记密码时的强制重置：.env 里填了 ADMIN_PASSWORD，则每次启动都覆盖网页上设的密码
    env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
    if env_pw:
        cfg["admin_salt"] = secrets.token_hex(8)
        cfg["admin_pw"] = _hash_pw(env_pw, cfg["admin_salt"])
        _save_config(cfg)
        log.info("ADMIN_PASSWORD 环境变量非空，管理密码已强制重置")
    with _cfg_lock:
        _config = cfg


def _new_token():
    """分享 token：8 位 base62（约 48 bit 熵），在线猜测不可行，长度只有原来 1/4。"""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(8))


def _new_link(label, token=None):
    return {
        "id": secrets.token_hex(6),
        "label": (label or "未命名").strip()[:32],
        "token": token or _new_token(),
        "enabled": True,
        "created": time.strftime("%Y-%m-%d %H:%M"),
    }


def _qr_png_bytes(text):
    """把文本编码为二维码 PNG（qrcodegen 生成矩阵 + 标准库 zlib 手写 PNG 编码器）。"""
    qr = QrCode.encode_text(text, QrCode.Ecc.MEDIUM)
    n = qr.get_size()
    border, scale = 4, 8
    w = n + border * 2
    px = w * scale
    raw = bytearray()
    for y in range(w):
        row = bytearray()
        row.append(0)  # PNG 行滤波器：None
        acc = bits = 0
        for x in range(w):
            mx, my = x - border, y - border
            dark = 0 <= mx < n and 0 <= my < n and qr.get_module(mx, my)
            bit = 0 if dark else 1  # 1-bit 灰度：0=黑，1=白
            for _ in range(scale):  # 横向放大
                acc = (acc << 1) | bit
                bits += 1
                if bits == 8:
                    row.append(acc)
                    acc = bits = 0
        if bits:
            row.append(acc << (8 - bits))
        for _ in range(scale):  # 纵向放大：每行模块重复 scale 个像素行
            raw.extend(row)

    def chunk(typ, data):
        c = struct.pack(">I", len(data)) + typ + data
        return c + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", px, px, 1, 0, 0, 0, 0)  # 灰度 1bit
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b""))


def find_link(token):
    """按 token 查找已启用的链接；禁用/不存在一律返回 None（对外无差别 404）。"""
    for l in list(get_config().get("links", [])):
        if l.get("enabled") and hmac.compare_digest(l.get("token", ""), token):
            return l
    return None


def _save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)


def get_config():
    with _cfg_lock:
        return dict(_config)


def update_config(**kw):
    with _cfg_lock:
        _config.update(kw)
        _save_config(dict(_config))


def admin_enabled():
    return bool(get_config().get("admin_pw"))


# ---------------- 会话/CSRF ----------------
def _session_token():
    return hmac.new(_server_secret, b"admin-session", hashlib.sha256).hexdigest()


def _csrf_token():
    return hmac.new(_server_secret, b"csrf", hashlib.sha256).hexdigest()


def _is_authed(handler):
    cookie = handler.headers.get("Cookie", "")
    m = re.search(r"(?:^|;\s*)sid=([0-9a-f]{64})(?:;|$)", cookie)
    return bool(m) and hmac.compare_digest(m.group(1), _session_token())


# ---------------- 上游 ----------------
MAX_UPSTREAM_BYTES = 8 * 1024 * 1024  # 订阅 YAML 很小，超过 8MB 视为异常


def fetch_upstream(timeout=FETCH_TIMEOUT, url=None):
    target = url or get_config()["upstream_url"]
    headers = {"User-Agent": "subwrap/1.0"}
    parts = urlsplit(target)
    if parts.username:
        # http.client 会把 user:pass@host 中的 "pass@host" 误判为端口
        # （InvalidURL: nonnumeric port），故把 userinfo 剥离改走 Authorization 头。
        creds = unquote(parts.username)
        if parts.password is not None:
            creds += ":" + unquote(parts.password)
        headers["Authorization"] = "Basic " + base64.b64encode(
            creds.encode("utf-8")).decode("ascii")
        host = parts.hostname or ""
        if ":" in host:  # IPv6 还原方括号
            host = f"[{host}]"
        if parts.port:
            host += f":{parts.port}"
        target = urlunsplit((parts.scheme, host, parts.path,
                             parts.query, parts.fragment))
    req = Request(target, headers=headers)
    t0 = time.time()
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read(MAX_UPSTREAM_BYTES + 1)
        if len(body) > MAX_UPSTREAM_BYTES:
            raise ValueError("upstream body too large")
        ms = int((time.time() - t0) * 1000)
        return resp.status, resp.headers.get("Content-Type", "text/yaml; charset=utf-8"), body, ms


def mask_url(url: str) -> str:
    """日志里不出现上游 URL。"""
    return "<upstream>"


# ================= 转发服务 =================
class ForwardHandler(BaseHTTPRequestHandler):
    server_version = "subwrap/1.0"

    def _send(self, code, body, ctype, filename=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self._send(200, b'{"ok": true, "mode": "forward"}',
                        "application/json; charset=utf-8")
            return
        m = re.fullmatch(r"/s/([^/]+)", path)
        link = find_link(m.group(1)) if m else None
        if link:
            try:
                status, ctype, body, _ms = fetch_upstream()
            except Exception as e:  # noqa: BLE001
                log.error("转发上游失败：%s", type(e).__name__)
                self._log_access(link["label"], 502, 0)
                self._send(502, b"upstream unavailable, try later",
                            "text/plain; charset=utf-8")
                return
            self._log_access(link["label"], status, len(body))
            if status != 200:
                self._send(502, b"upstream unavailable, try later",
                            "text/plain; charset=utf-8")
                return
            self._send(200, body, ctype, "sub.yaml")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def _log_access(self, label, status, nbytes):
        ip = self.client_address[0]
        _access_log.appendleft({
            "t": time.strftime("%m-%d %H:%M:%S"),
            "ip": ip, "label": label, "status": status, "bytes": nbytes,
        })

    def log_message(self, fmt, *args):
        logged = re.sub(r"^/s/[^/]+", "/s/<token>", self.path)
        log.info("%s %s", self.command, logged)


# ================= 管理界面 =================
LOGIN_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>subwrap 登录</title>
<style>body{font-family:system-ui;background:#111;color:#eee;display:flex;justify-content:center;
align-items:center;min-height:90vh;margin:0}.card{background:#1c1c1c;padding:28px 32px;border-radius:12px;
width:320px}h2{margin:0 0 16px}input{width:100%;box-sizing:border-box;padding:10px;margin:6px 0 12px;
background:#2a2a2a;border:1px solid #444;color:#eee;border-radius:6px}button{width:100%;padding:10px;
background:#2f7cf6;border:0;color:#fff;border-radius:6px;font-size:15px;cursor:pointer}.err{color:#ff7b7b;
margin-bottom:8px;min-height:20px}</style></head><body><div class="card">
<h2>subwrap 管理</h2><div class="err">{err}</div>
<form method="post" action="/admin/login">
<input type="hidden" name="csrf" value="{csrf}">
<input type="password" name="password" placeholder="管理密码" autofocus>
<button type="submit">登录</button></form></div></body></html>"""

DASH_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>subwrap 管理</title>
<style>body{font-family:system-ui;background:#111;color:#eee;margin:0;padding:20px}
.wrap{max-width:720px;margin:0 auto}.card{background:#1c1c1c;padding:18px 20px;border-radius:12px;
margin-bottom:14px}h2{margin:0 0 4px;font-size:20px}.sub{color:#888;font-size:13px;margin-bottom:12px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}input[type=text],input[type=password]{
flex:1;min-width:200px;padding:9px;background:#2a2a2a;border:1px solid #444;color:#eee;border-radius:6px}
button{padding:9px 14px;background:#2f7cf6;border:0;color:#fff;border-radius:6px;cursor:pointer;font-size:14px}
button.danger{background:#c0392b}button.ghost{background:#333}a{color:#7fb3ff}
.link{font-family:monospace;background:#2a2a2a;padding:8px 10px;border-radius:6px;word-break:break-all;
flex:1}.ok{color:#5fd08a}.bad{color:#ff7b7b}table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 4px;border-bottom:1px solid #2c2c2c;text-align:left}.muted{color:#888}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.err{color:#ff7b7b;min-height:20px;margin-bottom:8px}
details.card summary{cursor:pointer;font-size:17px;font-weight:bold;list-style:none}
details.card summary::-webkit-details-marker{display:none}
details.card summary::before{content:"▸ ";color:#888}
details.card[open] summary::before{content:"▾ "}
details.card h3{font-size:14px;color:#bbb;margin:12px 0 6px}
details.card h3:first-of-type{margin-top:10px}</style></head>
<body><div class="wrap">
<div class="top"><h2>subwrap 管理</h2>
<form method="post" action="/admin/logout" style="margin:0">
<input type="hidden" name="csrf" value="{csrf}"><button class="ghost" type="submit">退出</button></form></div>
<div class="err">{err}</div>

<details class="card">
<summary>产品说明与使用指南 <span class="muted" style="font-weight:normal;font-size:13px">（点击展开）</span></summary>
<div class="sub" style="line-height:1.7">
<h3>产品用途</h3>
subwrap 是一个极简订阅转发网关：把 VPS 上明文 HTTP 的 Clash 订阅 URL（含账号密码）藏在群晖内网，
经 Tailscale 加密隧道实时拉取，再通过 NPM 的 HTTPS 域名对外分发。对外只暴露转发地址，
VPS 的真实域名、IP、账号密码不出现在任何分享链接里。<br>
本服务<strong>不保存订阅内容、不做缓存</strong>，每次请求都实时拉上游，因此分享出去的永远是最新配置。
<h3>使用说明</h3>
1. 一人一链：每人新建一条带备注的专属链接发给对应的人，不要多人共用，否则无法单独吊销。<br>
2. 链接 token 为 8 位随机字符（如 `https://域名/s/aB3xK9qZ`），已足够短；换 token 会重新生成 8 位。<br>
3. 二维码分享：每条链接旁有点「二维码」按钮，打开后长按/右键保存图片发给对方，对方扫码即可导入（需先在「上游订阅」里填好公网域名）。<br>
4. 想断掉某人：点「禁用」（链接立即变 404）；想换发：点「换 token」（旧链接立即失效）；不用了就「删除」。<br>
5. 上游订阅地址变更（如 VPS 账号密码换了）：在「上游订阅」里修改保存即时生效，可先用「测试连通」验证。<br>
6. 「公网域名」只用于拼接展示分享链接和生成二维码，选填，不影响转发。<br>
7. 忘记管理密码：在群晖 .env 里填入新的 ADMIN_PASSWORD 后重建容器强制重置（平时建议清空该项，只在忘记时临时填入）。
<h3>异常处理</h3>
· 对方打不开链接（404）：链接被禁用/换了 token/已删除。请确认发给他的链接是最新的且处于启用状态。<br>
· 拉取订阅失败（502）：上游 VPS 无响应。检查 VPS 是否在线、订阅服务是否运行、群晖 Tailscale 能否访问 VPS 的 100.x 地址。<br>
· 转发地址本身打不开：检查 NPM 反代是否正常、群晖容器是否在运行（18080 端口）。<br>
· 订阅内容没更新：本服务零缓存，每次都实时拉上游；如果内容旧，说明上游本身还没更新，不是转发层的问题。
</div>
</details>

<div class="card"><h2>分享链接</h2><div class="sub">每人一条专属链接；禁用/换 token/删除即时生效，被分享人无感知原因（统一 404）</div>
<table><tr><th>备注</th><th>链接</th><th>状态</th><th>操作</th></tr>{linkrows}</table>
<form method="post" action="/admin/links/create" style="margin-top:10px">
<input type="hidden" name="csrf" value="{csrf}">
<div class="row"><input type="text" name="label" placeholder="备注，如：张三" maxlength="32">
<button type="submit">新建链接</button></div>
</form></div>

<div class="card"><h2>上游订阅</h2><div class="sub">转发目标（含账号密码），只走 Tailscale 隧道</div>
<form method="post" action="/admin/upstream">
<input type="hidden" name="csrf" value="{csrf}">
<div class="row"><input type="text" id="upstream_url" name="upstream_url" value="{upstream_url}" spellcheck="false"></div>
<div class="row" style="margin-top:8px"><input type="text" name="public_base"
value="{public_base}" placeholder="公网域名（选填，如 https://sub.example.com，用于拼接分享链接）"
spellcheck="false"></div>
<div class="row" style="margin-top:10px"><button type="submit">保存</button>
<button type="button" class="ghost" onclick="probe()">测试连通</button>
<span id="probe" class="muted"></span></div>
<div class="sub">「测试连通」测的是输入框里当前填的地址；确认没问题后再点「保存」。</div></form></div>

<div class="card"><h2>访问记录</h2><div class="sub">最近 {n} 次订阅拉取（内存记录，重启清空）</div>
<table><tr><th>时间</th><th>来源 IP</th><th>链接</th><th>状态</th><th>大小</th></tr>{logrows}</table></div>

<div class="card"><h2>修改管理密码</h2>
<form method="post" action="/admin/password">
<input type="hidden" name="csrf" value="{csrf}">
<div class="row"><input type="password" name="new_password" placeholder="新管理密码（≥8 位）">
<button type="submit">修改</button></div></form></div>
</div>
<script>
function probe(){var el=document.getElementById('probe');el.textContent='测试中…';
var u=document.getElementById('upstream_url').value;
fetch('/admin/api/probe',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
body:'csrf={csrf}&upstream_url='+encodeURIComponent(u)}).then(r=>r.json()).then(j=>{
el.className=j.ok?'ok':'bad';el.textContent=j.ok?('连通正常，'+j.ms+'ms，'+j.bytes+'字节'):('失败：'+j.error);
}).catch(e=>{el.className='bad';el.textContent='请求失败';});}
</script></body></html>"""


def _render(tpl, **kw):
    """只替换已知占位符，CSS 里的大括号不受影响。"""
    for k, v in kw.items():
        tpl = tpl.replace("{" + k + "}", str(v))
    return tpl


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "subwrap-admin/1.0"

    # ---------- 工具 ----------
    def _send_html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, to):
        self.send_response(303)
        self.send_header("Location", to)
        self.end_headers()

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 1024 * 1024:
            raise ValueError("form too large")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def _check_csrf(self, form):
        return hmac.compare_digest(form.get("csrf", ""), _csrf_token())

    def _set_session(self):
        self.send_response(303)
        self.send_header("Location", "/admin")
        self.send_header("Set-Cookie",
                         f"sid={_session_token()}; Path=/admin; HttpOnly; SameSite=Lax")
        self.end_headers()

    # ---------- 路由 ----------
    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            # 裸地址直接跳登录页，符合常规网站习惯
            self._redirect("/admin")
            return
        if not admin_enabled():
            self._send_html(200, _render(LOGIN_PAGE,
                csrf="", err="管理界面未启用：请在 .env 设置 ADMIN_PASSWORD 后重启容器。"))
            return
        if path in ("/admin", "/admin/"):
            if not _is_authed(self):
                self._send_html(200, _render(LOGIN_PAGE, csrf=_csrf_token(), err=""))
                return
            self._render_dash()
            return
        m = re.fullmatch(r"/admin/qr/([0-9a-f]{12})(/png)?", path)
        if m:
            if not _is_authed(self):
                self._redirect("/admin")
                return
            self._render_qr(m.group(1), as_png=bool(m.group(2)))
            return
        self._send_html(404, "not found")

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            form = self._read_form()
        except ValueError:
            self._send_html(413, "form too large")
            return
        if path == "/admin/login":
            if not admin_enabled():
                self._redirect("/admin")
                return
            cfg = get_config()
            ok = hmac.compare_digest(
                _hash_pw(form.get("password", ""), cfg["admin_salt"]), cfg["admin_pw"])
            if ok and self._check_csrf(form):
                self._set_session()
            else:
                self._send_html(200, _render(LOGIN_PAGE, csrf=_csrf_token(),
                                                       err="密码错误。"))
            return
        if not _is_authed(self):
            self._redirect("/admin")
            return
        if not self._check_csrf(form):
            self._send_html(403, "csrf check failed")
            return
        if path == "/admin/logout":
            global _server_secret
            _server_secret = secrets.token_bytes(32)  # 轮换密钥，旧会话全部失效
            self.send_response(303)
            self.send_header("Location", "/admin")
            self.send_header("Set-Cookie", "sid=; Path=/admin; Max-Age=0")
            self.end_headers()
            return
        if path == "/admin/links/create":
            label = form.get("label", "").strip()[:32] or "未命名"
            with _cfg_lock:
                _config.setdefault("links", []).append(_new_link(label))
                _save_config(dict(_config))
            log.info("管理操作：新建分享链接（%s）", label)
            self._redirect("/admin")
            return
        m = re.fullmatch(r"/admin/links/([0-9a-f]{12})/(toggle|regen|delete)", path)
        if m:
            lid, action = m.group(1), m.group(2)
            with _cfg_lock:
                links = _config.setdefault("links", [])
                link = next((l for l in links if l.get("id") == lid), None)
                if link:
                    if action == "toggle":
                        link["enabled"] = not link.get("enabled", True)
                        log.info("管理操作：链接 %s 已%s", link["label"],
                                 "禁用" if not link["enabled"] else "启用")
                    elif action == "regen":
                        link["token"] = _new_token()
                        log.info("管理操作：链接 %s 已重新生成 token", link["label"])
                    elif action == "delete":
                        links.remove(link)
                        log.info("管理操作：链接 %s 已删除", link["label"])
                _save_config(dict(_config))
            self._redirect("/admin")
            return
        if path == "/admin/upstream":
            url = form.get("upstream_url", "").strip()
            base = form.get("public_base", "").strip().rstrip("/")
            if url and urlparse(url).scheme in ("http", "https"):
                update_config(upstream_url=url, public_base=base)
                log.info("管理操作：上游地址已更新")
            self._redirect("/admin")
            return
        if path == "/admin/password":
            pw = form.get("new_password", "")
            if len(pw) >= 8:
                salt = secrets.token_hex(8)
                update_config(admin_salt=salt, admin_pw=_hash_pw(pw, salt))
                log.info("管理操作：管理密码已修改")
            self._redirect("/admin")
            return
        if path == "/admin/api/probe":
            test_url = form.get("upstream_url", "").strip()
            if test_url and urlparse(test_url).scheme not in ("http", "https"):
                self._send_json({"ok": False, "error": "URL 须以 http:// 或 https:// 开头"})
                return
            try:
                status, _ct, body, ms = fetch_upstream(timeout=10, url=test_url or None)
                self._send_json({"ok": status == 200, "ms": ms,
                                 "bytes": len(body),
                                 "error": "" if status == 200 else f"HTTP {status}"})
            except Exception as e:  # noqa: BLE001
                self._send_json({"ok": False, "error": f"{type(e).__name__}"})
            return
        self._send_html(404, "not found")

    def _render_qr(self, lid, as_png=False):
        cfg = get_config()
        link = next((l for l in cfg.get("links", []) if l.get("id") == lid), None)
        if not link:
            self._send_html(404, "not found")
            return
        base = (cfg.get("public_base") or "").rstrip("/")
        url = (base + "/s/" + link["token"]) if base else None
        if as_png:
            if not _QR_OK or not url:
                self._send_html(404, "not found")
                return
            try:
                png = _qr_png_bytes(url)
            except Exception:  # noqa: BLE001
                log.exception("二维码生成失败")
                self._send_html(500, "qr failed")
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(png)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(png)
            return
        if not _QR_OK:
            body = '<div class="card"><p class="bad">二维码库缺失（qrcodegen.py），请检查部署文件。</p></div>'
        elif not url:
            body = ('<div class="card"><p class="bad">还没填写「公网域名」，二维码无法编码完整地址。</p>'
                    '<p class="sub">请先在管理页「上游订阅」里填写公网域名（如 https://sub.example.com），再回来生成二维码。</p></div>')
        else:
            body = (f'<div class="card" style="text-align:center">'
                    f'<h2 style="text-align:left">「{html.escape(link.get("label", ""))}」的二维码</h2>'
                    f'<img src="/admin/qr/{lid}/png" style="width:min(72vw,340px);image-rendering:pixelated" alt="qrcode">'
                    f'<p><span class="link">{html.escape(url)}</span></p>'
                    f'<p class="sub">长按 / 右键把图片保存下来发给对方，对方用相机或 Clash 类 App 扫码即可导入。</p></div>')
        page = ("<!doctype html><html><head><meta charset=utf-8><meta name=viewport "
                "content='width=device-width,initial-scale=1'><title>二维码</title><style>"
                "body{background:#1a1a1a;color:#ddd;font-family:sans-serif;margin:0;padding:16px}"
                ".wrap{max-width:560px;margin:0 auto}.card{background:#222;border:1px solid #333;"
                "border-radius:10px;padding:16px;margin-bottom:14px}h2{font-size:16px;margin:0 0 10px}"
                ".sub{color:#999;font-size:13px;line-height:1.7}.bad{color:#ff7b7b}"
                ".link{font-family:monospace;background:#2a2a2a;padding:8px 10px;border-radius:6px;"
                "word-break:break-all;display:inline-block}a{color:#7fb3ff}</style></head>"
                f'<body><div class="wrap"><p><a href="/admin">← 返回管理页</a></p>{body}</div></body></html>')
        self._send_html(200, page)

    def _render_dash(self):
        cfg = get_config()
        base = (cfg.get("public_base") or "").rstrip("/")
        csrf = _csrf_token()
        err = parse_qs(urlparse(self.path).query).get("err", [""])[0]
        linkrows = ""
        for l in cfg.get("links", []):
            lid = l["id"]
            url = (base + "/s/" + l["token"]) if base else ("/s/" + l["token"])
            status = ('<span class="ok">启用中</span>' if l.get("enabled")
                      else '<span class="bad">已禁用</span>')
            toggle_label = "禁用" if l.get("enabled") else "启用"
            linkrows += (
                f'<tr><td>{html.escape(l.get("label", ""))}</td>'
                f'<td><span class="link">{html.escape(url)}</span> '
                f'<button class="ghost" style="padding:4px 8px" '
                f'onclick="navigator.clipboard.writeText(\'{html.escape(url)}\')">复制</button></td>'
                f'<td>{status}<br><span class="muted">{html.escape(l.get("created", ""))}</span></td>'
                f'<td><form method="post" action="/admin/links/{lid}/toggle" style="display:inline">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button class="ghost" style="padding:4px 8px" type="submit">{toggle_label}</button></form> '
                f'<a href="/admin/qr/{lid}" target="_blank" style="text-decoration:none">'
                f'<button class="ghost" style="padding:4px 8px" type="button">二维码</button></a> '
                f'<form method="post" action="/admin/links/{lid}/regen" style="display:inline" '
                f'onsubmit="return confirm(\'换 token 后此人旧链接立即失效，继续？\')">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button class="ghost" style="padding:4px 8px" type="submit">换 token</button></form> '
                f'<form method="post" action="/admin/links/{lid}/delete" style="display:inline" '
                f'onsubmit="return confirm(\'删除后此链接永久失效，继续？\')">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<button class="danger" style="padding:4px 8px" type="submit">删除</button></form></td></tr>'
            )
        if not linkrows:
            linkrows = '<tr><td colspan="4" class="muted">暂无链接，在下方新建一条</td></tr>'
        rows = "".join(
            f"<tr><td>{html.escape(r['t'])}</td><td>{html.escape(r['ip'])}</td>"
            f"<td>{html.escape(r.get('label', ''))}</td>"
            f"<td>{r['status']}</td><td>{r['bytes']}</td></tr>"
            for r in list(_access_log)
        ) or '<tr><td colspan="5" class="muted">暂无记录</td></tr>'
        self._send_html(200, _render(DASH_PAGE,
            csrf=csrf,
            err=html.escape(err),
            linkrows=linkrows,
            upstream_url=html.escape(cfg["upstream_url"]),
            public_base=html.escape(cfg.get("public_base") or ""),
            n=len(_access_log),
            logrows=rows,
        ))

    def log_message(self, fmt, *args):
        log.info("admin %s %s", self.command, urlparse(self.path).path)


def main():
    load_config()
    cfg = get_config()
    if not cfg.get("links") or not cfg.get("upstream_url"):
        raise SystemExit("FATAL: 链接列表为空或 UPSTREAM_URL 未设置（.env），拒绝启动。")
    if not admin_enabled():
        log.warning("ADMIN_PASSWORD 未设置，管理界面已禁用（仅转发服务运行）。")
    t1 = threading.Thread(
        target=ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), ForwardHandler).serve_forever,
        daemon=True)
    t1.start()
    log.info("forward :%d, admin :%d", LISTEN_PORT, ADMIN_PORT)
    ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), AdminHandler).serve_forever()


if __name__ == "__main__":
    main()
