#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""refresh_trae_token.py —— 在你自己的电脑上运行，浏览器登录 Trae 国内版，导出签到用的 GitHub Secret。

导出三项：
  TRAE_REFRESH_TOKEN  OAuth 回调拿到的 refreshToken（换过一次 token 后取服务端下发的最新值）
  TRAE_DEVICE_ID      签到设备号：优先本机 Trae 客户端的 Aha 纯数字设备号（12~20 位），取不到再退回
  TRAE_USER_ID        Trae 用户 ID

用法：
    python refresh_trae_token.py                       # 打印凭证 + 手动配置指引
    python refresh_trae_token.py --gh-repo OWNER/REPO  # 有 gh CLI 时直接写入 Secret
                                                       # 没有 gh 则打印凭证 + 手动配置指引
    python refresh_trae_token.py --debug               # 打印调试信息（token 已脱敏）

流程（参考 auto-checkin 的 login.py / checkin.py）：
  1. 本地起 127.0.0.1:18080 回调服务，浏览器打开 trae.cn 授权页，手机号 + 验证码登录；
  2. 登录后浏览器跳回本地回调，URL query 里带 refreshToken；
  3. 用 refreshToken 调 ExchangeToken 校验，拿 BoundDeviceID / 用户 ID / 最新 refreshToken；
  4. 从 storage.json 读客户端真实设备号；
  5. 写入 Secret 或打印。

安全约定：
  - 凭证只在本进程内存里，不写文件；
  - 写 Secret 时明文只经 stdin 交给 gh，不出现在命令行与进程列表中；
  - 调试日志里的 token 只保留前 6 位。
"""

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

CALLBACK_PORT = 18080
LOGIN_TIMEOUT = 300
TRAE_AUTH = "https://api.trae.com.cn"
TRAE_CLIENT_ID = "en1oxy7wnw8j9n"
TRAE_UA = "Trae/0.1.43"
AHA_DEVICE_RE = re.compile(r"iCubeAuthInfo://icube-dc:(\d{12,20})(?!\d)")
TRAE_CLIENT_DIRS = ("TRAE SOLO CN", "Trae CN", "Trae")

DEBUG = False


def redact(text):
    """长串（token 类）只保留前 6 位。"""
    return re.sub(r"[A-Za-z0-9._~+/=-]{24,}", lambda m: m.group(0)[:6] + "***", str(text))


def dbg(msg):
    if DEBUG:
        print("  [debug] %s" % redact(msg), flush=True)


def http_post(url, body, timeout=30):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": TRAE_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        status = e.code
    dbg("POST %s -> %s %s" % (url, status, raw[:300]))
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {"_raw": raw[:300]}
    return status, parsed if isinstance(parsed, dict) else {"_raw": raw[:300]}


# ---------------------------------------------------------------------------
# 浏览器登录
# ---------------------------------------------------------------------------
class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/authorize"):
            self.send_response(404)
            self.end_headers()
            return
        query = urllib.parse.parse_qs(parsed.query)
        self.server.auth_result = {k: (v[0] if v else "") for k, v in query.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write((
            "<html><body style='font-family:sans-serif;text-align:center;padding:40px'>"
            "<h2>Trae 登录成功</h2><p>已捕获登录凭证，可以关闭此页面回到命令行。</p>"
            "</body></html>").encode("utf-8"))

    def log_message(self, fmt, *args):
        if DEBUG:
            print("  [http] %s" % redact(fmt % args))


def wait_for_callback(server, timeout):
    server.auth_result = None
    server.timeout = 1
    start = time.time()
    while time.time() - start < timeout:
        server.handle_request()
        if server.auth_result:
            return server.auth_result
    return None


def browser_login():
    """打开授权页并等待回调，返回回调 query（dict）。"""
    try:
        server = HTTPServer(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
    except OSError:
        raise SystemExit("本地端口 %d 被占用，请关闭占用它的程序后重试" % CALLBACK_PORT)

    params = {
        "client_id": TRAE_CLIENT_ID,
        "auth_from": "solo",
        "login_channel": "native_ide",
        "plugin_version": "2.3.62834",
        "auth_callback_url": "http://127.0.0.1:%d/authorize" % CALLBACK_PORT,
        "x_app_version": "0.1.43",
        "x_app_type": "stable",
        "device_id": secrets.token_hex(16),
        "machine_id": secrets.token_hex(16),
    }
    login_url = "https://www.trae.cn/authorization?" + urllib.parse.urlencode(params)
    print("即将打开浏览器，请完成 Trae 账号登录（手机号 + 验证码）。")
    print("浏览器没自动打开的话，手动访问：\n  %s" % login_url)
    print("等待登录回调（最多 %d 分钟）…" % (LOGIN_TIMEOUT // 60))
    threading.Thread(target=lambda: webbrowser.open(login_url), daemon=True).start()
    try:
        result = wait_for_callback(server, LOGIN_TIMEOUT)
    finally:
        server.server_close()
    if not result:
        raise SystemExit("超时：%d 分钟内未收到登录回调，请重试" % (LOGIN_TIMEOUT // 60))
    dbg("回调参数: %s" % result)
    return result


def _json_param(raw):
    if not raw:
        return {}
    try:
        value = json.loads(urllib.parse.unquote(raw))
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def _user_id_from_jwt(token):
    """从 Cloud-IDE-JWT 的 payload.data.id 取用户 ID。"""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        obj = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return ""
    if not isinstance(obj, dict):
        return ""
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    uid = data.get("id") or data.get("UserID") or obj.get("UserID") or obj.get("userId")
    return str(uid) if uid else ""


def exchange_token(refresh_token, user_id):
    """refreshToken 换 accessToken，校验凭证有效，并取服务端下发的最新信息。"""
    status, body = http_post(TRAE_AUTH + "/cloudide/api/v3/trae/oauth/ExchangeToken", {
        "ClientID": TRAE_CLIENT_ID,
        "RefreshToken": refresh_token,
        "ClientSecret": "-",
        "UserID": user_id or "",
    })
    result = body.get("Result") or body.get("data") or {}
    access = result.get("Token") or result.get("AccessToken")
    if not access:
        err = (body.get("ResponseMetadata") or {}).get("Error") or {}
        raise SystemExit("ExchangeToken 失败（HTTP %s %s），请重试登录"
                         % (status, err.get("Code") or err.get("Message") or ""))
    return {
        "access": access,
        "refresh": result.get("RefreshToken") or refresh_token,
        "bound_device": result.get("BoundDeviceID") or "",
        "user_id": user_id or result.get("UserID") or _user_id_from_jwt(access),
    }


# ---------------------------------------------------------------------------
# 设备号
# ---------------------------------------------------------------------------
def resolve_device_id(fallback):
    """优先 Trae 客户端 storage.json 里的 Aha 纯数字设备号（12~20 位，签到会校验设备，
    UUID / hex 设备号易被风控返回 9074）；其次旧版 machineid；最后服务端 BoundDeviceID。
    返回 (设备号, 来源说明)。"""
    roaming = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
    for name in TRAE_CLIENT_DIRS:
        storage = os.path.join(roaming, name, "User", "globalStorage", "storage.json")
        try:
            with open(storage, "r", encoding="utf-8", errors="replace") as f:
                m = AHA_DEVICE_RE.search(f.read())
        except OSError:
            continue
        if m:
            return m.group(1), "本机客户端 %s（Aha 设备号）" % name
    for name in TRAE_CLIENT_DIRS:
        path = os.path.join(roaming, name, "machineid")
        try:
            with open(path, "r", encoding="utf-8") as f:
                value = f.read().strip()
        except OSError:
            continue
        if value:
            return value, "本机客户端 %s 的 machineid（旧版 UUID，可能触发 9074）" % name
    return fallback, "服务端 BoundDeviceID（未找到本机 Trae 客户端，可能触发 9074）"


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def normalize_repo(value):
    repo = value.strip().rstrip("/")
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if repo.count("/") != 1 or not all(repo.split("/")):
        raise SystemExit("仓库格式应为 OWNER/REPO（例如 jian1098/workbuddy_auto_checkin），收到：%s" % value)
    return repo


def set_gh_secret(repo, name, value):
    proc = subprocess.run(
        ["gh", "secret", "set", name, "--repo", repo, "--body", "-"],
        input=value.encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise SystemExit("写入 GitHub Secret %s 失败：%s" % (name, proc.stderr.decode("utf-8", "replace")))
    print("已写入 GitHub Secret %s（仓库 %s）" % (name, repo))


def main():
    global DEBUG
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = sys.argv[1:]
    DEBUG = "--debug" in args
    gh_repo = None
    if "--gh-repo" in args:
        idx = args.index("--gh-repo")
        if idx + 1 >= len(args):
            raise SystemExit("--gh-repo 后面要跟 OWNER/REPO")
        gh_repo = normalize_repo(args[idx + 1])

    callback = browser_login()
    refresh_token = callback.get("refreshToken") or callback.get("refresh_token") or callback.get("data")
    if not refresh_token:
        raise SystemExit("登录回调里没有 refreshToken，请重试（加 --debug 查看回调参数）")
    user_info = _json_param(callback.get("userInfo"))
    user_jwt = _json_param(callback.get("userJwt"))
    user_id = user_info.get("UserID") or user_jwt.get("UserID") or ""

    print("登录成功，正在用 refreshToken 换 token 校验…")
    info = exchange_token(refresh_token, user_id)
    device_id, device_source = resolve_device_id(info["bound_device"])
    if not device_id:
        raise SystemExit("拿不到设备号：本机没有 Trae 客户端，服务端也没返回 BoundDeviceID")
    print("设备号来源：%s" % device_source)

    values = [
        ("TRAE_REFRESH_TOKEN", info["refresh"]),
        ("TRAE_DEVICE_ID", device_id),
        ("TRAE_USER_ID", info["user_id"]),
    ]

    if gh_repo and shutil.which("gh") is not None:
        for name, value in values:
            if value:
                set_gh_secret(gh_repo, name, value)
            else:
                print("跳过 %s（未取到值）" % name)
        return

    if gh_repo:
        print("\n[提示] 未检测到 GitHub CLI（gh），无法自动写入 Secret。")
    print("\n请手动配置：")
    if gh_repo:
        print("  打开 https://github.com/%s/settings/secrets/actions/new" % gh_repo)
    else:
        print("  你仓库的 Settings → Secrets and variables → Actions → New repository secret")
    print("  按下面的 Name / 值逐个新建（值为空的那项可以不建）")
    for name, value in values:
        print("\n----- %s -----" % name)
        print(value or "（未取到）")
    print("----- 结束 -----")
    print("\n[安全提醒] refreshToken 等同登录态，请勿粘贴到聊天、日志或任何第三方站点。", file=sys.stderr)


def _pause_if_frozen():
    """打包成 exe 被双击运行时，结束前停一下，让用户来得及复制输出。"""
    if not getattr(sys, "frozen", False):
        return
    try:
        input("\n按回车键退出…")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已取消。")
    finally:
        _pause_if_frozen()
