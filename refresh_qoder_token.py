#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""refresh_qoder_token.py —— 在你自己的 Windows 电脑上运行，从 Qoder CN 桌面端登录态导出签到用的 GitHub Secret。

导出两项：
  QODER_TOKEN      桌面端 auth.v1.dat 解出的访问令牌（到期后回桌面端重新登录再跑一次）
  QODER_BASE_URL   令牌签发端对应的 API 域（与默认值一致时不写，云端用默认即可）

用法：
    python refresh_qoder_token.py                        # 打印令牌 + 手动配置指引
    python refresh_qoder_token.py --gh-repo OWNER/REPO   # 有 gh CLI 时直接写入 Secret
    python refresh_qoder_token.py --debug                # 打印调试信息（令牌已脱敏）

原理（解密链参考 auto-signin-kit（MIT）qoder 域 auth 的实现）：
  1. 扫描 %APPDATA%\\com.qodercn.app*，按最近修改排序取有 auth.v1.dat 的目录；
  2. "Local State" 里 os_crypt.encrypted_key 经 DPAPI（当前用户）解出对称密钥；
  3. auth.v1.dat 为 v10 前缀 + 12 字节 nonce + AES-256-GCM 密文（含 16 字节 tag）；
  4. 解出的会话 JSON 里有 token / expiresAt / authenticationContext（推导 API 域）。

安全约定：
  - 凭证只在本进程内存里，不写文件；
  - 写 Secret 时明文只经 stdin 交给 gh，不出现在命令行与进程列表中；
  - 调试日志里的令牌只保留前 6 位。
"""

import base64
import ctypes
import ctypes.wintypes as wt
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

AUTH_DIR_GLOB = "com.qodercn.app*"
AUTH_FILE = "auth.v1.dat"
LOCAL_STATE_FILE = "Local State"

#: 登录态签发主域 → API 域（CN 版默认；解不出时脚本会提示手动配置）。
API_BASE_BY_ISSUER = {
    "qoder.com": "https://openapi.qoder.sh",
    "qoder.com.cn": "https://openapi.qoder.com.cn",
}
DEFAULT_BASE_URL = "https://openapi.qoder.com.cn"

DEBUG = False


class DecryptError(Exception):
    """凭据解锁失败。"""


def redact(text):
    """长串（token 类）只保留前 6 位。"""
    return re.sub(r"[A-Za-z0-9._~+/=-]{24,}", lambda m: m.group(0)[:6] + "***", str(text))


def dbg(msg):
    if DEBUG:
        print("  [debug] %s" % redact(msg), flush=True)


# ---------------------------------------------------------------- DPAPI / AES-GCM

class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


class _AeadInfo(ctypes.Structure):  # BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    _fields_ = [
        ("cbSize", ctypes.c_ulong), ("dwInfoVersion", ctypes.c_ulong),
        ("pbNonce", ctypes.POINTER(ctypes.c_ubyte)), ("cbNonce", ctypes.c_ulong),
        ("pbAuthData", ctypes.POINTER(ctypes.c_ubyte)), ("cbAuthData", ctypes.c_ulong),
        ("pbTag", ctypes.POINTER(ctypes.c_ubyte)), ("cbTag", ctypes.c_ulong),
        ("pbMacContext", ctypes.POINTER(ctypes.c_ubyte)), ("cbMacContext", ctypes.c_ulong),
        ("pbAAD", ctypes.POINTER(ctypes.c_ubyte)), ("cbAAD", ctypes.c_ulonglong),
        ("cbData", ctypes.c_ulonglong), ("dwFlags", ctypes.c_ulong),
    ]


def dpapi_unprotect(data):
    """DPAPI 解密（只限启动进程的同一 Windows 用户）。"""
    src = _DataBlob(len(data), ctypes.create_string_buffer(data, len(data)))
    dst = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(src), None, None, None, None, 0x01, ctypes.byref(dst)
    ):
        raise DecryptError("DPAPI 解不开密钥（%s）——需要同一 Windows 用户且已登录桌面"
                           % ctypes.WinError())
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(dst.pbData)


def decrypt_gcm(key, nonce, blob):
    """AES-GCM：优先 cryptography，缺库时退回 Windows 自带 CNG。"""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return _decrypt_gcm_cng(key, nonce, blob)
    try:
        return AESGCM(key).decrypt(nonce, blob, None)
    except Exception as exc:
        raise DecryptError("AES-GCM 认证失败（%s）" % type(exc).__name__) from None


def _decrypt_gcm_cng(key, nonce, blob):
    bcrypt = ctypes.WinDLL("bcrypt.dll")
    ct, tag = blob[:-16], blob[-16:]

    def chk(res, what):
        if res != 0:
            raise DecryptError("CNG %s 失败 NTSTATUS=0x%08x" % (what, res & 0xFFFFFFFF))

    h_alg = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    try:
        chk(bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0), "OpenAlg")
        mode = "ChainingModeGCM"
        chk(bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, (len(mode) + 1) * 2, 0),
            "SetProperty")
        kbuf = ctypes.create_string_buffer(key, len(key))
        chk(bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0,
                                              kbuf, len(key), 0), "GenKey")
        nbuf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
        tbuf = (ctypes.c_ubyte * len(tag)).from_buffer_copy(tag)
        info = _AeadInfo()
        info.cbSize = ctypes.sizeof(_AeadInfo)
        info.dwInfoVersion = 1
        info.pbNonce = ctypes.cast(nbuf, ctypes.POINTER(ctypes.c_ubyte))
        info.cbNonce = len(nonce)
        info.pbTag = ctypes.cast(tbuf, ctypes.POINTER(ctypes.c_ubyte))
        info.cbTag = len(tag)
        ibuf = ctypes.create_string_buffer(ct, len(ct))
        obuf = ctypes.create_string_buffer(len(ct))
        done = ctypes.c_ulong()
        chk(bcrypt.BCryptDecrypt(h_key, ibuf, len(ct), ctypes.byref(info), None, 0,
                                 obuf, len(ct), ctypes.byref(done), 0), "Decrypt")
        return obuf.raw[:done.value]
    finally:
        if h_key:
            bcrypt.BCryptDestroyKey(h_key)
        if h_alg:
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


# ---------------------------------------------------------------- 登录态读取

def find_auth_dirs():
    """扫描 Qoder 数据目录（QODER_AUTH_DIR 覆盖；多目录按最近修改排序）。"""
    override = os.environ.get("QODER_AUTH_DIR")
    if override:
        return [Path(override).expanduser()]
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    hits = [Path(p) for p in glob.glob(str(appdata / AUTH_DIR_GLOB))]
    hits.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return hits


def read_session(root):
    """解锁并读出目录里的会话 JSON；读到半截（客户端正在重写）短暂重试。"""
    last = None
    for _ in range(3):
        try:
            return _read_session_once(root)
        except (ValueError, OSError, DecryptError) as exc:
            last = exc
            time.sleep(0.25)
    raise DecryptError("登录态读取失败：%s: %s" % (type(last).__name__, last))


def _read_session_once(root):
    raw = (root / AUTH_FILE).read_bytes()
    if raw[:3] != b"v10":
        raise DecryptError("%s 格式未知（%r）" % (AUTH_FILE, raw[:3]))
    if len(raw) < 3 + 12 + 16 + 2:
        raise DecryptError("%s 过短，可能正被客户端改写" % AUTH_FILE)
    state = json.loads((root / LOCAL_STATE_FILE).read_text(encoding="utf-8"))
    crypt = state.get("os_crypt") if isinstance(state, dict) else None
    if not isinstance(crypt, dict):
        raise DecryptError("%s 缺少 os_crypt 配置" % LOCAL_STATE_FILE)
    key_blob = base64.b64decode(crypt.get("encrypted_key") or "")
    if key_blob[:5] != b"DPAPI":
        raise DecryptError("%s 的 os_crypt 结构变了" % LOCAL_STATE_FILE)
    key = dpapi_unprotect(key_blob[5:])
    plain = decrypt_gcm(key, raw[3:15], raw[15:])
    sess = json.loads(plain.decode("utf-8"))
    if not isinstance(sess, dict) or not str(sess.get("token") or "").strip():
        raise DecryptError("解密成功但会话里没有 token")
    return sess


def load_session():
    """从第一个能读出令牌的目录取会话；全失败时报带路径的诊断。"""
    dirs = find_auth_dirs()
    if not dirs:
        raise SystemExit("没找到 %%APPDATA%%\\%s，请先安装并登录 Qoder CN 桌面端" % AUTH_DIR_GLOB)
    errors = []
    for root in dirs:
        if not (root / AUTH_FILE).is_file():
            errors.append("%s: 未登录" % root.name)
            continue
        try:
            sess = read_session(root)
        except (DecryptError, OSError, ValueError) as exc:
            errors.append("%s: %s" % (root.name, exc))
            continue
        dbg("登录态目录 %s" % root)
        return sess
    raise SystemExit("Qoder 登录态读取失败（%s），请重新登录桌面端后重试" % "；".join(errors))


def token_expired(sess):
    """expiresAt（ISO8601，无时区视为 UTC）已过返回 True；缺字段视为未过期。"""
    value = sess.get("expiresAt")
    if not value:
        return False
    try:
        moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment <= datetime.now(timezone.utc)


def detect_api_base(sess):
    """从 authenticationContext 推导 API 域：优先取 openapi.* 域，再按主域映射。"""
    ctx = sess.get("authenticationContext")
    if isinstance(ctx, str):
        try:
            ctx = json.loads(ctx)
        except ValueError:
            return None
    if not isinstance(ctx, list):
        return None
    hosts = [str(x).split("//", 1)[-1].rstrip("/") for x in ctx
             if isinstance(x, str) and "//" in x]
    for host in hosts:
        if host.startswith("openapi."):
            return "https://" + host
    for host in hosts:
        if host in API_BASE_BY_ISSUER:
            return API_BASE_BY_ISSUER[host]
    return None


# ---------------------------------------------------------------- Secret 写入

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
    args = sys.argv[1:]
    if "--debug" in args:
        DEBUG = True
        args = [a for a in args if a != "--debug"]
    repo = None
    if "--gh-repo" in args:
        i = args.index("--gh-repo")
        if i + 1 >= len(args):
            raise SystemExit("--gh-repo 需要跟上 OWNER/REPO")
        repo = args[i + 1]
        args = args[:i] + args[i + 2:]
    if args:
        raise SystemExit("未知参数：%s（支持 --gh-repo OWNER/REPO / --debug）" % " ".join(args))

    if sys.platform != "win32":
        raise SystemExit("本脚本依赖 Windows DPAPI，只能在装有 Qoder CN 桌面端的 Windows 电脑上运行")

    sess = load_session()
    token = str(sess["token"]).strip()
    base_url = detect_api_base(sess) or DEFAULT_BASE_URL
    dbg("authenticationContext -> %s" % base_url)

    if token_expired(sess):
        raise SystemExit("令牌已过期（expiresAt=%s），请打开 Qoder CN 桌面端重新登录后再跑本脚本"
                         % sess.get("expiresAt"))

    print("Qoder CN 登录态读取成功（令牌有效期至 %s）" % (sess.get("expiresAt") or "未知"))

    if repo:
        if shutil.which("gh") is None:
            raise SystemExit("未找到 gh CLI，请安装后登录（gh auth login），或按下方指引手动配置 Secret")
        set_gh_secret(repo, "QODER_TOKEN", token)
        if base_url != DEFAULT_BASE_URL:
            set_gh_secret(repo, "QODER_BASE_URL", base_url)
            print("已写入 GitHub Secret QODER_BASE_URL（%s，与默认端点不同）" % base_url)
        print("完成：云端 wb_auto.py 会自动读取这两个 Secret")
        return 0

    print("")
    print("手动配置（Repository → Settings → Secrets and variables → Actions → New repository secret）：")
    print("  QODER_TOKEN      = %s" % token)
    if base_url != DEFAULT_BASE_URL:
        print("  QODER_BASE_URL   = %s" % base_url)
    else:
        print("  QODER_BASE_URL   无需配置（云端默认 %s）" % DEFAULT_BASE_URL)
    print("提示：令牌到期后（云端报 HTTP 401），回到桌面端重新登录并重跑本脚本。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
