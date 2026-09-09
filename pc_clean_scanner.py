#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
电脑清理扫描器 v2 (PC Clean Scanner)
====================================
只扫描、只出报告，绝不删除任何文件。

v2 新增：
  · 针对性清理点：Docker/WSL 虚拟磁盘、AI 工具缓存(.codex/.ollama)、项目依赖目录(node_modules/venv/target)
  · 重复文件检测（按内容哈希，找出重复下载的大文件）
  · 历史对比：与上次扫描比较，看清理效果/空间变化
  · HTML 报告：列排序、关键字筛选、勾选项目导出"移入回收站"清理脚本
  · 无窗口模式：双击 exe 不弹黑框，进度窗口 + 日志落盘
  · 手机查看：扫描完可启动局域网服务，手机扫码直接看报告

用法:
    python pc_clean_scanner.py              快速扫描(用户目录 + 常见缓存/下载 + 程序清单)
    python pc_clean_scanner.py --full       全盘扫描(所有本地硬盘)
    python pc_clean_scanner.py --drives C,D 只扫描指定盘符
    python pc_clean_scanner.py --min-size 200MB    大文件门槛(默认 100MB)
    python pc_clean_scanner.py --dup-min 50MB      重复文件门槛(默认 10MB)
    python pc_clean_scanner.py --no-duplicates     跳过重复文件检测
    python pc_clean_scanner.py --no-open    结束后不自动打开报告
    python pc_clean_scanner.py --gui        强制图形界面模式
"""
import os
import sys
import csv
import json
import re
import time
import glob
import ctypes
import string
import argparse
import hashlib
import socket
import threading
import queue as queue_mod
from datetime import datetime
from urllib.parse import quote

IS_WIN = (os.name == "nt")
if IS_WIN:
    import winreg

# 无窗口 exe 下 sys.stdout 为 None，print 会报错，统一走 log()
if IS_WIN:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if getattr(sys, "frozen", False):  # PyInstaller 打包后，跟随 exe 所在目录
    SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "扫描设置.json")
DEFAULT_REPORT_DIR = os.path.join(SCRIPT_DIR, "scan_reports")
LOG_FILE = os.path.join(SCRIPT_DIR, "扫描日志.log")

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
APP_VERSION = "2.2.7"
GITHUB_REPO = "UltraSkyShow321/pc-clean-scanner"
RELEASES_URL = "https://github.com/%s/releases" % GITHUB_REPO
LEVEL_INFO = {
    "A": "放心清理 —— 缓存/临时文件，删除不影响软件功能",
    "B": "确认后清理 —— 可能含个人内容或可重新下载的资源，删除前先看一眼",
    "C": "谨慎/仅了解 —— 系统关键文件或个人数据，本工具只统计体积，不建议直接删",
}


# ---------------------------------------------------------------- 日志
class Log:
    def __init__(self, path=None):
        self.path = path
        self._f = None
        if path:
            try:
                self._f = open(path, "a", encoding="utf-8")
            except OSError:
                self._f = None

    def __call__(self, msg):
        line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
        if sys.stdout:
            try:
                print(line, flush=True)
            except Exception:
                pass
        if self._f:
            try:
                self._f.write(line + "\n")
                self._f.flush()
            except Exception:
                pass

    def close(self):
        if self._f:
            try:
                self._f.close()
            except Exception:
                pass


LOG = Log(LOG_FILE)


# ---------------------------------------------------------------- 进度回调
# GUI 扫描时注入 hook：_prog(stage, pct, detail)
# stage: 1~7 阶段号；pct: 本阶段内进度 0~1（<0 表示不定进度）；detail: 实时细节文本
STAGE_NAMES = ["磁盘与程序", "清理点统计", "依赖目录", "大文件搜索",
               "文件夹体积", "重复文件", "对比与报告"]
STAGE_WEIGHTS = [0.05, 0.20, 0.15, 0.20, 0.15, 0.20, 0.05]
PROGRESS_HOOK = None


def _prog(stage, pct, detail=""):
    h = PROGRESS_HOOK
    if h:
        try:
            h(stage, pct, detail)
        except Exception:
            pass


# ---------------------------------------------------------------- 工具函数
def fmt_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d B" % n) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def fmt_date(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    except Exception:
        return "-"


def days_old(ts):
    try:
        return max(0, int((time.time() - ts) / 86400))
    except Exception:
        return -1


def parse_size(text):
    text = str(text).strip().upper()
    mult = 1
    for suf, m in (("TB", 2**40), ("GB", 2**30), ("MB", 2**20), ("KB", 2**10), ("B", 1)):
        if text.endswith(suf):
            mult, text = m, text[: -len(suf)]
            break
    return int(float(text.strip()) * mult)


def expand_paths(patterns):
    out = []
    for p in patterns or []:
        p = os.path.expandvars(os.path.expanduser(p))
        hits = sorted(glob.glob(p)) if "*" in p else [p]
        for h in hits:
            if os.path.exists(h):
                out.append(h)
    return out


# ---------------------------------------------------------------- 配置
def load_config():
    cfg = {}
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except OSError as e:
        LOG("⚠ 配置保存失败：%s" % e)
        return False


def report_dir_from(args, cfg):
    if args.report_dir:
        d = os.path.abspath(os.path.expandvars(os.path.expanduser(args.report_dir)))
    elif cfg.get("report_dir"):
        d = os.path.abspath(os.path.expandvars(os.path.expanduser(cfg["report_dir"])))
    else:
        d = DEFAULT_REPORT_DIR
    return d


# ---------------------------------------------------------------- 保护名单(#3)
PROTECTED_FILE = os.path.join(SCRIPT_DIR, "保护名单.json")


def load_protected_paths():
    """用户标记的「永不建议清理」路径列表"""
    try:
        with open(PROTECTED_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return [str(p) for p in data.get("protected", []) if p]
    except Exception:
        return []


def save_protected_paths(paths):
    with open(PROTECTED_FILE, "w", encoding="utf-8") as f:
        json.dump({"protected": sorted(set(paths))}, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 清理历史(#4)
CLEAN_LOG_FILE = os.path.join(SCRIPT_DIR, "清理历史.json")


def load_clean_history():
    try:
        with open(CLEAN_LOG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"records": []}


def append_clean_history(paths, note=""):
    """记录一次清理（由导出的清理脚本通过 --log-clean 调用）"""
    hist = load_clean_history()
    rec = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           "count": len(paths), "paths": paths, "note": note}
    hist["records"].append(rec)
    hist["records"] = hist["records"][-200:]
    with open(CLEAN_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(hist, f, ensure_ascii=False, indent=2)


def cleanup_last_scan_time(report_root):
    """最近一次扫描的时间字符串（供 GUI 扫描提醒用）"""
    snap = load_last_snapshot(report_root)
    return (snap or {}).get("generated", "")


# ---------------------------------------------------------------- 清理点定义
def cleanup_definitions():
    """返回 (名称, 等级, 路径模式列表, 清理建议, 官方清理命令)"""
    L = os.environ.get("LOCALAPPDATA", "")
    A = os.environ.get("APPDATA", "")
    U = os.environ.get("USERPROFILE", "")
    W = os.environ.get("WINDIR", r"C:\Windows")
    chrome_cache = os.path.join(L, "Google", "Chrome", "User Data", "*", "Cache*")
    chrome_code = os.path.join(L, "Google", "Chrome", "User Data", "*", "Code Cache")
    edge_cache = os.path.join(L, "Microsoft", "Edge", "User Data", "*", "Cache*")
    edge_code = os.path.join(L, "Microsoft", "Edge", "User Data", "*", "Code Cache")
    return [
        # ---- A 级：缓存/临时文件，放心清理 ----
        ("用户临时文件", "A", [os.path.join(L, "Temp")],
         "关闭正在运行的程序后，可全选删除；个别提示「正在使用」的文件跳过即可。", ""),
        ("Windows 临时文件", "A", [os.path.join(W, "Temp")],
         "建议用系统自带「磁盘清理」(cleanmgr) 或 设置→存储 清理。", ""),
        ("系统更新缓存", "A", [os.path.join(W, "SoftwareDistribution", "Download")],
         "已下载完的更新安装包可清理；若 Windows 更新正在下载，先等它完成。", ""),
        ("缩略图/图标缓存", "A", [os.path.join(L, "Microsoft", "Windows", "Explorer")],
         "删除后系统会自动重建，仅首次打开图片文件夹时稍慢。", ""),
        ("DirectX 着色器缓存", "A", [os.path.join(L, "D3DSCache")], "可放心删除，游戏首次启动会重新编译。", ""),
        ("Chrome 浏览器缓存", "A", [chrome_cache, chrome_code],
         "浏览器内 设置→隐私→清除浏览数据→「缓存的图片和文件」更稳妥，不会丢登录状态。", ""),
        ("Edge 浏览器缓存", "A", [edge_cache, edge_code],
         "浏览器内 设置→隐私→清除浏览数据→「缓存的图片和文件」。", ""),
        ("系统崩溃转储", "A", [os.path.join(L, "CrashDumps"), os.path.join(W, "Minidump")],
         "崩溃日志，除非正在排查蓝屏问题，否则可删。", ""),
        ("Windows 错误报告", "A", [os.path.join(L, "Microsoft", "Windows", "WER")], "可放心删除。", ""),
        ("Courier/崩溃日志缓存", "A", [os.path.join(A, "Courier", "Logs"),
                                         os.path.join(L, "SquirrelTemp")],
         "各类安装器残留日志，可放心删除。", ""),
        # ---- B 级：确认后清理 ----
        ("下载文件夹", "B", [os.path.join(U, "Downloads")],
         "逐个查看：安装包/压缩包用完即可删，重要文件移到文档盘归档。", ""),
        ("pip 缓存", "B", [os.path.join(L, "pip", "cache")], "命令 pip cache purge 可清空，需要时会重新下载。",
         "pip cache purge"),
        ("npm 缓存", "B", [os.path.join(A, "npm-cache"), os.path.join(L, "npm-cache")],
         "命令 npm cache clean --force；缓存能加速安装，空间紧张再清。", "npm cache clean --force"),
        ("Yarn 缓存", "B", [os.path.join(L, "Yarn", "Cache")], "yarn cache clean。", "yarn cache clean"),
        ("Gradle 缓存", "B", [os.path.join(U, ".gradle", "caches")],
         "含构建缓存与依赖包，清理后下次构建会重新下载。", ""),
        ("Maven 本地仓库", "B", [os.path.join(U, ".m2", "repository")],
         "全部是依赖包，删后重新 import 会重新下载，空间大时再清。", ""),
        ("NuGet 包缓存", "B", [os.path.join(U, ".nuget", "packages")], "dotnet 开发依赖，可清但会重新下载。", ""),
        ("conda 包缓存", "B", [os.path.join(U, "anaconda3", "pkgs"), os.path.join(U, "miniconda3", "pkgs")],
         "命令 conda clean --all 可安全清理。", "conda clean --all"),
        ("HuggingFace 模型缓存", "B", [os.path.join(U, ".cache", "huggingface")],
         "已下载的模型权重；删后再次使用会重新下载(可能很大)。", ""),
        ("AI 工具缓存(.codex/.ollama 等)", "B", [os.path.join(U, ".codex"),
                                                  os.path.join(U, ".ollama", "models"),
                                                  os.path.join(U, ".claude"),
                                                  os.path.join(U, ".gemini"),
                                                  os.path.join(U, ".cache")],
         "AI CLI 工具的会话/模型缓存。.codex 里的 sessions 与日志会持续增长；"
         ".ollama/models 是本地大模型权重，删后需重新 pull。确认不再需要的内容再清。", ""),
        ("项目依赖目录(node_modules/venv/target)", "B", [],
         "统计所有项目里的 node_modules、venv/.venv、target、__pycache__ 总体积；"
         "不用的项目整个删除即可，需要时 npm install / pip install 重建。", ""),
        ("Docker 镜像/卷占用", "B", [os.path.join(L, "Docker", "wsl"),
                                      os.path.join(L, "Docker")],
         "docker system df 查看明细；docker system prune 清理未使用镜像/容器。"
         "Docker Desktop 的 WSL 虚拟磁盘只增不减，需在 Docker Desktop→Troubleshoot 里清理。", "docker system df"),
        ("WSL 发行版虚拟磁盘", "B", [os.path.join(L, "Packages"), os.path.join(U, ".docker")],
         "WSL 虚拟磁盘(vhdx)只增不减：wsl --shutdown 后用 diskpart/optimize-vhd 压缩，"
         "或在 PowerShell 里运行 Optimize-VHD(需管理员+Hyper-V)。", ""),
        ("Android 构建缓存", "B", [os.path.join(U, ".android", "build-cache"),
                                    os.path.join(L, "Android")],
         "Android 构建缓存，删除后下次构建变慢一次。", ""),
        ("微信/QQ 接收文件", "B", [os.path.join(U, "Documents", "WeChat Files"),
                                    os.path.join(U, "Documents", "Tencent Files"),
                                    os.path.join(U, "Documents", "xwechat_files")],
         "聊天记录里的图片/视频/文件！清理前务必在微信里确认哪些要保留。", ""),
        # ---- C 级：仅统计体积，谨慎 ----
        ("系统休眠文件 hiberfil.sys", "C", [r"C:\hiberfil.sys"],
         "不用休眠功能的话，管理员命令行执行 powercfg /h off 可彻底关闭并释放空间。", "powercfg /h off"),
        ("虚拟内存页面文件 pagefile.sys", "C", [r"C:\pagefile.sys"],
         "系统自动管理，不要手动删除；空间紧张可在「高级系统设置」里调小或移到其他盘。", ""),
        ("文档(个人数据)", "C", [os.path.join(U, "Documents")], "个人数据，仅统计体积，请自行归档。", ""),
        ("图片/视频/音乐", "C", [os.path.join(U, "Pictures"), os.path.join(U, "Videos"), os.path.join(U, "Music")],
         "个人数据，仅统计体积。", ""),
        # ---- v2.2 新增清理点 ----
        ("回收站占用", "A", [os.environ.get("SYSTEMDRIVE", "C:") + "\\$Recycle.Bin"],
         "清空回收站即可释放；资源管理器内右键回收站 → 清空。", ""),
        ("pnpm 缓存", "B", [os.path.join(L, "pnpm", "cache"), os.path.join(L, "pnpm", "store")],
         "pnpm store prune 可安全清理未引用包。", "pnpm store prune"),
        ("Go 模块缓存", "B", [os.path.join(U, "go", "pkg", "mod")],
         "go clean -modcache 清理已下载模块。", "go clean -modcache"),
        ("uv 缓存", "B", [os.path.join(L, "uv", "cache")],
         "uv cache clean 清理。", "uv cache clean"),
        ("Cargo 注册表缓存", "B", [os.path.join(U, ".cargo", "registry")],
         "rust 开发依赖缓存，删后重新下载。", ""),
        ("Torch 模型缓存", "B", [os.path.join(U, ".cache", "torch")],
         "PyTorch 预训练模型权重，确认不再用再清。", ""),
        ("Docker 构建缓存/悬空镜像", "B", [os.path.join(L, "Docker", "wsl", "data", "ext4.vhdx")],
         "docker system prune -a 清理未使用镜像/构建缓存；虚拟磁盘压缩需 Docker Desktop → Troubleshoot。"
         " 悬空镜像可用 docker image prune 单独清。", "docker system prune -a -f"),
        ("系统还原点占用", "C", [os.path.join(W, "System Volume Information")],
         "系统还原/卷影副本占用，需管理员：vssadmin list shadowstorage 查看，"
         "vssadmin resize shadowstorage 调整上限。", "vssadmin list shadowstorage"),
    ]


# 微信/QQ 接收文件按年份细分（B 级，在 run_scan 中动态计算）
def wechat_year_definitions():
    U = os.environ.get("USERPROFILE", "")
    base = []
    for root in (os.path.join(U, "Documents", "WeChat Files"),
                 os.path.join(U, "Documents", "Tencent Files"),
                 os.path.join(U, "Documents", "xwechat_files")):
        if os.path.isdir(root):
            try:
                for e in os.scandir(root):
                    if e.is_dir(follow_symlinks=False):
                        base.append(e.path)
            except OSError:
                pass
    # 取一层（通常是账号目录），里面才是 FileStorage
    out = []
    for acct in base:
        try:
            for e in os.scandir(acct):
                if e.is_dir(follow_symlinks=False) and e.name.lower() in ("filestorage", "filestorage_cache", "files"):
                    out.append(e.path)
        except OSError:
            pass
    return out


DEPEND_DIR_NAMES = {"node_modules", "venv", ".venv", "target", "__pycache__",
                    "dist", "build", "cmake-build-debug", "cmake-build-release"}


# ---------------------------------------------------------------- 盘符
def list_drives():
    """枚举本地固定硬盘。关键：不能用 GetDriveTypeW——它遇到断开/不可达的
    网络映射盘会尝试重新连接 SMB，阻塞数十秒到数分钟且无任何提示。
    QueryDosDeviceW 只查内核设备名，不触碰网络，永远立即返回。
    本地硬盘的设备名以 \\Device\\Harddisk 开头；网络盘是 LanmanRedirector 等。"""
    drives = []
    if IS_WIN:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                root = "%s:" % letter
                buf = ctypes.create_unicode_buffer(512)
                n = ctypes.windll.kernel32.QueryDosDeviceW(root, buf, 512)
                target = buf.value if n else ""
                if target.startswith("\\Device\\Harddisk"):
                    drives.append(root + "\\")
    else:
        drives = ["/"]
    return drives


def drive_free_gb(root):
    try:
        if IS_WIN:
            free = ctypes.c_ulonglong(0)
            total = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                root, ctypes.byref(free), ctypes.byref(total), None)
            return total.value, free.value
        st = os.statvfs(root)
        return st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    except Exception:
        return 0, 0


# ---------------------------------------------------------------- 目录/文件扫描
def is_symlink(path, st=None):
    try:
        if os.path.islink(path):
            return True
        return bool(st is not None and st.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False


def scan_tree(root, max_depth=4, skip_names=None, on_file=None):
    """统计 root 下文件总大小/数量。on_file(path, stat) 回调可顺便收集信息。
    返回 (size, file_count)。"""
    skip_names = skip_names or set()
    total = 0
    count = 0
    stack = [(root, 0)]
    while stack:
        path, depth = stack.pop()
        try:
            entries = os.scandir(path)
        except (PermissionError, FileNotFoundError, OSError):
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except (PermissionError, FileNotFoundError, OSError):
                continue
            if is_symlink(e.path, st):
                continue
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name.lower() in skip_names:
                        continue
                    if depth < max_depth:
                        stack.append((e.path, depth + 1))
                elif e.is_file(follow_symlinks=False):
                    total += st.st_size
                    count += 1
                    if on_file:
                        on_file(e.path, st)
            except (PermissionError, FileNotFoundError, OSError):
                continue
    return total, count


def scan_tree_stale(root, max_depth=4, skip_names=None):
    """统计 root 下体积，并返回加权平均的「最后活跃时间」。
    返回 (size, file_count, last_active_ts)。last_active_ts 按文件大小加权，
    大文件的活动时间权重更高，能代表该目录「最近是否在用」。"""
    skip_names = skip_names or set()
    total = 0
    count = 0
    w_sum = 0.0        # 权重和
    w_time = 0.0       # 加权时间和
    stack = [(root, 0)]
    while stack:
        path, depth = stack.pop()
        try:
            entries = os.scandir(path)
        except (PermissionError, FileNotFoundError, OSError):
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except (PermissionError, FileNotFoundError, OSError):
                continue
            if is_symlink(e.path, st):
                continue
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name.lower() in skip_names:
                        continue
                    if depth < max_depth:
                        stack.append((e.path, depth + 1))
                elif e.is_file(follow_symlinks=False):
                    total += st.st_size
                    count += 1
                    w = st.st_size + 1.0
                    w_sum += w
                    w_time += w * st.st_mtime
            except (PermissionError, FileNotFoundError, OSError):
                continue
    last_active = (w_time / w_sum) if w_sum > 0 else 0.0
    return total, count, last_active


# ---------------------------------------------------------------- 清理优先级评分
def cleanup_score(level, size, last_active):
    """清理优先级评分 0~5 星（保留 1 位小数）。
    规则：安全等级(A=2/B=1/C=0 基础分) + 体积(>1GB=2, >256MB=1.5, >64MB=1,
    >16MB=0.5, 其他 0.2) + 陈旧度(>180天=1, >90天=0.6, >30天=0.3, 活跃=0)。"""
    base = {"A": 2.0, "B": 1.0, "C": 0.0}.get(level, 0.0)
    if size > 1 * 2**30:
        vs = 2.0
    elif size > 256 * 2**20:
        vs = 1.5
    elif size > 64 * 2**20:
        vs = 1.0
    elif size > 16 * 2**20:
        vs = 0.5
    else:
        vs = 0.2
    if last_active <= 0:
        ss = 0.3  # 无法判断时给中性偏保守分
    else:
        days = max(0.0, (time.time() - last_active) / 86400.0)
        if days > 180:
            ss = 1.0
        elif days > 90:
            ss = 0.6
        elif days > 30:
            ss = 0.3
        else:
            ss = 0.0
    score = min(5.0, base + vs + ss)
    return round(score, 1)


def fmt_stale(last_active):
    """陈旧度文案"""
    if last_active <= 0:
        return "-"
    days = max(0, int((time.time() - last_active) / 86400))
    if days <= 7:
        return "本周活跃"
    if days <= 30:
        return "%d 天未更新" % days
    if days <= 90:
        return "%d 天未更新" % days
    return "%d 天未更新" % days



def scan_top_folders(drive_root, max_depth=4):
    skip = {"$recycle.bin", "system volume information", "windows.old"}
    results = []
    try:
        entries = list(os.scandir(drive_root))
    except (PermissionError, OSError):
        return results
    for e in entries:
        if is_symlink(e.path):
            continue
        try:
            if e.is_dir(follow_symlinks=False):
                if e.name.lower() in skip:
                    continue
                size, cnt = scan_tree(e.path, max_depth=max_depth)
                if size > 0:
                    results.append({"path": e.path, "size": size, "files": cnt})
            else:
                st = e.stat(follow_symlinks=False)
                if st.st_size > 0:
                    results.append({"path": e.path, "size": st.st_size, "files": 1})
        except (PermissionError, OSError):
            continue
    results.sort(key=lambda x: -x["size"])
    return results


def find_large_files(roots, min_bytes, max_depth=8, time_limit=None, on_progress=None):
    found = []
    deadline = time.time() + time_limit if time_limit else None
    skip_top = {"windows", "$recycle.bin", "system volume information", "$windows.~bt"}
    tick = [0]
    for root in roots:
        stack = [(root, 0)]
        while stack:
            if deadline and time.time() > deadline:
                return found
            path, depth = stack.pop()
            tick[0] += 1
            if on_progress and tick[0] % 40 == 0:
                on_progress(path)
            try:
                entries = os.scandir(path)
            except (PermissionError, FileNotFoundError, OSError):
                continue
            for e in entries:
                if deadline and time.time() > deadline:
                    return found
                try:
                    if is_symlink(e.path):
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if depth == 0 and e.name.lower() in skip_top:
                            continue
                        if depth < max_depth:
                            stack.append((e.path, depth + 1))
                    elif e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        if st.st_size >= min_bytes:
                            found.append({"path": e.path, "size": st.st_size, "mtime": st.st_mtime})
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    found.sort(key=lambda x: -x["size"])
    return found


# ---------------------------------------------------------------- 依赖目录扫描(node_modules 等)
def scan_dependency_dirs(roots, time_limit=None, on_progress=None):
    """在 roots 下找 node_modules/venv/target/__pycache__ 等项目依赖目录并统计体积"""
    hits = []
    deadline = time.time() + time_limit if time_limit else None
    targets = DEPEND_DIR_NAMES
    tick = [0]
    for root in roots:
        stack = [(root, 0)]
        while stack:
            if deadline and time.time() > deadline:
                return hits
            path, depth = stack.pop()
            tick[0] += 1
            if on_progress and tick[0] % 40 == 0:
                on_progress(path, len(hits))
            try:
                entries = os.scandir(path)
            except (PermissionError, FileNotFoundError, OSError):
                continue
            for e in entries:
                if deadline and time.time() > deadline:
                    return hits
                try:
                    if not e.is_dir(follow_symlinks=False) or is_symlink(e.path):
                        continue
                    low = e.name.lower()
                    if low in targets:
                        # 找到了依赖目录：统计后不再深入
                        size, cnt = scan_tree(e.path, max_depth=12)
                        if size > 0:
                            hits.append({"path": e.path, "size": size, "files": cnt,
                                         "kind": low})
                        continue
                    # 常见项目根标记：有 .git 时浅层继续找
                    if low in {".git", ".gradle", "repos", "projects", "code", "workspace",
                               "workspaces", "dev", "github", "src", "gopath", "go"} or depth < 3:
                        stack.append((e.path, depth + 1))
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    hits.sort(key=lambda x: -x["size"])
    return hits


# ---------------------------------------------------------------- 重复文件检测
def find_duplicates(roots, min_bytes, time_limit=None, max_groups=50, on_progress=None):
    """按内容哈希找重复文件：先按(大小)分组，只对同尺寸文件做部分+完整哈希。
    返回重复组列表 [{size, files:[path...]}, ...]（保留每组第一个文件不动，其余为可删候选）"""
    if min_bytes <= 0:
        return []
    by_size = {}
    deadline = time.time() + time_limit if time_limit else None
    tick = [0]

    def collect(path, st):
        if st.st_size >= min_bytes:
            by_size.setdefault(st.st_size, []).append(path)
        tick[0] += 1
        if on_progress and tick[0] % 300 == 0:
            on_progress(path, len(by_size))

    for root in roots:
        scan_tree(root, max_depth=8, on_file=collect)
        if deadline and time.time() > deadline:
            break

    def partial_hash(path, size):
        try:
            h = hashlib.blake2b(digest_size=16)
            with open(path, "rb") as f:
                # 小文件全读；大文件读头+中+尾各 64KB
                if size <= 262144:
                    h.update(f.read())
                else:
                    h.update(f.read(65536))
                    f.seek(size // 2)
                    h.update(f.read(65536))
                    f.seek(max(0, size - 65536))
                    h.update(f.read(65536))
            return h.digest()
        except OSError:
            return None

    def full_hash(path):
        try:
            h = hashlib.blake2b(digest_size=16)
            with open(path, "rb") as f:
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
            return h.digest()
        except OSError:
            return None

    groups = []
    candidates = 0
    for size, paths in sorted(by_size.items(), key=lambda kv: -kv[0]):
        if deadline and time.time() > deadline:
            break
        if len(paths) < 2 or len(groups) >= max_groups:
            continue
        candidates += 1
        # 第一轮：部分哈希分组
        by_ph = {}
        for p in paths:
            ph = partial_hash(p, size)
            if ph is not None:
                by_ph.setdefault(ph, []).append(p)
        # 第二轮：部分哈希相同的做完整哈希确认
        for ph, ps in by_ph.items():
            if len(ps) < 2:
                continue
            by_fh = {}
            for p in ps:
                fh = full_hash(p)
                if fh is not None:
                    by_fh.setdefault(fh, []).append(p)
            for fh, fs in by_fh.items():
                if len(fs) >= 2:
                    groups.append({"size": size, "files": fs,
                                   "wasted": size * (len(fs) - 1)})
    groups.sort(key=lambda g: -g["wasted"])
    return groups


# ---------------------------------------------------------------- 大文件类型聚类(#9)
FILE_TYPE_RULES = [
    ("视频", (".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".ts", ".m4v", ".rmvb")),
    ("安装包", (".exe", ".msi", ".msix", ".apk")),
    ("压缩包", (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso")),
    ("虚拟机/磁盘镜像", (".vhd", ".vhdx", ".vmdk", ".qcow2", ".img", ".dmg", ".wim")),
    ("数据库文件", (".mdb", ".db", ".sqlite", ".mdf", ".ldf", ".ibd")),
    ("文档", (".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".md", ".txt")),
    ("图片", (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".raw", ".psd", ".tif")),
    ("音频", (".mp3", ".flac", ".wav", ".ape", ".m4a", ".ogg")),
    ("模型权重", (".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf", ".onnx")),
    ("日志/转储", (".log", ".dmp", ".dump", ".tmp")),
]


def classify_file(path):
    ext = os.path.splitext(path)[1].lower()
    for label, exts in FILE_TYPE_RULES:
        if ext in exts:
            return label
    return "其他"


def cluster_large_files(large_files):
    """按类型聚类大文件，返回 [{type, size, files, top_path}]，并做相似文件名归组"""
    clusters = {}
    for f in large_files:
        t = classify_file(f["path"])
        c = clusters.setdefault(t, {"type": t, "size": 0, "files": 0, "top": f})
        c["size"] += f["size"]
        c["files"] += 1
    out = sorted(clusters.values(), key=lambda x: -x["size"])
    for c in out:
        c.pop("top", None)
    # 相似文件名序列归组（同目录/同类型，名字尾部带编号的差异）
    def base_name(p):
        n = os.path.basename(p)
        n = re.sub(r"[_\-.\s]*\d{1,4}(?=\.[^.]+$)", "", n)   # 去掉尾部编号
        n = re.sub(r"[\(\[（【]?\d{1,3}[\)\]）】]?(?=\.[^.]+$)", "", n)
        d = os.path.dirname(p)
        return d.lower() + "|" + n.lower()
    groups = {}
    for f in large_files:
        key = base_name(f["path"])
        g = groups.setdefault(key, {"key": key, "size": 0, "count": 0, "sample": f["path"]})
        g["size"] += f["size"]
        g["count"] += 1
    serials = [g for g in groups.values() if g["count"] >= 3]
    serials.sort(key=lambda g: -g["size"])
    return out, serials[:12]


# ---------------------------------------------------------------- 空文件夹与同名文件(#2)
def find_empty_folders(roots, limit=200, time_limit=60):
    """找空文件夹（不含隐藏系统目录）"""
    out = []
    deadline = time.time() + time_limit if time_limit else None
    skip = {"$recycle.bin", "system volume information", "windows", "windows.old",
            "appdata", "$windows.~bt", "node_modules", ".git", "__pycache__"}
    for root in roots:
        stack = [root]
        while stack:
            if deadline and time.time() > deadline:
                return out
            path = stack.pop()
            try:
                entries = list(os.scandir(path))
            except (PermissionError, FileNotFoundError, OSError):
                continue
            if not entries:
                out.append(path)
                if len(out) >= limit:
                    return out
                continue
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False) and not is_symlink(e.path):
                        if e.name.lower() not in skip:
                            stack.append(e.path)
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    return out


def find_same_name_files(large_files):
    """同名但不同位置的大文件（可能是多份拷贝）"""
    by_name = {}
    for f in large_files:
        by_name.setdefault(os.path.basename(f["path"]).lower(), []).append(f)
    out = []
    for name, fs in by_name.items():
        if len(fs) >= 2:
            out.append({"name": name, "files": [{"path": f["path"], "size": f["size"]}
                                                for f in fs],
                        "wasted": sum(f["size"] for f in fs) - max(f["size"] for f in fs)})
    out.sort(key=lambda g: -g["wasted"])
    return out[:30]


# ---------------------------------------------------------------- 重复文件保留策略(#2)
KEEP_HINT_DIRS = ("documents", "desktop", "work", "workspace", "projects", "code", "dev")
DROP_HINT_DIRS = ("temp", "cache", "downloads", "recycle", "tmp", "backup", "old", "副本")


def dup_keep_suggestion(files):
    """为重复组建议保留哪个文件：位于工作/文档目录的优先保留；
    位于缓存/下载/临时目录的标为建议删除。返回每文件的标记列表。"""
    def score(p):
        low = p.lower().replace("/", "\\")
        s = 0
        if any(k in low for k in KEEP_HINT_DIRS):
            s += 2
        if any(k in low for k in DROP_HINT_DIRS):
            s -= 2
        # 更早的文件（原始版本）略加分
        try:
            s += (os.path.getmtime(p) < time.time() - 30 * 86400) and 0.5 or 0
        except OSError:
            pass
        return s
    ranked = sorted(files, key=lambda p: (-score(p), p))
    keep = ranked[0]
    marks = []
    for f in files:
        if f == keep:
            marks.append("keep")
        elif score(f) < score(keep):
            marks.append("drop")
        else:
            marks.append("dup")  # 同分，均为候选副本
    return marks


def load_snapshots(report_root, limit=10):
    """按时间返回最近的 N 次 summary.json 快照（旧→新）"""
    snaps = []
    try:
        stamps = sorted(d for d in os.listdir(report_root)
                        if os.path.isdir(os.path.join(report_root, d)))
    except OSError:
        return snaps
    for stamp in reversed(stamps):
        p = os.path.join(report_root, stamp, "summary.json")
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    snaps.append(json.load(f))
            except Exception:
                continue
        if len(snaps) >= limit:
            break
    snaps.reverse()
    return snaps


def load_last_snapshot(report_root):
    """找上一次扫描的 summary.json"""
    try:
        stamps = sorted(d for d in os.listdir(report_root)
                        if os.path.isdir(os.path.join(report_root, d)))
    except OSError:
        return None
    for stamp in reversed(stamps):
        p = os.path.join(report_root, stamp, "summary.json")
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                continue
    return None


def diff_snapshot(cur, prev):
    """对比两次扫描结果，返回对比数据(供 HTML 渲染)"""
    if not prev:
        return None
    out = {"prev_time": prev.get("generated", "?"),
           "disks": [], "cleanups": [], "top_grow": []}
    # 磁盘变化
    prev_disks = {d["root"]: d for d in prev.get("disks", [])}
    for d in cur["disks"]:
        pd = prev_disks.get(d["root"])
        if pd:
            out["disks"].append({"root": d["root"], "free": d["free"],
                                 "free_delta": d["free"] - pd["free"]})
    # 清理点变化
    prev_cl = {c["name"]: c for c in prev.get("cleanups", [])}
    for c in cur["cleanups"]:
        pc = prev_cl.get(c["name"])
        if pc:
            delta = c["size"] - pc["size"]
            if abs(delta) > 10 * 2**20:  # 只显示变化超 10MB 的
                out["cleanups"].append({"name": c["name"], "level": c["level"],
                                        "size": c["size"], "delta": delta})
    # 用户目录顶层文件夹增长排行
    prev_f = {f["path"]: f for f in prev.get("folders", [])}
    grows = []
    for f in cur["folders"]:
        pf = prev_f.get(f["path"])
        if pf:
            d = f["size"] - pf["size"]
            if abs(d) > 50 * 2**20:
                grows.append({"path": f["path"], "delta": d, "size": f["size"]})
    grows.sort(key=lambda x: -x["delta"])
    out["top_grow"] = grows[:15]
    return out


# ---------------------------------------------------------------- 已安装程序(Windows 注册表)
def installed_programs():
    if not IS_WIN:
        return []
    seen = {}
    views = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]
    for hive, subkey, access in views:
        try:
            base = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | access)
        except OSError:
            continue
        idx = 0
        while True:
            try:
                name = winreg.EnumKey(base, idx)
                idx += 1
            except OSError:
                break
            try:
                k = winreg.OpenKey(base, name)
            except OSError:
                continue
            info = {"name": "", "version": "", "publisher": "",
                    "size": 0, "date": "", "uninstall": "", "location": ""}
            for field, vname in (("name", "DisplayName"), ("version", "DisplayVersion"),
                                  ("publisher", "Publisher"), ("date", "InstallDate"),
                                  ("uninstall", "UninstallString"), ("location", "InstallLocation")):
                try:
                    info[field] = winreg.QueryValueEx(k, vname)[0]
                except OSError:
                    pass
            try:
                info["size"] = int(winreg.QueryValueEx(k, "EstimatedSize")[0]) * 1024
            except OSError:
                info["size"] = 0
            winreg.CloseKey(k)
            if not info["name"]:
                continue
            key = info["name"].strip().lower()
            if key in seen:
                if info["size"] > seen[key]["size"]:
                    seen[key] = info
            else:
                seen[key] = info
        winreg.CloseKey(base)
    return sorted(seen.values(), key=lambda x: -x.get("size", 0))


def guess_program_category(name, publisher):
    n = (name or "").lower()
    p = (publisher or "").lower()
    if any(k in p for k in ("microsoft",)) and any(
            k in n for k in ("visual studio", "windows sdk", ".net", "sql server")):
        return "开发工具"
    if any(k in n for k in ("python", "java", "jdk", "node", "git", "vscode",
                            "code", "visual studio", "eclipse", "intellij", "pycharm",
                            "webstorm", "android studio", "docker", "mysql", "postgres",
                            "vmware", "virtualbox", "maven", "rust", "golang", "go ",
                            "wsl", "cursor", "trae", "qoder", "opencode")):
        return "开发工具"
    if any(k in n for k in ("微信", "wechat", "qq", "钉钉", "dingtalk", "telegram",
                            "飞书", "feishu", "lark", "teams", "zoom", "discord")):
        return "通讯社交"
    if any(k in n for k in ("chrome", "edge", "firefox", "浏览器")):
        return "浏览器"
    if any(k in n for k in ("office", "word", "excel", "powerpoint", "wps", "pdf",
                            "acrobat", "notion", "obsidian", "typora", "语雀")):
        return "办公文档"
    if any(k in n for k in ("steam", "game", "epic", "netease", "we game", "tomb",
                            "rockstar", "燕云")):
        return "游戏"
    if any(k in n for k in ("driver", "驱动", "nvidia", "amd", "realtek", "intel", "联想")):
        return "驱动/硬件"
    if any(k in n for k in ("百度网盘", "夸克", "quark", "onedrive", "dropbox", "绿联")):
        return "网盘/同步"
    return "其他"


# ---------------------------------------------------------------- 主扫描
def scan_roots_for(args, drives, home):
    """统一的扫描根选择：--drives 指定盘符 > --full 全盘 > 默认用户目录"""
    if getattr(args, "drives", ""):
        roots = [r.strip().rstrip("\\") + "\\" for r in args.drives.split(",")
                 if r.strip()]
        return [r for r in roots if os.path.isdir(r)] or [home]
    if args.full:
        return drives
    return [home]


def run_scan(args, report_root):
    t0 = time.time()
    home = os.path.expanduser("~")
    # 第一时间输出日志：让用户立刻看到扫描已启动（此前磁盘枚举是静默期）
    LOG("开始扫描 · 模式：%s" % ("全盘扫描" if args.full else
        ("指定盘符: " + args.drives if getattr(args, "drives", "") else "快速扫描(用户目录)")))
    _prog(1, -1, "正在识别本地硬盘 ...")
    drives = list_drives()
    LOG("    识别到本地硬盘: %s" % ", ".join(drives))
    system_drive = "C:\\" if IS_WIN else "/"
    is_admin = False
    if IS_WIN:
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass

    # 1) 磁盘概览
    disks = []
    for root in drives:
        total, free = drive_free_gb(root)
        if total > 0:
            disks.append({"root": root, "total": total, "free": free,
                          "used": total - free, "pct": round((total - free) / total * 100, 1)})

    # 2) 已安装程序
    LOG("[1/7] 正在读取已安装程序清单 ...")
    _prog(1, -1, "读取注册表与开始菜单 ...")
    progs = installed_programs()
    for p in progs:
        p["category"] = guess_program_category(p["name"], p["publisher"])
    _prog(1, 1.0, "共 %d 个程序" % len(progs))

    # 3) 清理点
    LOG("[2/7] 正在统计各类缓存/清理点体积 ...")
    cleanups = []
    defs = cleanup_definitions()
    protected = load_protected_paths()
    for i, (name, level, patterns, tip, cmd) in enumerate(defs):
        _prog(2, i / max(1, len(defs)), name)
        paths = expand_paths(patterns)
        size = 0
        files = 0
        last_active = 0.0
        if paths:
            for p in paths:
                if os.path.isdir(p):
                    depth = 3 if level == "B" else 4
                    s, c, la = scan_tree_stale(p, max_depth=depth)
                    size += s
                    files += c
                    if la > last_active:
                        last_active = la
                elif os.path.isfile(p):
                    try:
                        size += os.path.getsize(p)
                        files += 1
                        la = os.path.getmtime(p)
                        if la > last_active:
                            last_active = la
                    except OSError:
                        pass
        is_protected = any(p and (p in pr or pr in p) for pr in protected for p in paths)
        cleanups.append({"name": name, "level": level, "size": size,
                         "files": files, "paths": paths, "tip": tip, "cmd": cmd,
                         "last_active": last_active,
                         "stale_text": fmt_stale(last_active),
                         "score": cleanup_score(level, size, last_active),
                         "protected": is_protected})
        LOG("    %-28s %s" % (name, fmt_size(size)))
    _prog(2, 1.0, "共 %d 个清理点" % len(cleanups))

    # 3b) 项目依赖目录(node_modules 等)
    LOG("[3/7] 正在扫描项目依赖目录(node_modules/venv/target) ...")
    dep_roots = scan_roots_for(args, drives, home)

    def dep_prog(path, nhits):
        _prog(3, -1, "%s ｜ 已找到 %d 个" % (path, nhits))

    dep_dirs = scan_dependency_dirs(dep_roots, time_limit=args.timeout,
                                    on_progress=dep_prog)
    dep_total = sum(d["size"] for d in dep_dirs)
    for c in cleanups:
        if c["name"].startswith("项目依赖目录"):
            c["size"] = dep_total
            c["files"] = sum(d["files"] for d in dep_dirs)
    LOG("    找到 %d 个依赖目录，合计 %s" % (len(dep_dirs), fmt_size(dep_total)))

    # 4) 大文件
    LOG("[4/7] 正在搜索大文件(>=%s) ..." % fmt_size(args.min_size))
    roots = scan_roots_for(args, drives, home)

    def big_prog(path):
        _prog(4, -1, path)

    large = find_large_files(roots, args.min_size, max_depth=8,
                             time_limit=args.timeout, on_progress=big_prog)
    _prog(4, 1.0, "找到 %d 个大文件" % len(large))

    # 4b) 大文件类型聚类 + 相似文件名归组 + 同名文件(#9/#2)
    LOG("    正在做大文件类型聚类 ...")
    large_clusters, serial_groups = cluster_large_files(large)
    same_name = find_same_name_files(large)
    LOG("    类型聚类 %d 组，相似序列 %d 组，同名文件 %d 组"
        % (len(large_clusters), len(serial_groups), len(same_name)))

    # 4c) 空文件夹(#2)
    empty_roots = scan_roots_for(args, drives, home)
    empty_folders = find_empty_folders(empty_roots, time_limit=min(60, args.timeout))
    LOG("    找到 %d 个空文件夹" % len(empty_folders))

    # 5) 文件夹体积排行
    LOG("[5/7] 正在统计文件夹体积排行 ...")
    folder_rows = []
    scan_roots = ([r.strip() + ("\\" if not r.strip().endswith("\\") else "")
                   for r in args.drives.split(",") if r.strip()] if args.drives
                  else (drives if args.full else [home]))
    for i, root in enumerate(scan_roots):
        _prog(5, i / max(1, len(scan_roots)), root)
        LOG("    扫描 %s ..." % root)
        folder_rows.extend(scan_top_folders(root, max_depth=4))
    _prog(5, 1.0, "完成")

    # 6) 重复文件
    dup_groups = []
    if not args.no_duplicates:
        LOG("[6/7] 正在检测重复文件(>=%s，按内容哈希) ..." % fmt_size(args.dup_min))
        dup_roots = scan_roots_for(args, drives, home)

        def dup_prog(path, nsizes):
            _prog(6, -1, "%s ｜ %d 种尺寸" % (path, nsizes))

        dup_groups = find_duplicates(dup_roots, args.dup_min,
                                     time_limit=args.timeout, max_groups=50,
                                     on_progress=dup_prog)
        wasted = sum(g["wasted"] for g in dup_groups)
        LOG("    找到 %d 组重复文件，可释放约 %s" % (len(dup_groups), fmt_size(wasted)))
        _prog(6, 1.0, "%d 组重复，约 %s" % (len(dup_groups), fmt_size(wasted)))
        # 保留策略建议(#2)：每组建议保留哪个、删除哪个
        for g in dup_groups:
            g["marks"] = dup_keep_suggestion(g["files"])
    else:
        pass

    # 6b) 微信/QQ 接收文件按账号-存储目录细分(#11)
    wechat_dirs = wechat_year_definitions()
    wechat_rows = []
    if wechat_dirs:
        LOG("    正在细分微信/QQ 接收文件目录 ...")
        for wd in wechat_dirs:
            s, c, la = scan_tree_stale(wd, max_depth=5)
            if s > 0:
                wechat_rows.append({"path": wd, "size": s, "files": c,
                                    "last_active": la,
                                    "stale_text": fmt_stale(la)})
        wechat_rows.sort(key=lambda x: -x["size"])
        LOG("    微信/QQ 存储目录 %d 个，合计 %s"
            % (len(wechat_rows), fmt_size(sum(w["size"] for w in wechat_rows))))

    # 7) 历史对比
    LOG("[7/7] 正在与上次扫描结果对比 ...")
    _prog(7, -1, "读取上次快照 ...")
    prev = load_last_snapshot(report_root)
    compare = diff_snapshot({"disks": disks, "cleanups": cleanups,
                             "folders": folder_rows, "generated":
                             datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, prev)
    # 近 10 次快照的趋势数据（含本次）
    _prog(7, 0.4, "汇总空间趋势 ...")
    snaps = load_snapshots(report_root, 10)
    trend = []
    for s in snaps:
        trend.append({"generated": s.get("generated", "?"),
                      "disks": {d["root"]: d["free"] for d in s.get("disks", [])}})
    trend.append({"generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                  "disks": {d["root"]: d["free"] for d in disks},
                  "current": True})
    # 清理历史（供报告展示）
    _prog(7, 0.6, "读取清理历史 ...")
    clean_hist = load_clean_history()

    LOG("正在生成报告 ...")
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": round(time.time() - t0, 1),
        "mode": "全盘扫描" if args.full else "快速扫描(用户目录)",
        "is_admin": is_admin,
        "disks": disks,
        "programs": progs,
        "cleanups": cleanups,
        "dep_dirs": dep_dirs,
        "large_files": large,
        "large_clusters": large_clusters,
        "serial_groups": serial_groups,
        "same_name": same_name,
        "empty_folders": empty_folders,
        "wechat_rows": wechat_rows,
        "folders": folder_rows,
        "duplicates": dup_groups,
        "compare": compare,
        "trend": trend,
        "clean_history": clean_hist.get("records", []),
        "protected": protected,
        "min_size": args.min_size,
        "dup_min": args.dup_min,
    }


# ---------------------------------------------------------------- 报告输出
def write_csvs(data, outdir):
    def w(path, header, rows):
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            wr = csv.writer(f)
            wr.writerow(header)
            wr.writerows(rows)
        return path

    files = {}
    files["programs"] = w(os.path.join(outdir, "程序清单.csv"),
        ["名称", "分类", "版本", "厂商", "体积", "安装日期", "安装位置", "卸载命令"],
        [[p["name"], p["category"], p["version"], p["publisher"],
          fmt_size(p["size"]), p["date"], p["location"], p["uninstall"]]
         for p in data["programs"]])

    files["cleanups"] = w(os.path.join(outdir, "清理点.csv"),
        ["名称", "安全等级", "当前体积", "文件数", "路径", "清理建议", "官方命令"],
        [[c["name"], c["level"], fmt_size(c["size"]), c["files"],
          " ; ".join(c["paths"]), c["tip"], c["cmd"]] for c in data["cleanups"]])

    files["large"] = w(os.path.join(outdir, "大文件.csv"),
        ["文件路径", "大小", "最后修改", "距今(天)"],
        [[f["path"], fmt_size(f["size"]), fmt_date(f["mtime"]),
          days_old(f["mtime"])] for f in data["large_files"]])

    files["folders"] = w(os.path.join(outdir, "文件夹体积.csv"),
        ["路径", "体积", "文件数"],
        [[f["path"], fmt_size(f["size"]), f["files"]] for f in data["folders"]])

    files["depdirs"] = w(os.path.join(outdir, "项目依赖目录.csv"),
        ["路径", "类型", "体积", "文件数"],
        [[d["path"], d["kind"], fmt_size(d["size"]), d["files"]] for d in data["dep_dirs"]])

    files["duplicates"] = w(os.path.join(outdir, "重复文件.csv"),
        ["组", "单个体积", "重复浪费", "文件1", "文件2", "文件3"],
        [[i + 1, fmt_size(g["size"]), fmt_size(g["wasted"])] + g["files"][:3]
         for i, g in enumerate(data["duplicates"])])
    return files


def write_summary(data, outdir):
    """写 summary.json 供下次对比用（只存对比需要的精简字段）"""
    snap = {
        "generated": data["generated"],
        "mode": data["mode"],
        "disks": data["disks"],
        "cleanups": [{"name": c["name"], "level": c["level"], "size": c["size"]}
                     for c in data["cleanups"]],
        "folders": data["folders"][:200],
    }
    with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False)


# ---------------------------------------------------------------- HTML 报告
HTML_HEAD = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>电脑清理扫描报告</title>
<style>
  :root{--a:#16a34a;--b:#d97706;--c:#dc2626;--bg:#f4f5f7;--card:#fff;--ink:#1f2328;--muted:#6b7280;--line:#e5e7eb;--brand:#1e3a8a}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Microsoft YaHei","Segoe UI",sans-serif;background:var(--bg);color:var(--ink)}
  header{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;padding:24px 32px}
  header h1{margin:0 0 6px;font-size:22px}
  header p{margin:2px 0;opacity:.85;font-size:13px}
  .wrap{max-width:1220px;margin:0 auto;padding:18px 22px 70px}
  .tabs{display:flex;gap:8px;margin:16px 0;flex-wrap:wrap}
  .tabs button{border:1px solid var(--line);background:#fff;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:14px}
  .tabs button.active{background:var(--brand);color:#fff;border-color:var(--brand)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .card h2{margin:0 0 4px;font-size:17px}
  .card .sub{color:var(--muted);font-size:12px;margin-bottom:10px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#f8fafc;text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);white-space:nowrap;cursor:pointer;user-select:none;position:relative}
  th.sortable:hover{background:#eef2f7}
  th .arrow{font-size:10px;margin-left:3px;opacity:.9}
  td{padding:7px 10px;border-bottom:1px solid var(--line);word-break:break-all;vertical-align:top}
  tr:hover td{background:#f8fafc}
  .num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
  .delta-up{color:#dc2626} .delta-down{color:#16a34a}
  .lvl{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
  .lvl-A{background:var(--a)} .lvl-B{background:var(--b)} .lvl-C{background:var(--c)}
  .bar{height:14px;border-radius:7px;background:#e5e7eb;overflow:hidden;display:inline-block;width:180px;vertical-align:middle}
  .bar i{display:block;height:100%}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
  .stat{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:12px 14px}
  .stat .v{font-size:20px;font-weight:700}
  .stat .k{font-size:12px;color:var(--muted);margin-top:2px}
  .tip{color:var(--muted);font-size:12px}
  .toolbar{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
  .toolbar input[type=text]{border:1px solid var(--line);border-radius:8px;padding:8px 12px;width:260px;font-size:13px}
  .toolbar select{border:1px solid var(--line);border-radius:8px;padding:8px;font-size:13px}
  .btn{border:none;border-radius:8px;padding:9px 18px;font-size:13px;cursor:pointer;background:var(--brand);color:#fff}
  .btn:hover{opacity:.9}
  .btn.ghost{background:#fff;color:var(--brand);border:1px solid var(--brand)}
  .warn{background:#fffbeb;border:1px solid #fcd34d;border-radius:10px;padding:12px 16px;font-size:13px;margin:12px 0}
  code{background:#f1f5f9;padding:1px 6px;border-radius:4px;font-size:12px}
  .chk{width:15px;height:15px;cursor:pointer}
  #exportBar{position:fixed;bottom:0;left:0;right:0;background:#0f172a;color:#fff;padding:12px 24px;display:none;align-items:center;gap:16px;z-index:9;flex-wrap:wrap}
  #exportBar .sel{font-size:13px}
  footer{text-align:center;color:var(--muted);font-size:12px;padding:20px}
</style>
</head>
<body>
<header>
  <h1>🧹 电脑清理扫描报告</h1>
  <p id="meta"></p>
</header>
<div class="wrap">
<div class="warn">本工具<b>只扫描、只出报告，不会删除任何文件</b>。"勾选导出"生成的清理脚本把文件<b>移入回收站</b>（可撤销），运行前请再确认一遍内容。</div>
<div class="tabs" id="tabs"></div>
<div id="panels"></div>
</div>
<div id="exportBar">
  <span class="sel" id="selInfo"></span>
  <button class="btn" onclick="exportScript()">⬇ 导出清理脚本(.bat)</button>
  <button class="btn ghost" onclick="clearChecks()" style="background:#1e293b;color:#fff;border-color:#475569">清空勾选</button>
</div>
<script>
const DATA = __DATA__;
function h(size){const u=["B","KB","MB","GB","TB"];let n=size,i=0;while(n>=1024&&i<4){n/=1024;i++}return i?n.toFixed(1)+" "+u[i]:n+" B"}
function dt(ts){return new Date(ts*1000).toLocaleDateString("zh-CN")}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
document.getElementById("meta").textContent =
  DATA.generated + " · " + DATA.mode + " · 耗时 " + DATA.elapsed + " 秒" +
  (DATA.is_admin ? "" : " · ⚠ 未以管理员运行，系统目录统计可能偏小") + " · 只扫描不删除";
"""
HTML_TAIL = """
</script>
</body>
</html>
"""

PANEL_JS = """
// ================= 通用：可排序表格 =================
function makeSortable(tbodyId, rows, render, sortKeys){
  // rows: 对象数组; render(obj)->tr html; sortKeys: {列名: 取值函数}
  const st={key:null,asc:false};
  function draw(){
    let list=rows.slice();
    const q=(document.getElementById(tbodyId+"-q")||{}).value||"";
    if(q) list=list.filter(r=>JSON.stringify(r).toLowerCase().includes(q.toLowerCase()));
    if(st.key){const k=sortKeys[st.key];list.sort((a,b)=>{const x=k(a),y=k(b);
      return (x<y?-1:x>y?1:0)*(st.asc?1:-1)});}
    document.getElementById(tbodyId).innerHTML=list.map(render).join("")||"<tr><td colspan=9 class='tip'>没有匹配的行</td></tr>";
    document.querySelectorAll("#th-"+tbodyId+" th").forEach(th=>{
      const base=th.dataset.k;th.querySelector(".arrow").textContent=th.dataset.k===st.key?(st.asc?"▲":"▼"):"";
    });
  }
  const thead=document.getElementById("th-"+tbodyId);
  thead.querySelectorAll("th").forEach(th=>{
    if(th.dataset.k){th.classList.add("sortable");th.onclick=()=>{
      if(st.key===th.dataset.k)st.asc=!st.asc;else{st.key=th.dataset.k;st.asc=true}draw()}};
  });
  const inp=document.getElementById(tbodyId+"-q");
  if(inp)inp.oninput=draw;
  draw();
  return draw;
}

// ================= Tabs =================
const TABS=[["disk","💾 磁盘与对比"],["cleanup","🧽 清理点(A/B/C)"],["dup","🔁 重复文件"],
  ["dep","📦 项目依赖目录"],["programs","🪀 已安装程序"],["large","🐘 大文件排行"],["folders","📁 文件夹体积"],
  ["trend","📈 空间趋势"],["hist","🗂 清理历史"]];
const tabsEl=document.getElementById("tabs"),panelsEl=document.getElementById("panels");
TABS.forEach(([id,label],i)=>{
  const b=document.createElement("button");b.textContent=label;b.onclick=()=>show(id);
  if(i===0)b.classList.add("active");b.dataset.tab=id;tabsEl.appendChild(b);
  const d=document.createElement("div");d.id="panel-"+id;d.style.display=i===0?"":"none";
  d.className="card";panelsEl.appendChild(d);
});
function show(id){
  tabsEl.querySelectorAll("button").forEach(b=>b.classList.toggle("active",b.dataset.tab===id));
  panelsEl.querySelectorAll(".card").forEach(p=>p.style.display=p.id==="panel-"+id?"":"none");
}
function tableHTML(id,headers){return "<table><thead id='th-"+id+"'><tr>"+
  headers.map(x=>"<th data-k='"+(x[1]||"")+"'>"+x[0]+"<span class='arrow'></span></th>").join("")+
  "</tr></thead><tbody id='"+id+"'></tbody></table>"}

// ================= 磁盘 + 对比 =================
(function(){
  let html="<h2>磁盘使用概览</h2><div class='grid'>"+DATA.disks.map(x=>{
    const color=x.pct>90?"#dc2626":x.pct>75?"#d97706":"#16a34a";
    return "<div class='stat'><div class='v'>"+esc(x.root)+"</div><div class='k'>总 "+h(x.total)+" / 剩余 "+h(x.free)+"</div>"+
      "<div class='bar'><i style='width:"+x.pct+"%;background:"+color+"'></i></div><div class='k'>已用 "+x.pct+"%</div></div>";}).join("")+"</div>";
  if(DATA.compare){
    const c=DATA.compare;
    let rows=c.disks.map(d=>{const up=d.free_delta<0; // 剩余变少=空间被占用
      return "<tr><td>"+esc(d.root)+"</td><td class='num'>"+h(d.free)+"</td><td class='num "+(up?"delta-up":"delta-down")+"'>"+
      (d.free_delta>=0?"+":"")+h(d.free_delta)+"</td></tr>";}).join("");
    html+="<h2 style='margin-top:16px'>📈 与上次扫描对比 <span class='tip'>("+esc(c.prev_time)+")</span></h2>"+
      "<div class='sub'>正值(绿)=释放了空间，负值(红)=又占用了空间</div><table><thead><tr><th>磁盘</th><th>当前剩余</th><th>剩余变化</th></tr></thead><tbody>"+rows+"</tbody></table>";
    if(c.cleanups&&c.cleanups.length){
      html+="<h2 style='margin-top:16px'>清理点变化(>10MB)</h2><table><thead><tr><th>名称</th><th>等级</th><th>当前</th><th>变化</th></tr></thead><tbody>"+
      c.cleanups.map(x=>{const grew=x.delta>0;
        return "<tr><td>"+esc(x.name)+"</td><td><span class='lvl lvl-"+x.level+"'>"+x.level+"</span></td><td class='num'>"+h(x.size)+
        "</td><td class='num "+(grew?"delta-up":"delta-down")+"'>"+(x.delta>0?"+":"")+h(x.delta)+"</td></tr>";}).join("")+"</tbody></table>";}
    if(c.top_grow&&c.top_grow.length){
      html+="<h2 style='margin-top:16px'>文件夹增减排行(>50MB)</h2><table><thead><tr><th>路径</th><th>当前体积</th><th>变化</th></tr></thead><tbody>"+
      c.top_grow.map(x=>{const grew=x.delta>0;
        return "<tr><td>"+esc(x.path)+"</td><td class='num'>"+h(x.size)+"</td><td class='num "+(grew?"delta-up":"delta-down")+"'>"+(x.delta>0?"+":"")+h(x.delta)+"</td></tr>";}).join("")+"</tbody></table>";}
  } else {
    html+="<p class='tip' style='margin-top:14px'>（首次扫描，还没有历史数据可对比；下次扫描会自动生成对比）</p>";
  }
  document.getElementById("panel-disk").innerHTML=html;
})();

// ================= 清理点(含勾选) =================
const CHECKS={};const CHKSIZE={};
function chkBox(kind,path,size){const id=kind+"|"+path;
  return "<input type='checkbox' class='chk' data-id='"+esc(id)+"' data-path='"+esc(path)+"' data-size='"+(size||0)+"' onchange='onCheck(this)'>";}
function onCheck(el){
  if(el.checked){CHECKS[el.dataset.id]=el.dataset.path;CHKSIZE[el.dataset.id]=+el.dataset.size||0;}
  else{delete CHECKS[el.dataset.id];delete CHKSIZE[el.dataset.id];}
  const n=Object.keys(CHECKS).length;
  const total=Object.values(CHKSIZE).reduce((a,b)=>a+b,0);
  document.getElementById("exportBar").style.display=n?"flex":"none";
  document.getElementById("selInfo").textContent="已勾选 "+n+" 项，预计可释放 "+h(total)+"（大小可估计的项）";
}
function clearChecks(){Object.keys(CHECKS).forEach(k=>delete CHECKS[k]);
  document.querySelectorAll(".chk").forEach(c=>c.checked=false);
  document.getElementById("exportBar").style.display="none";}
function exportScript(){
  const paths=Object.values(CHECKS);
  if(!paths.length)return;
  // 生成 .bat：逐项用 PowerShell 移入回收站（可撤销），显示逐项进度，结束后回调记录清理历史
  const tool=DATA.tool_path||"";
  const psLine=(p,i)=>{
    const q=p.replace(/'/g,"''");
    return "powershell -NoProfile -Command \"Add-Type -AssemblyName Microsoft.VisualBasic; "+
      "echo [进度 "+i+"/"+paths.length+"] 处理: "+p.replace(/["<>|&]/g,"")+"; "+
      "if(Test-Path -LiteralPath '"+q+"' -PathType Container){"+
      "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('"+q+"','OnlyErrorDialogs','SendToRecycleBin')"+
      "}else{[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('"+q+"','OnlyErrorDialogs','SendToRecycleBin')}\"";
  };
  const logLine=tool?("\"\r\n\""+tool.replace(/"/g,"")+"\" --log-clean \""+paths.join("|")+"\""):"";
  const bat="@echo off\r\nchcp 65001 >nul\r\necho ============================================\r\n"+
    "echo 即将把以下 "+paths.length+" 项移入回收站(可撤销):\r\n"+
    paths.map(p=>"echo   "+p).join("\r\n")+"\r\n"+
    "echo ============================================\r\npause\r\n"+
    paths.map((p,i)=>psLine(p,i+1)).join("\r\n")+"\r\n"+
    "echo.\r\necho 全部完成！文件已在回收站，确认无误后可清空回收站。\r\n"+
    (logLine?"echo (已自动记录到清理历史)\r\n":"")+"pause\r\n";
  const blob=new Blob([bat],{type:"text/plain;charset=utf-8"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);
  a.download="清理脚本-请先审阅.bat";a.click();
  toast("脚本已下载：清理脚本-请先审阅.bat（请先审阅路径列表再运行）");
}
(function(){
  const rows=DATA.cleanups;
  const sum={A:0,B:0,C:0};rows.forEach(c=>sum[c.level]+=c.size);
  const stats=Object.keys(sum).map(l=>"<div class='stat'><div class='v'>"+h(sum[l])+"</div><div class='k'>"+l+" 级合计 — "+
    (l==="A"?"缓存临时文件，放心清":l==="B"?"确认后清理":"谨慎/仅了解")+"</div></div>").join("");
  document.getElementById("panel-cleanup").innerHTML=
    "<h2>清理点分级（含清理优先级评分）</h2><div class='sub'>星级 = 安全等级 + 体积 + 陈旧度综合评分，★★★★★ 最值得优先处理；点击「保护」可把路径加入永不建议清理名单</div>"+
    "<div class='grid' style='margin-bottom:12px'>"+stats+"</div>"+
    "<div class='toolbar'></div>"+
    tableHTML("cl",[["",""],["名称","name"],["等级","level"],["评分","score"],["当前体积","size"],["陈旧度","stale"],["文件数","files"],["位置",""],["清理建议",""]]);
  makeSortable("cl",rows,c=>{
    const cleanable=c.paths&&c.paths.length&&c.level!=="C"&&!c.protected;
    const stars="★★★★★☆☆☆☆☆".slice(0,Math.round(c.score||0))+
                "☆☆☆☆☆".slice(0,5-Math.round(c.score||0));
    return "<tr"+(c.protected?" style='opacity:.45'":"")+"><td>"+(cleanable?chkBox("cl",c.paths[0],c.size):"")+"</td><td>"+esc(c.name)+
    (c.protected?" <span class='lvl' style='background:#64748b'>已保护</span>":"")+"</td>"+
    "<td><span class='lvl lvl-"+c.level+"'>"+c.level+"</span></td>"+
    "<td title='优先级 "+(c.score||0)+"/5'>"+stars+"</td>"+
    "<td class='num'>"+h(c.size)+"</td><td class='num'>"+esc(c.stale_text||"-")+"</td>"+
    "<td class='num'>"+c.files+"</td><td class='tip'>"+esc((c.paths||[]).join(" ; "))+
    ((c.paths&&c.paths.length)?" <a href='#' onclick='protectPath(this,"+JSON.stringify(JSON.stringify(c.paths[0]))+");return false' style='font-size:11px'>"+(c.protected?"取消保护":"保护")+"</a>":"")+"</td>"+
    "<td class='tip'>"+esc(c.tip)+(c.cmd?"<br><code>"+esc(c.cmd)+"</code> <a href='#' onclick='copyCmd("+JSON.stringify(JSON.stringify(c.cmd))+");return false' style='font-size:11px'>复制命令</a>":"")+"</td></tr>";
  },{name:r=>r.name,level:r=>r.level,size:r=>r.size,files:r=>r.files,
    score:r=>r.score||0,stale:r=>r.last_active||0});
  const tb=document.querySelector("#panel-cleanup .toolbar");
  const qq=document.createElement("input");qq.type="text";qq.id="cl-q";qq.placeholder="🔍 筛选名称...";
  const btn=document.createElement("button");btn.className="btn ghost";btn.textContent="全选 A 级";btn.onclick=checkAllA;
  tb.append(qq,btn);
  // 微信/QQ 接收文件细分(#11)
  const wx=DATA.wechat_rows||[];
  if(wx.length){
    const div=document.createElement("div");div.style.marginTop="16px";
    div.innerHTML="<h2 style='margin:0 0 4px'>微信/QQ 接收文件细分</h2>"+
      "<div class='sub'>按账号-存储目录拆分，老的目录可先清</div>"+
      tableHTML("wx",[["目录",""],["体积","size"],["陈旧度",""],["文件数","files"]]);
    document.getElementById("panel-cleanup").appendChild(div);
    makeSortable("wx",wx,w=>{
      return "<tr><td class='tip'>"+esc(w.path)+"</td><td class='num'>"+h(w.size)+
      "</td><td class='num'>"+esc(w.stale_text||"-")+"</td><td class='num'>"+w.files+"</td></tr>";
    },{size:w=>w.size,files:w=>w.files});
  }
})();
function protectPath(el, path){
  // HTML 报告是静态文件，无法直接写保护名单；复制命令到剪贴板，运行后生效
  const marked=el.textContent==="取消保护";
  const flag=marked?"--unprotect":"--protect";
  const tool=DATA.tool_path||"电脑清理扫描器.exe";
  const cmd="\""+tool+"\" "+flag+" \""+path+"\"";
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(cmd).then(
      ()=>toast((marked?"已复制取消保护命令":"已复制保护命令")+"，请在 cmd 中运行后生效：\n"+cmd),
      ()=>toast("请手动运行：\n"+cmd));}
  else toast("请手动运行：\n"+cmd);
  el.textContent=marked?"保护":"取消保护";
  el.closest("tr").style.opacity=marked?"1":".45";
}
function checkAllA(){
  DATA.cleanups.forEach(c=>{
    if(c.level==="A"&&c.paths&&c.paths.length&&!c.protected){
      const id="cl|"+c.paths[0];CHECKS[id]=c.paths[0];CHKSIZE[id]=c.size;}});
  window._drawCl&&window._drawCl();
  document.querySelectorAll("#cl .chk").forEach(c=>{c.checked=!!CHECKS[c.dataset.id];});
  onCheck({checked:Object.keys(CHECKS).length>0,dataset:{id:"_sync",path:""}});
  document.querySelectorAll("#cl .chk").forEach(c=>{c.checked=!!CHECKS[c.dataset.id];});
}
function copyCmd(cmd){
  navigator.clipboard&&navigator.clipboard.writeText(cmd).then(
    ()=>{toast("已复制命令："+cmd)},
    ()=>{toast("复制失败，请手动选择命令文本复制")});
}
function toast(msg){
  let t=document.getElementById("_toast");
  if(!t){t=document.createElement("div");t.id="_toast";
    t.style.cssText="position:fixed;top:18px;left:50%;transform:translateX(-50%);background:#0f172a;color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;z-index:99;box-shadow:0 4px 14px rgba(0,0,0,.25)";
    document.body.appendChild(t);}
  t.textContent=msg;t.style.display="block";
  clearTimeout(t._h);t._h=setTimeout(()=>{t.style.display="none"},2600);
}
"""
PANEL_JS += """
// ================= 重复文件 =================
(function(){
  const rows=DATA.duplicates||[];
  const wasted=rows.reduce((s,g)=>s+g.wasted,0);
  let html="<h2>重复文件（内容完全相同）</h2><div class='sub'>✔ 保留=建议保留（工作/文档目录优先），🗑 副本=建议删除候选（缓存/下载/临时目录）；共 "+
    rows.length+" 组，重复占用约 <b>"+h(wasted)+"</b></div>";
  if(!rows.length){html+="<p class='tip'>没有发现大体积重复文件（门槛 ≥ "+h(DATA.dup_min)+"）</p>";}
  else{
    const markTag=m=>m==="keep"?"<span style='color:#16a34a;font-weight:600'>✔ 保留:</span>":
      m==="drop"?"<span style='color:#dc2626;font-weight:600'>🗑 删除:</span>":
      "<span style='color:#6b7280'>↳ 副本:</span>";
    html+="<div class='toolbar'><input type='text' id='dup-q' placeholder='🔍 筛选路径...'></div>"+
    tableHTML("dup",[["组","gi"],["单个体积","size"],["重复浪费","wasted"],["文件列表(含保留建议)",""]]);
    makeSortable("dup",rows.map((g,i)=>({...g,gi:i+1})),g=>{
      const marks=g.marks||g.files.map((_,i)=>i?"drop":"keep");
      return "<tr><td class='num'>"+g.gi+"</td><td class='num'>"+h(g.size)+"</td><td class='num delta-up'>"+h(g.wasted)+
      "</td><td>"+g.files.map((f,i)=>"<div class='"+(i?"tip":"")+"'>"+markTag(marks[i])+" "+esc(f)+"</div>").join("")+"</td></tr>";
    },{gi:g=>g.gi,size:g=>g.size,wasted:g=>g.wasted});
  }
  // 同名不同位置的大文件(#2)
  const sn=DATA.same_name||[];
  if(sn.length){
    html+="<h2 style='margin-top:18px'>同名文件（不同位置，疑似多份拷贝）</h2>"+
      "<div class='sub'>名字相同但内容未必相同，删除前请自行比对</div>"+
      tableHTML("sn",[["文件名","name"],["重复浪费","wasted"],["位置列表",""]]);
    makeSortable("sn",sn,g=>{
      return "<tr><td>"+esc(g.name)+"</td><td class='num delta-up'>"+h(g.wasted)+"</td><td>"+
      g.files.map(f=>"<div class='tip'>"+esc(f.path)+" ("+h(f.size)+")</div>").join("")+"</td></tr>";
    },{name:g=>g.name,wasted:g=>g.wasted});
  }
  // 空文件夹(#2)
  const ef=DATA.empty_folders||[];
  if(ef.length){
    html+="<h2 style='margin-top:18px'>空文件夹（"+ef.length+" 个）</h2>"+
      "<div class='sub'>可安全删除；已排除系统/依赖目录。前 50 个：</div>"+
      "<div style='max-height:260px;overflow-y:auto'><table><tbody>"+
      ef.slice(0,50).map(p=>"<tr><td class='tip'>"+esc(p)+"</td></tr>").join("")+
      "</tbody></table></div>";
  }
  document.getElementById("panel-dup").innerHTML=html;
  const tb=document.querySelector("#panel-dup .toolbar");
  if(tb){const q=document.createElement("input");q.type="text";q.id="dup-q";q.placeholder="🔍 筛选路径...";
    tb.appendChild(q);const d=window._drawDup;}
})();

// ================= 项目依赖目录 =================
(function(){
  const rows=DATA.dep_dirs||[];
  const total=rows.reduce((s,d)=>s+d.size,0);
  let html="<h2>项目依赖目录（node_modules / venv / target / __pycache__）</h2><div class='sub'>共 "+
    rows.length+" 个，合计 "+h(total)+"；不用的项目整个删除，需要时重新 install 重建</div>";
  if(!rows.length){html+="<p class='tip'>没有扫描到项目依赖目录</p>";}
  else{
    html+="<div class='toolbar'></div>"+tableHTML("dep",[["路径",""],["类型","kind"],["体积","size"],["文件数","files"],["",""]]);
    makeSortable("dep",rows,d=>{
      return "<tr><td>"+esc(d.path)+"</td><td><code>"+esc(d.kind)+"</code></td><td class='num'>"+h(d.size)+
      "</td><td class='num'>"+d.files+"</td><td>"+chkBox("dep",d.path)+"</td></tr>";
    },{kind:d=>d.kind,size:d=>d.size,files:d=>d.files});
  }
  document.getElementById("panel-dep").innerHTML=html;
})();

// ================= 程序 =================
(function(){
  document.getElementById("panel-programs").innerHTML=
    "<h2>已安装程序（"+DATA.programs.length+" 个）</h2><div class='sub'>来自系统注册表；卸载请到「设置→应用」或使用卸载命令，不要直接删文件夹</div>"+
    "<div class='toolbar'><input type='text' id='pg-q' placeholder='🔍 筛选名称/厂商...'></div>"+
    tableHTML("pg",[["名称","name"],["分类","category"],["版本",""],["厂商","publisher"],["体积","size"],["安装日期",""],["卸载命令",""]]);
  makeSortable("pg",DATA.programs,p=>{
    return "<tr><td>"+esc(p.name)+"</td><td>"+esc(p.category)+"</td><td>"+esc(p.version)+
    "</td><td class='tip'>"+esc(p.publisher)+"</td><td class='num'>"+(p.size?h(p.size):"-")+"</td><td class='tip'>"+esc(p.date)+
    "</td><td class='tip'>"+esc(p.uninstall)+"</td></tr>";
  },{name:p=>p.name,category:p=>p.category,publisher:p=>p.publisher,size:p=>p.size});
})();

// ================= 大文件 =================
(function(){
  const rows=DATA.large_files||[];
  // 类型聚类(#9)
  const cl=DATA.large_clusters||[];
  let clHTML="";
  if(cl.length){
    const max=cl[0].size||1;
    clHTML="<h2 style='margin-top:4px'>按类型聚类</h2><div class='sub'>大文件的类型分布，定位"哪类东西最占空间"</div>"+
    "<table style='max-width:640px'><thead><tr><th>类型</th><th>合计体积</th><th>文件数</th><th>占比</th></tr></thead><tbody>"+
    cl.map(c=>"<tr><td>"+esc(c.type)+"</td><td class='num'>"+h(c.size)+"</td><td class='num'>"+c.files+
    "</td><td><div class='bar' style='width:220px'><i style='width:"+Math.round(c.size/max*100)+"%;background:#1e3a8a'></i></div></td></tr>").join("")+
    "</tbody></table>";
  }
  // 相似文件名序列(#9)
  const se=DATA.serial_groups||[];
  let seHTML="";
  if(se.length){
    seHTML="<h2 style='margin-top:18px'>相似文件名序列（≥3 个一组）</h2><div class='sub'>video_001/002… 这类连续文件，往往是成批素材</div>"+
    "<table style='max-width:640px'><thead><tr><th>示例文件</th><th>数量</th><th>合计体积</th></tr></thead><tbody>"+
    se.map(g=>"<tr><td class='tip'>"+esc(g.sample)+"</td><td class='num'>"+g.count+"</td><td class='num'>"+h(g.size)+"</td></tr>").join("")+
    "</tbody></table>";
  }
  document.getElementById("panel-large").innerHTML=
    "<h2>大文件排行（≥ "+h(DATA.min_size)+"）</h2><div class='sub'>按体积排序；视频/安装包/虚拟机镜像往往是大头，确认无用后再删</div>"+clHTML+seHTML+
    (rows.length?"<h2 style='margin-top:18px'>明细</h2><div class='toolbar'><input type='text' id='lg-q' placeholder='🔍 筛选路径...'></div>"+
    tableHTML("lg",[["文件路径",""],["类型",""],["大小","size"],["最后修改","mtime"],["距今","days"]]):"<p class='tip'>没有找到符合条件的大文件（试试全盘扫描或调低 --min-size）</p>");
  if(rows.length)makeSortable("lg",rows.map(f=>({...f,days:Math.max(0,Math.floor((Date.now()/1000-f.mtime)/86400))})),f=>{
    return "<tr><td>"+esc(f.path)+"</td><td>"+esc(f._type||"")+"</td><td class='num'>"+h(f.size)+"</td><td class='num'>"+dt(f.mtime)+"</td><td class='num'>"+f.days+" 天</td></tr>";
  },{size:f=>f.size,mtime:f=>f.mtime,days:f=>f.days});
  // 补类型标记（cluster 函数没把类型写回每个文件）
  const typeMap={};
  (DATA.large_files||[]).forEach(f=>{
    const ext=(f.path.split(".").pop()||"").toLowerCase();
    const rules=[["视频",["mp4","mkv","avi","mov","wmv","flv","ts","m4v","rmvb"]],
      ["安装包",["exe","msi","msix","apk"]],
      ["压缩包",["zip","rar","7z","tar","gz","bz2","xz","iso"]],
      ["虚拟机/镜像",["vhd","vhdx","vmdk","qcow2","img","dmg","wim"]],
      ["数据库",["mdb","db","sqlite","mdf","ldf","ibd"]],
      ["文档",["pdf","doc","docx","ppt","pptx","xls","xlsx","md","txt"]],
      ["图片",["jpg","jpeg","png","gif","bmp","webp","heic","raw","psd","tif"]],
      ["音频",["mp3","flac","wav","ape","m4a","ogg"]],
      ["模型权重",["safetensors","bin","pt","pth","ckpt","gguf","onnx"]],
      ["日志/转储",["log","dmp","dump","tmp"]]];
    let t="其他";
    for(const [n,exts] of rules){if(exts.includes(ext)){t=n;break;}}
    typeMap[f.path]=t;});
  const draw=window._drawLg;if(draw)draw();
})();

// ================= 文件夹 =================
(function(){
  const rows=DATA.folders||[];
  document.getElementById("panel-folders").innerHTML=
    "<h2>文件夹体积排行</h2><div class='sub'>扫描顶层目录（深度 4 层），用于定位"空间都去哪了"</div>"+
    (rows.length?"<div class='toolbar'><input type='text' id='fd-q' placeholder='🔍 筛选路径...'></div>"+
    tableHTML("fd",[["路径",""],["体积","size"],["文件数","files"]]):"<p class='tip'>无数据</p>");
  if(rows.length)makeSortable("fd",rows,f=>{
    return "<tr><td>"+esc(f.path)+"</td><td class='num'>"+h(f.size)+"</td><td class='num'>"+f.files+"</td></tr>";
  },{size:f=>f.size,files:f=>f.files});
})();

// ================= 空间趋势(#7) =================
(function(){
  const t=DATA.trend||[];
  const el=document.getElementById("panel-trend");
  if(t.length<2){el.innerHTML="<h2>分区剩余空间趋势</h2><p class='tip'>仅 "+t.length+" 次扫描记录，下次扫描后会生成趋势折线图</p>";return;}
  const W=980,Hh=340,padL=70,padR=20,padT=20,padB=60;
  const roots=[...new Set(t.flatMap(x=>Object.keys(x.disks||{})))];
  const colors=["#1e3a8a","#16a34a","#d97706","#7c3aed","#0891b2","#dc2626"];
  const series=roots.map((r,i)=>({root:r,color:colors[i%colors.length],
    pts:t.map((s,j)=>({j:j+1,v:(s.disks||{})[r],cur:!!s.current,
      g:s.generated})).filter(p=>p.v!=null)}));
  const allV=series.flatMap(s=>s.pts.map(p=>p.v));
  const lo=Math.min(...allV),hi=Math.max(...allV);
  const span=(hi-lo)||1;
  const X=j=>padL+(j-1)*(W-padL-padR)/(t.length-1);
  const Y=v=>padT+(Hh-padT-padB)*(1-(v-lo)/span);
  let svg="<svg viewBox='0 0 "+W+" "+Hh+"' style='width:100%;max-width:"+W+"px'>";
  for(let g=0;g<=4;g++){const v=lo+span*g/4,y=Y(v);
    svg+="<line x1='"+padL+"' y1='"+y+"' x2='"+(W-padR)+"' y2='"+y+"' stroke='#e5e7eb'/>";
    svg+="<text x='"+(padL-8)+"' y="+(y+4)+" text-anchor='end' font-size='11' fill='#6b7280'>"+h(v)+"</text>";}
  series.forEach(s=>{
    if(s.pts.length<2)return;
    svg+="<polyline fill='none' stroke='"+s.color+"' stroke-width='2.5' points='"+
      s.pts.map(p=>X(p.j)+","+Y(p.v)).join(" ")+"'/>";
    s.pts.forEach(p=>{svg+="<circle cx='"+X(p.j)+"' cy='"+Y(p.v)+"' r='"+(p.cur?5:3.5)+
      "' fill='"+(p.cur?s.color:"#fff")+"' stroke='"+s.color+"' stroke-width='2'><title>"+
      esc(p.g)+" · "+s.root+" 剩余 "+h(p.v)+"</title></circle>";});
  });
  t.forEach((s,j)=>{if(t.length>8&&j%2)return;
    svg+="<text x='"+X(j+1)+"' y='"+(Hh-38)+"' text-anchor='middle' font-size='10' fill='#6b7280'>"+
      esc(String(s.generated||"").slice(2,10))+"</text>";});
  svg+="</svg>";
  let legend="<div style='display:flex;gap:16px;flex-wrap:wrap;margin:10px 0'>"+
    series.map(s=>"<span style='font-size:13px'><span style='display:inline-block;width:12px;height:12px;border-radius:6px;background:"+s.color+";margin-right:6px;vertical-align:-1px'></span>"+esc(s.root)+"</span>").join("")+"</div>";
  el.innerHTML="<h2>分区剩余空间趋势（近 "+t.length+" 次扫描）</h2>"+
    "<div class='sub'>折线上升=释放了空间，下降=空间被占用；大圆点=本次扫描</div>"+legend+
    "<div style='overflow-x:auto'>"+svg+"</div>";
})();

// ================= 清理历史(#4) =================
(function(){
  const recs=(DATA.clean_history||[]).slice().reverse();
  const el=document.getElementById("panel-hist");
  if(!recs.length){el.innerHTML="<h2>清理历史</h2><p class='tip'>还没有清理记录。在「清理点」或「项目依赖目录」页勾选项目并导出清理脚本，运行后这里会自动出现记录。</p>";return;}
  const total=recs.reduce((s,r)=>s+(r.count||0),0);
  let rows=recs.map(r=>"<tr><td class='num'>"+esc(r.time)+"</td><td class='num'>"+(r.count||0)+
    "</td><td class='tip'>"+(r.paths||[]).slice(0,5).map(esc).join("<br>")+
    ((r.paths||[]).length>5?"<br>… 共 "+r.paths.length+" 项":"")+"</td></tr>").join("");
  el.innerHTML="<h2>清理历史（最近 "+recs.length+" 次）</h2>"+
    "<div class='sub'>由导出的清理脚本自动记录；配合「空间趋势」页可验证清理效果。累计清理 "+total+" 项</div>"+
    "<table><thead><tr><th>时间</th><th>项数</th><th>清理内容</th></tr></thead><tbody>"+rows+"</tbody></table>";
})();

"""

# ---------------------------------------------------------------- HTML 写出
def write_html(data, outdir):
    # 内嵌 exe/脚本路径，供导出的清理脚本回调记录清理历史
    data = dict(data)
    data["tool_path"] = os.path.abspath(sys.executable if getattr(sys, "frozen", False)
                                        else os.path.abspath(__file__))
    head = HTML_HEAD.replace("__DATA__", json.dumps(data, ensure_ascii=False))
    html = head + PANEL_JS + HTML_TAIL
    path = os.path.join(outdir, "清理扫描报告.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ---------------------------------------------------------------- 手机查看(局域网)
def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def start_lan_server(serve_dir, q=None):
    """在局域网启动静态文件服务，返回 (url, stop_fn)。手机与电脑同一 WiFi 即可访问。"""
    import http.server
    import functools

    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=serve_dir)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 0), handler)
    port = httpd.server_address[1]
    url = "http://%s:%d/清理扫描报告.html" % (get_lan_ip(), port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return url, httpd.shutdown


def make_qr_png(url, png_path):
    """用 segno 生成二维码 PNG；未安装则返回 False"""
    try:
        import segno
        segno.make(url, error="m").save(png_path, scale=10, border=2)
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------- 图形界面(无窗口模式)
def run_gui(args, cfg, report_root):
    import tkinter as tk
    from tkinter import font as tkfont, filedialog

    # ---------------- DPI 感知：高分辨率屏不模糊、不拉伸 ----------------
    scale = 1.0
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PER_MONITOR_AWARE
            scale = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100.0
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    if scale <= 0 or scale > 3:
        scale = 1.0

    def S(v):
        return int(round(v * scale))

    # ---------------- 液态玻璃配色 ----------------
    BG0 = "#0a0f1e"      # 深夜蓝底
    CARD = "#161e38"     # 玻璃卡片
    EDGE = "#2e3a63"     # 卡片描边
    EDGE_HI = "#4a5a95"  # 顶部高光
    TXT = "#e9eefb"
    DIM = "#8d9abf"
    ACCENT = "#6d7bff"   # 主强调（蓝紫）
    CYAN = "#4dd6ff"     # 次强调（青）
    GREEN = "#3ddc97"
    AMBER = "#ffc35c"
    RED = "#ff6b81"

    root = tk.Tk()
    root.title("电脑清理扫描器 · 只扫描不删除")
    root.geometry("%dx%d" % (S(880), S(680)))
    root.minsize(S(820), S(620))
    root.configure(bg=BG0)
    try:
        ico = os.path.join(SCRIPT_DIR, "app-icon.ico")
        if os.path.exists(ico):
            root.iconbitmap(ico)
    except Exception:
        pass

    state = {"scanning": False, "outdir": None, "html": None,
             "server": None, "url": None}
    logq = queue_mod.Queue()

    # 字体用负数像素字号（Tk 中负值=像素）：随 DPI 精确缩放，不会双重放大导致重叠
    F_TITLE = tkfont.Font(root, family="Microsoft YaHei UI",
                          size=-S(26), weight="bold")
    F_SUB = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(14))
    F_UI = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(14))
    F_UIB = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(14), weight="bold")
    F_BTN = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(15), weight="bold")
    F_STAGE = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(14), weight="bold")
    F_DETAIL = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(12))
    F_LOG = tkfont.Font(root, family="Consolas", size=-S(12))
    F_CHIP = tkfont.Font(root, family="Microsoft YaHei UI", size=-S(11))

    def round_pts(x1, y1, x2, y2, r):
        return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r,
                x2, y2, x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r,
                x1, y1 + r, x1, y1]

    def shorten(s, n=52):
        s = str(s)
        return s if len(s) <= n else s[:n - 26] + "…" + s[-20:]

    # ---------------- 顶部 hero：渐变 + 液态光斑 ----------------
    hero = tk.Canvas(root, height=S(104), bg=BG0, highlightthickness=0)
    hero.pack(fill="x")

    def draw_hero(e=None):
        hero.delete("all")
        w = max(hero.winfo_width(), S(300))
        h = int(hero["height"])
        n = 48
        for i in range(n):
            t = i / n
            col = "#%02x%02x%02x" % (int(10 + 22 * t), int(15 + 26 * t), int(30 + 52 * t))
            hero.create_rectangle(0, h * t, w, h * (t + 1.0 / n) + 1, fill=col, outline="")
        for cx, cy, rx, ry, col in [(w * 0.88, S(8), S(180), S(62), "#26335f"),
                                     (w * 0.04, h, S(210), S(74), "#1d2951"),
                                     (w * 0.46, -S(6), S(160), S(52), "#1b2547")]:
            hero.create_oval(cx - rx, cy - ry, cx + rx, cy + ry, fill=col,
                             outline="", stipple="gray50")
        # 用字体实测行高排版，任何 DPI 下都不会重叠
        tl = F_TITLE.metrics("linespace")
        sl = F_SUB.metrics("linespace")
        y_title = S(14) + tl // 2
        y_sub = y_title + tl // 2 + sl // 2 + S(2)
        if y_sub + sl // 2 > h:  # 视高度不够则整体上移
            y_title = max(S(8), y_title - (y_sub + sl // 2 - h + S(4)))
            y_sub = y_title + tl // 2 + sl // 2 + S(2)
        hero.create_text(S(28), y_title, anchor="w", text="电脑清理扫描器",
                         font=F_TITLE, fill=TXT)
        hero.create_text(S(30), y_sub, anchor="w",
                         text="只扫描、只出报告，绝不删除 · 报告位置可切换 · 实时进度",
                         font=F_SUB, fill=DIM)
    hero.bind("<Configure>", draw_hero)


    # ---------------- 玻璃卡片 ----------------
    class Card(tk.Frame):
        def __init__(self, master):
            super().__init__(master, bg=BG0)
            # 背景画布用 place 铺满，不占用 pack 空间，
            # 后续 pack 进来的内容控件不会被挤成 1x1
            self.cv = tk.Canvas(self, bg=BG0, highlightthickness=0)
            self.cv.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.cv.bind("<Configure>", lambda e: self._redraw())

        def _redraw(self):
            self.cv.delete("card")
            w = self.cv.winfo_width()
            h = self.cv.winfo_height()
            if w < 30 or h < 24:
                return
            self.cv.create_polygon(round_pts(1, 1, w - 2, h - 2, S(16)), smooth=True,
                                   fill=CARD, outline=EDGE, width=1, tags="card")
            self.cv.create_line(S(18), 2.5, w - S(18), 2.5, fill=EDGE_HI, width=1, tags="card")
            self.cv.tag_lower("card")

    # ---------------- 玻璃按钮 ----------------
    class GButton(tk.Canvas):
        def __init__(self, master, text, cmd, kind="ghost", width=None):
            h = S(46) if kind == "primary" else S(34)
            self._kind = kind
            self._cmd = cmd
            self._t = text
            self._hov = False
            self._en = True
            # 宽度按字体实测自适应（字数估算在高 DPI 下会失准）
            f = F_BTN if kind == "primary" else F_UIB
            tw = tkfont.Font(font=f).measure(text)
            self._cw = width or (tw + S(44))
            self._cw = max(self._cw, S(96))
            super().__init__(master, height=h, width=self._cw, bg=BG0,
                             highlightthickness=0, cursor="hand2")
            self.bind("<Button-1>", lambda e: self._click())
            self.bind("<Enter>", lambda e: self._enter(True))
            self.bind("<Leave>", lambda e: self._enter(False))
            self.redraw()

        def _click(self):
            if self._en:
                try:
                    self._cmd()
                except Exception as e:
                    import traceback
                    try:
                        LOG("按钮执行异常: %s" % traceback.format_exc())
                    except Exception:
                        pass

        def _enter(self, v):
            self._hov = v
            self.redraw()

        def set_enabled(self, en):
            self._en = en
            self.redraw()

        def redraw(self):
            self.delete("all")
            w = self._cw
            h = int(self["height"])
            r = h // 2
            if self._kind == "primary":
                if not self._en:
                    fill, tc = "#3a4166", "#9aa3c8"
                elif self._hov:
                    fill, tc = "#8089ff", "#ffffff"
                else:
                    fill, tc = ACCENT, "#ffffff"
                self.create_polygon(round_pts(1, 1, w - 2, h - 2, r), smooth=True,
                                    fill=fill, outline="")
                if self._en:
                    self.create_line(S(16), S(4), w - S(16), S(4), fill="#aab2ff", width=1)
                self.create_text(w / 2, h / 2 + 1, text=self._t, font=F_BTN, fill=tc)
            else:
                fill = "#263257" if self._hov else "#1c2647"
                tc = ("#f4f7ff" if self._hov else "#d7def5") if self._en else "#7f89ad"
                self.create_polygon(round_pts(1, 1, w - 2, h - 2, r), smooth=True,
                                    fill=fill, outline=EDGE)
                self.create_text(w / 2, h / 2 + 1, text=self._t, font=F_UIB, fill=tc)

    # ---------------- 开关药丸 ----------------
    class Toggle(tk.Canvas):
        def __init__(self, master, text, var, width=None):
            self._t = text
            self._v = var
            # 宽度按字体实测自适应，含右侧滑块区
            tw = tkfont.Font(font=F_UI).measure(text)
            self._cw = width or (tw + S(84))
            super().__init__(master, height=S(34), width=self._cw, bg=CARD,
                             highlightthickness=0, cursor="hand2")
            self.bind("<Button-1>", lambda e: self._v.set(not self._v.get()))
            self._v.trace_add("write", lambda *a: self.redraw())
            self.redraw()

        def redraw(self):
            self.delete("all")
            w = self._cw
            h = S(34)
            on = self._v.get()
            fill = "#232e6e" if on else "#121a33"
            edge = ACCENT if on else "#28325a"
            self.create_polygon(round_pts(1, 1, w - 2, h - 2, h // 2), smooth=True,
                                fill=fill, outline=edge)
            self.create_text(16, h / 2 + 1, anchor="w", text=self._t, font=F_UI,
                             fill=TXT if on else DIM)
            x0 = w - S(44)
            y0 = h / 2 - S(8)
            self.create_polygon(round_pts(x0, y0, x0 + S(32), y0 + S(16), S(8)), smooth=True,
                                fill="#0d1428", outline=edge)
            kx = x0 + S(24) if on else x0 + S(9)
            self.create_oval(kx - S(6), y0 + S(2), kx + S(6), y0 + S(14),
                             fill=ACCENT if on else "#3a4a80", outline="")

    # ---------------- 进度条（渐变 + 流光） ----------------
    class ProgBar(tk.Canvas):
        def __init__(self, master):
            super().__init__(master, height=S(18), bg=CARD, highlightthickness=0)
            self.pct = 0.0
            self.indet = False
            self.phase = 0.0
            self.bind("<Configure>", lambda e: self.redraw())

        def set(self, pct, indet=False):
            self.pct = pct
            self.indet = indet
            self.redraw()

        def tick(self):
            if self.indet:
                self.phase = (self.phase + 0.02) % 1.0
                self.redraw()

        def redraw(self):
            self.delete("all")
            w = self.winfo_width()
            h = S(18)
            if w < S(30):
                return
            self.create_polygon(round_pts(1, 1, w - 2, h - 2, S(9)), smooth=True,
                                fill="#0d1428", outline=EDGE)
            fw = int((w - S(8)) * max(0.0, min(1.0, self.pct)))
            if fw > 12:
                self.create_polygon(round_pts(S(4), S(4), S(4) + fw, h - S(4), S(8)), smooth=True,
                                    fill=ACCENT, outline="")
                self.create_line(S(10), S(6), S(4) + fw - S(8), S(6), fill="#9aa5ff", width=1)
                if self.indet:
                    span = min(S(50), max(S(24), fw // 3))
                    x = S(6) + max(0, fw - span - S(4)) * self.phase
                    self.create_polygon(round_pts(x, S(4), x + span, h - S(4), S(7)),
                                        smooth=True, fill="#aeb8ff", outline="",
                                        stipple="gray50")

    # ---------------- 阶段指示（7 步） ----------------
    CHIP_NAMES = ["磁盘", "清理点", "依赖", "大文件", "文件夹", "重复", "报告"]

    class StageChips(tk.Canvas):
        def __init__(self, master):
            super().__init__(master, height=S(52), bg=CARD, highlightthickness=0)
            self.active = 0
            self.done = set()
            self.bind("<Configure>", lambda e: self.redraw())

        def set(self, stage, pct):
            for k in range(1, stage):
                self.done.add(k)
            if pct >= 1.0:
                self.done.add(stage)
                if self.active == stage:
                    self.active = 0
            else:
                self.active = stage
            self.redraw()

        def all_done(self):
            self.done = set(range(1, 8))
            self.active = 0
            self.redraw()

        def reset(self):
            self.done = set()
            self.active = 0
            self.redraw()

        def redraw(self):
            self.delete("all")
            w = self.winfo_width()
            h = int(self["height"])
            if w < S(140):
                return
            cw = w / 7.0
            # 按字体实测行高排版，避免重叠
            f_num = F_CHIP
            f_name = F_CHIP
            num_ls = tkfont.Font(font=f_num).metrics("linespace")
            name_ls = tkfont.Font(font=f_name).metrics("linespace")
            avail = cw - S(12)
            for i in range(7):
                x1 = i * cw + S(3)
                x2 = (i + 1) * cw - S(3)
                st = i + 1
                if st in self.done:
                    fill, edge, tc = "#11322a", "#1f7a5c", GREEN
                elif st == self.active:
                    fill, edge, tc = "#232e6e", ACCENT, TXT
                else:
                    fill, edge, tc = "#121a33", "#28325a", DIM
                self.create_polygon(round_pts(x1, S(2), x2, h - S(2), S(10)),
                                    smooth=True, fill=fill, outline=edge)
                cx = (x1 + x2) / 2
                total = num_ls + name_ls + S(6)
                y0 = max(S(4), (h - total) / 2)
                self.create_text(cx, y0 + num_ls / 2,
                                 text=("✓" if st in self.done else str(st)),
                                 font=f_num, fill=tc)
                name = CHIP_NAMES[i]
                # 名字超宽时才逐字截断（正常宽度下显示完整）
                while name and tkfont.Font(font=f_name).measure(name) > avail:
                    name = name[:-1]
                self.create_text(cx, y0 + num_ls + S(6) + name_ls / 2,
                                 text=name, font=f_name, fill=tc)

    # ---------------- 布局 ----------------
    content = tk.Frame(root, bg=BG0)
    content.pack(fill="both", expand=True, padx=S(20), pady=(S(12), S(4)))

    # 选项卡
    opt_card = Card(content)
    opt_card.pack(fill="x")
    opt_card.pack_propagate(False)
    opt_card.configure(height=S(58))
    full_var = tk.BooleanVar(value=False)
    dup_var = tk.BooleanVar(value=True)
    # pack 顺序布局：从左到右自动排列，不会互相重叠
    tog1 = Toggle(opt_card, "全盘扫描", full_var)
    tog1.pack(side="left", padx=(S(18), S(6)), pady=S(10))
    tog2 = Toggle(opt_card, "检测重复文件", dup_var)
    tog2.pack(side="left", padx=S(6), pady=S(10))

    # 扫描范围多选（#12）：默认用户目录 / 指定盘符
    avail_drives = [d for d in list_drives()] if IS_WIN else ["/"]
    scan_scope_var = tk.StringVar(value="范围: 默认用户目录")
    scope_menu = tk.OptionMenu(opt_card, scan_scope_var,
                               "范围: 默认用户目录",
                               *["范围: %s 盘" % d[0] for d in avail_drives])
    scope_menu.configure(font=F_UI, bg=CARD, fg=TXT,
                         activebackground="#232e6e", activeforeground=TXT,
                         highlightthickness=0, bd=0, indicatoron=False,
                         direction="below", padx=S(12), pady=S(7), cursor="hand2")
    opt_card.menu = scope_menu["menu"]
    opt_card.menu.configure(font=F_UI, bg=CARD, fg=TXT,
                            activebackground="#232e6e", activeforeground=TXT,
                            tearoff=0)
    scope_menu.pack(side="left", padx=S(14), pady=S(10))

    def scope_choice():
        """返回传给 run_scan 的 drives 字符串（空=默认用户目录）"""
        v = scan_scope_var.get()
        if "默认" in v:
            return ""
        return v.replace("范围:", "").strip()[0]  # "C 盘" -> "C"
    tk.Label(opt_card, text="勾选全盘时忽略范围", font=F_DETAIL,
             bg=CARD, fg=DIM).pack(side="right", padx=S(16))

    # 报告位置卡（点击打开 / 可切换 / 记住上次）
    dir_card = Card(content)
    dir_card.pack(fill="x", pady=(S(10), 0))
    dir_card.pack_propagate(False)
    dir_card.configure(height=S(58))
    path_state = {"dir": report_root}

    # 单行内容条：层内 pack 排列，结构上不可能重叠
    dir_row = tk.Frame(dir_card, bg=CARD)
    dir_row.place(relx=0.02, rely=0.0, relwidth=0.96, relheight=1.0)

    icocv = tk.Canvas(dir_row, width=S(34), height=S(34), bg=CARD,
                      highlightthickness=0, cursor="hand2")

    def draw_folder_icon():
        icocv.delete("all")
        icocv.create_polygon(round_pts(S(2), S(10), S(32), S(32), S(6)), smooth=True,
                             fill="#3d4c85", outline="#5a6bb0")
        icocv.create_rectangle(S(2), S(4), S(13), S(9), fill="#4a5a95", outline="#5a6bb0")
        icocv.create_line(S(8), S(18), S(26), S(18), fill="#8fa0d8", width=S(2))
        icocv.create_line(S(8), S(24), S(21), S(24), fill="#7284c4", width=S(2))
    draw_folder_icon()

    def open_report_dir(_e=None):
        d = path_state["dir"]
        try:
            os.makedirs(d, exist_ok=True)
            os.startfile(d)
        except Exception as ex:
            append_log("打开文件夹失败：%s" % ex)

    def choose_report_dir():
        d = filedialog.askdirectory(initialdir=path_state["dir"],
                                    title="选择报告保存位置")
        if not d:
            return
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".wtest")
            open(probe, "w").close()
            os.remove(probe)
        except OSError as ex:
            append_log("该位置不可写，换一个试试：%s" % ex)
            return
        path_state["dir"] = d
        cfg["report_dir"] = d
        try:
            save_config(cfg)
            append_log("✔ 已记住新的报告位置（下次打开自动使用）：%s" % d)
        except Exception:
            append_log("报告位置已切换为 %s（写入配置失败）" % d)
        refresh_dir_label()

    dir_lbl = tk.Label(dir_row, text="", font=F_UIB, bg=CARD, fg=CYAN,
                       cursor="hand2", anchor="w", justify="left")
    dir_lbl.bind("<Button-1>", open_report_dir)
    icocv.bind("<Button-1>", open_report_dir)
    tip_lbl = tk.Label(dir_row, text="点击路径打开文件夹", font=F_DETAIL,
                       bg=CARD, fg=DIM)

    def refresh_dir_label():
        dir_lbl.configure(text=shorten(path_state["dir"], 44))
    refresh_dir_label()

    dir_btn = GButton(dir_row, "切换位置", choose_report_dir)

    # pack 顺序：右侧先占位（按钮+提示），路径标签占剩余空间（过长自动截断，不重叠）
    dir_btn.pack(side="right", padx=(S(8), S(4)))
    tip_lbl.pack(side="right", padx=S(8))
    icocv.pack(side="left", padx=(S(2), S(8)), pady=S(10))
    dir_lbl.pack(side="left", fill="x", expand=True)

    # 进度卡：三行垂直堆叠（绝对像素定位行容器，行内 pack 排列）
    prog_card = Card(content)
    prog_card.pack(fill="x", pady=(S(10), 0))
    prog_card.pack_propagate(False)
    prog_card.configure(height=S(168))

    row1 = tk.Frame(prog_card, bg=CARD)
    row1.place(x=S(8), y=S(6), relwidth=0.96, height=S(54))
    chips = StageChips(row1)
    chips.pack(fill="both", expand=True)

    row2 = tk.Frame(prog_card, bg=CARD)
    row2.place(x=S(8), y=S(66), relwidth=0.96, height=S(24))
    pct_lbl = tk.Label(row2, text="0%", font=F_UIB, bg=CARD, fg=TXT)
    bar = ProgBar(row2)
    bar.pack(side="left", fill="x", expand=True, padx=(0, S(12)), pady=S(2))
    pct_lbl.pack(side="right")

    row3 = tk.Frame(prog_card, bg=CARD)
    row3.place(x=S(8), y=S(98), relwidth=0.96, height=S(30))
    stage_lbl = tk.Label(row3, text="就绪 · 点击开始扫描", font=F_STAGE,
                         bg=CARD, fg=TXT)
    detail_lbl = tk.Label(row3, text="支持 7 个阶段实时进度", font=F_DETAIL,
                          bg=CARD, fg=DIM)
    time_lbl = tk.Label(row3, text="", font=F_UIB, bg=CARD, fg=CYAN)
    detail_lbl.pack(side="left", padx=(0, S(12)))
    stage_lbl.pack(side="left")
    time_lbl.pack(side="right")

    # 日志卡
    log_card = Card(content)
    log_card.pack(fill="both", expand=True, pady=(S(10), 0))
    log_card.pack_propagate(False)
    log_box = tk.Text(log_card, state="disabled", wrap="none", font=F_LOG,
                      bg="#0d1326", fg="#c9d4f0", bd=0, padx=10, pady=8,
                      insertbackground=TXT, selectbackground="#2c3d8f")
    log_box.place(relx=0.015, rely=0.07, relwidth=0.94, relheight=0.86)
    lsb = tk.Scrollbar(log_card, command=log_box.yview, bd=0,
                       highlightthickness=0, bg=CARD, troughcolor="#0d1326")
    log_box.configure(yscrollcommand=lsb.set)
    lsb.place(relx=0.982, rely=0.07, relheight=0.86, anchor="ne")

    # 底栏
    bottom = tk.Frame(root, bg=BG0)
    bottom.pack(fill="x", padx=S(20), pady=(S(10), S(14)))
    status_lbl = tk.Label(bottom, text="就绪", font=F_UIB, bg=BG0, fg=DIM)
    status_lbl.pack(side="right")

    scan_btn = GButton(bottom, "开始扫描", None, kind="primary")
    scan_btn.pack(side="left")
    open_btn = GButton(bottom, "打开报告", None)
    open_btn.pack(side="left", padx=(S(14), 0))
    open_btn.set_enabled(False)
    phone_btn = GButton(bottom, "手机查看", None)
    phone_btn.pack(side="left", padx=(S(14), 0))
    phone_btn.set_enabled(False)

    def append_log(msg):
        log_box.configure(state="normal")
        log_box.insert("end", msg + "\n")
        log_box.see("end")
        log_box.configure(state="disabled")

    class GuiLog:
        def __call__(self, msg):
            line = "[%s] %s" % (datetime.now().strftime("%H:%M:%S"), msg)
            logq.put(("log", line))

    def fmt_ms(sec):
        return "%d:%02d" % (int(sec) // 60, int(sec) % 60)

    def do_scan():
        if state["scanning"]:
            return
        state["scanning"] = True
        state["t0"] = time.time()
        scan_btn.set_enabled(False)
        open_btn.set_enabled(False)
        phone_btn.set_enabled(False)
        chips.reset()
        bar.set(0.0)
        pct_lbl.configure(text="0%")
        detail_lbl.configure(text="")
        stage_lbl.configure(text="准备中 …")
        status_lbl.configure(text="扫描中", fg=AMBER)
        log_box.configure(state="normal")
        log_box.delete("1.0", "end")
        log_box.configure(state="disabled")
        global LOG, PROGRESS_HOOK
        old_log = LOG
        LOG = GuiLog()

        def hook(stage, pct, detail):
            logq.put(("prog", (stage, pct, detail)))

        PROGRESS_HOOK = hook

        # Tkinter 非线程安全：所有 Tk 变量必须在主线程读取完毕，
        # 后台线程只使用普通 Python 值（跨线程 .get() 会死锁，表现为进度恒 0、日志无输出）
        opt_full = full_var.get()
        opt_dup = dup_var.get()
        opt_drives = scope_choice()
        opt_rroot = path_state["dir"]

        def work():
            # LOG/PROGRESS_HOOK 是全局变量；finally 里对它们赋值，
            # 没有 global 声明时 Python 会把 LOG 当局部变量，
            # 前面读取时触发 UnboundLocalError（扫描完成后收尾崩溃）
            global LOG, PROGRESS_HOOK
            try:
                a = argparse.Namespace(
                    full=opt_full, drives=opt_drives, min_size=100 * 2**20,
                    dup_min=10 * 2**20, no_duplicates=not opt_dup,
                    timeout=900, no_open=True, report_dir="",
                    set_report_dir="", reset_report_dir=False)
                rroot = opt_rroot
                data = run_scan(a, rroot)
                stamp = datetime.now().strftime("%Y%m%d_%H%M")
                outdir = os.path.join(rroot, stamp)
                os.makedirs(outdir, exist_ok=True)
                logq.put(("prog", (7, 0.6, "正在写出 CSV / JSON / HTML 报告 …")))
                write_csvs(data, outdir)
                write_summary(data, outdir)
                html = write_html(data, outdir)
                a_total = sum(c["size"] for c in data["cleanups"] if c["level"] == "A")
                b_total = sum(c["size"] for c in data["cleanups"] if c["level"] == "B")
                LOG("✔ 扫描完成！报告目录：%s" % outdir)
                LOG("小结：A 级可放心清理约 %s，确认后可清理的 B 级约 %s。"
                    % (fmt_size(a_total), fmt_size(b_total)))
                if data.get("duplicates"):
                    LOG("      另发现重复文件 %d 组，重复占用约 %s。" % (
                        len(data["duplicates"]),
                        fmt_size(sum(g["wasted"] for g in data["duplicates"]))))
                logq.put(("done", (outdir, html)))
            except Exception as e:
                logq.put(("error", "%s: %s" % (type(e).__name__, e)))
            finally:
                LOG = old_log
                PROGRESS_HOOK = None

        threading.Thread(target=work, daemon=True).start()

    def overall_pct(stage, pct):
        base = sum(STAGE_WEIGHTS[:stage - 1])
        w = STAGE_WEIGHTS[stage - 1]
        if pct < 0:
            return base + w * 0.55
        return base + w * max(0.0, min(1.0, pct))

    def poll_msg():
        try:
            while True:
                kind, payload = logq.get_nowait()
                if kind == "log":
                    append_log(payload)
                elif kind == "prog":
                    stage, pct, detail = payload
                    chips.set(stage, pct)
                    op = overall_pct(stage, pct)
                    bar.set(op, indet=(pct < 0))
                    pct_lbl.configure(text="%d%%" % int(op * 100))
                    stage_lbl.configure(
                        text="阶段 %d/7 · %s" % (stage, STAGE_NAMES[stage - 1]))
                    detail_lbl.configure(
                        text=shorten(detail, 76) if detail else "")
                elif kind == "done":
                    outdir, html = payload
                    state["outdir"] = outdir
                    state["html"] = html
                    state["scanning"] = False
                    chips.all_done()
                    bar.set(1.0)
                    pct_lbl.configure(text="100%")
                    stage_lbl.configure(text="全部完成 ✓")
                    detail_lbl.configure(text="报告：%s" % shorten(outdir, 64))
                    if "t0" in state:
                        time_lbl.configure(
                            text="耗时 %s" % fmt_ms(time.time() - state["t0"]))
                    status_lbl.configure(text="完成 ✓", fg=GREEN)
                    scan_btn.set_enabled(True)
                    open_btn.set_enabled(True)
                    phone_btn.set_enabled(True)
                elif kind == "error":
                    state["scanning"] = False
                    scan_btn.set_enabled(True)
                    status_lbl.configure(text="出错", fg=RED)
                    stage_lbl.configure(text="扫描失败")
                    detail_lbl.configure(text=str(payload)[:80])
                    append_log("扫描失败：%s" % payload)
        except queue_mod.Empty:
            pass
        root.after(150, poll_msg)

    def on_tick():
        if state["scanning"]:
            bar.tick()
            if "t0" in state:
                time_lbl.configure(
                    text="耗时 %s" % fmt_ms(time.time() - state["t0"]))
        root.after(120, on_tick)

    def open_report():
        if state["html"]:
            os.startfile(state["html"])

    def phone_view():
        if state["outdir"]:
            if state["server"]:
                show_qr_window(state["url"])
                return
            url, stop = start_lan_server(state["outdir"])
            state["server"] = stop
            state["url"] = url
            show_qr_window(url)

    def show_qr_window(url):
        win = tk.Toplevel(root)
        win.title("手机查看报告")
        win.geometry("%dx%d" % (S(380), S(480)))
        win.configure(bg=BG0)
        try:
            ico = os.path.join(SCRIPT_DIR, "app-icon.ico")
            if os.path.exists(ico):
                win.iconbitmap(ico)
        except Exception:
            pass
        hd = tk.Canvas(win, height=S(60), bg=BG0, highlightthickness=0)
        hd.pack(fill="x")

        def draw_hd(e=None):
            hd.delete("all")
            w = max(hd.winfo_width(), 200)
            for i in range(30):
                t = i / 30
                hd.create_rectangle(0, S(60) * t, w, S(60) * (t + 1 / 30) + 1,
                                    fill="#%02x%02x%02x" % (int(10 + 22 * t),
                                                            int(15 + 26 * t),
                                                            int(30 + 52 * t)),
                                    outline="")
            hd.create_text(S(20), S(30), anchor="w", text="手机扫码查看报告",
                           font=F_UIB, fill=TXT)
        hd.bind("<Configure>", draw_hd)

        tk.Label(win, text="手机和电脑连同一 WiFi，扫码或输入网址：",
                 font=F_UI, bg=BG0, fg=DIM).pack(pady=(12, 4))
        tk.Label(win, text=url, font=("Consolas", S(10)), bg=BG0, fg=CYAN).pack()
        png = os.path.join(state["outdir"], "_qr.png")
        if make_qr_png(url, png):
            img = tk.PhotoImage(file=png)
            lbl = tk.Label(win, image=img, bg=BG0)
            lbl.image = img
            lbl.pack(pady=10)
        else:
            tk.Label(win, text="(未安装二维码组件，请手动输入上面的网址)",
                     font=F_DETAIL, bg=BG0, fg=DIM).pack(pady=10)
        tk.Label(win, text="关闭本窗口后服务继续运行，退出程序时自动停止",
                 font=F_DETAIL, bg=BG0, fg=DIM).pack(side="bottom", pady=10)

    def on_close():
        if state["server"]:
            try:
                state["server"]()
            except Exception:
                pass
        root.destroy()

    scan_btn._cmd = do_scan
    open_btn._cmd = open_report
    phone_btn._cmd = phone_view
    root.protocol("WM_DELETE_WINDOW", on_close)
    append_log("欢迎使用电脑清理扫描器 v%s —— 只扫描、只出报告，绝不删除。" % APP_VERSION)
    append_log("报告保存位置：%s（点击上方路径可打开文件夹，可「切换位置」）"
               % path_state["dir"])
    append_log("点击「开始扫描」开始，扫描过程中可实时观察 7 个阶段的进度。")

    # ---- #14 距上次扫描提醒 ----
    last_scan = cleanup_last_scan_time(path_state["dir"])
    if last_scan:
        try:
            t = datetime.strptime(last_scan, "%Y-%m-%d %H:%M:%S")
            gap = (datetime.now() - t).days
            if gap >= 30:
                append_log("⏰ 距上次扫描已 %d 天，建议做一次新的扫描。" % gap)
            elif gap >= 7:
                append_log("距上次扫描 %d 天（%s）。" % (gap, last_scan))
        except ValueError:
            pass
    else:
        append_log("这是首次扫描，完成后下次会自动生成历史对比与空间趋势。")

    # ---- #13 后台检查 GitHub 新版本 ----
    def check_update():
        latest = check_github_latest()
        if latest and version_gt(latest, APP_VERSION):
            logq.put(("log", "发现新版本 v%s（当前 v%s），可到 %s 下载。"
                      % (latest, APP_VERSION, RELEASES_URL)))
    threading.Thread(target=check_update, daemon=True).start()

    poll_msg()
    on_tick()
    root.mainloop()


# ---------------------------------------------------------------- 版本更新检查(#13)
def check_github_latest(timeout=8):
    """后台线程调用：返回最新版本号字符串，失败返回 None"""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO,
            headers={"User-Agent": "pc-clean-scanner"})
        # 尊重系统代理（无代理直连，国内环境由 Clash 等接管）
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        return (data.get("tag_name") or "").lstrip("v") or None
    except Exception:
        return None


def version_gt(a, b):
    """比较两个 x.y.z 版本号，a>b 返回 True"""
    try:
        pa = [int(x) for x in a.split(".")]
        pb = [int(x) for x in b.split(".")]
        return pa > pb
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="电脑清理扫描器（只扫描不删除）")
    ap.add_argument("--full", action="store_true", help="全盘扫描所有本地硬盘")
    ap.add_argument("--drives", default="", help="指定盘符，如 C,D（配合 --full）")
    ap.add_argument("--min-size", default="100MB", help="大文件门槛（默认 100MB）")
    ap.add_argument("--dup-min", default="10MB", help="重复文件门槛（默认 10MB）")
    ap.add_argument("--no-duplicates", action="store_true", help="跳过重复文件检测")
    ap.add_argument("--timeout", type=int, default=300, help="各阶段时间上限秒数（默认 300）")
    ap.add_argument("--no-open", action="store_true", help="结束后不自动打开报告")
    ap.add_argument("--report-dir", default="", help="报告保存位置，会记住该设置")
    ap.add_argument("--set-report-dir", default="", help="只设置默认报告位置并退出")
    ap.add_argument("--reset-report-dir", action="store_true", help="恢复默认报告位置并退出")
    ap.add_argument("--console", action="store_true", help="强制控制台模式(不弹窗口)")
    ap.add_argument("--serve", action="store_true", help="扫描后启动手机查看服务")
    ap.add_argument("--protect", default="", help="把路径加入保护名单(内部使用)")
    ap.add_argument("--unprotect", default="", help="把路径移出保护名单(内部使用)")
    ap.add_argument("--log-clean", default="", help="记录一次清理到清理历史(内部使用)")
    args = ap.parse_args()

    cfg = load_config()

    # ---- 内部命令：保护名单 / 清理历史（由报告页与导出脚本调用）----
    if args.protect:
        p = os.path.abspath(args.protect)
        paths = load_protected_paths()
        if p not in paths:
            paths.append(p)
            save_protected_paths(paths)
        print("protected: %s" % p)
        return
    if args.unprotect:
        p = os.path.abspath(args.unprotect)
        paths = [x for x in load_protected_paths() if x != p]
        save_protected_paths(paths)
        print("unprotected: %s" % p)
        return
    if args.log_clean:
        paths = [x for x in args.log_clean.split("|") if x]
        append_clean_history(paths)
        print("logged: %d paths" % len(paths))
        return

    if args.set_report_dir:
        d = os.path.abspath(os.path.expandvars(os.path.expanduser(args.set_report_dir)))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            print("该位置无法创建文件夹：%s" % e)
            sys.exit(1)
        cfg["report_dir"] = d
        save_config(cfg)
        print("✔ 以后的扫描报告都会保存到：%s" % d)
        return
    if args.reset_report_dir:
        cfg.pop("report_dir", None)
        save_config(cfg)
        print("✔ 已恢复默认位置：%s" % DEFAULT_REPORT_DIR)
        return

    report_root = report_dir_from(args, cfg)
    if args.report_dir and cfg.get("report_dir") != report_root:
        cfg["report_dir"] = report_root
        save_config(cfg)

    # 无参数 + Windows 图形环境 → 图形界面；否则控制台
    use_gui = (IS_WIN and not args.console and not args.full
               and not args.drives and sys.stdout is None)
    if use_gui:
        run_gui(args, cfg, report_root)
        return

    # ---- 控制台流程 ----
    print("=" * 52)
    print("  电脑清理扫描器 v2 —— 只扫描，不删除任何文件")
    print("=" * 52)
    try:
        args.min_size = parse_size(args.min_size)
        args.dup_min = parse_size(args.dup_min)
    except ValueError:
        print("--min-size / --dup-min 格式不对，示例：100MB / 2GB")
        sys.exit(1)

    data = run_scan(args, report_root)

    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    try:
        outdir = os.path.join(report_root, stamp)
        os.makedirs(outdir, exist_ok=True)
    except OSError as e:
        print("⚠ 自定义报告位置不可写(%s)，改用默认位置" % e)
        outdir = os.path.join(DEFAULT_REPORT_DIR, stamp)
        os.makedirs(outdir, exist_ok=True)

    csv_files = write_csvs(data, outdir)
    write_summary(data, outdir)
    html_path = write_html(data, outdir)

    print()
    print("✔ 扫描完成！报告保存在：")
    print("   " + outdir)
    for k, v in csv_files.items():
        print("   - " + os.path.basename(v))
    print("   - 清理扫描报告.html  （浏览器打开，可排序/筛选/勾选导出）")
    a_total = sum(c["size"] for c in data["cleanups"] if c["level"] == "A")
    b_total = sum(c["size"] for c in data["cleanups"] if c["level"] == "B")
    print()
    print("小结：A 级可放心清理约 %s，B 级确认后可清约 %s。" % (fmt_size(a_total), fmt_size(b_total)))
    if data["duplicates"]:
        print("      另发现重复文件 %d 组，重复占用约 %s。" % (
            len(data["duplicates"]),
            fmt_size(sum(g["wasted"] for g in data["duplicates"]))))

    if args.serve:
        url, stop = start_lan_server(outdir)
        print()
        print("📱 手机查看服务已启动(同一 WiFi)：")
        print("   " + url)
        try:
            import segno
            segno.make(url).terminal()
        except ImportError:
            pass
        try:
            input("按回车停止服务 ... ")
        except EOFError:
            pass
        stop()

    if not args.no_open:
        try:
            os.startfile(html_path)
        except Exception:
            pass


if __name__ == "__main__":
    main()
