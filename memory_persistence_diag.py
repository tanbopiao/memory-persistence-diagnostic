#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""记忆存活性体检包 / Memory Persistence Diagnostic

只读检测你的 AI 工作环境：哪些目录会随沙箱销毁、哪些能活过重启、
记忆文件落在哪里、出口网络通不通、配额给了多少。

设计铁律：
1. 默认完全只读、不联网——只看挂载表、系统配额和已有文件的位置。
2. 绝不读取任何文件内容做上传，报告只含路径、类型、计数与建议。
3. 跨重启探针（--plant / --check）只写随机标记文件，不含任何用户数据。

用法：
    python memory_persistence_diag.py [被检目录]           # 静态体检
    python memory_persistence_diag.py --plant              # 播种探针（下次重启前跑）
    python memory_persistence_diag.py --check              # 收获探针（重启后跑）
    python memory_persistence_diag.py --net                # 附带出口网络检测
"""
import argparse
import datetime
import json
import os
import platform
import re
import shutil
import socket
import sys
import uuid

REPORT_DIR = os.environ.get("MPD_REPORT_DIR", "memory_diag_reports")
MARKER_REGISTRY = os.path.join(REPORT_DIR, "markers.json")
MARKER_NAME = ".memory_probe_marker"

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# 常见智能体记忆/配置目录候选
MEMORY_DIR_CANDIDATES = [
    "~/.memory", "~/memories", "~/memory", "~/.memories",
    "~/.config/memory", "~/.claude", "~/.openai", "~/.cursor",
    "~/.continue", "~/.dify", "~/.cache/agent",
]

VOLATILE_FS = {"tmpfs", "ramfs", "devtmpfs"}
EPHEMERAL_FS = {"overlay", "overlay2", "aufs"}
PERSISTENT_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "ntfs", "vfat", "exfat", "f2fs"}
SHARED_FS = {"virtiofs", "nfs", "nfs4", "cifs", "9p", "efs", "gcsfuse", "s3fs", "fuse.rclone"}
SPECIAL_FS = {"proc", "sysfs", "devpts", "cgroup", "cgroup2", "mqueue", "hugetlbfs",
              "securityfs", "debugfs", "tracefs", "pstore", "bpf", "fusectl", "configfs",
              "nsfs", "efivarfs", "squashfs", "iso9660", "autofs"}


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_mounts():
    """返回 [(mount_point, fs_type, device)]，按挂载点长度倒序。"""
    mounts = []
    path = "/proc/mounts"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    dev, mp, fstype = parts[0], parts[1], parts[2]
                    mp = mp.replace("\\040", " ").replace("\\011", "\t")
                    mounts.append((mp, fstype, dev))
    else:  # macOS 等
        try:
            import subprocess
            out = subprocess.run(["mount"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                m = re.match(r"(.+?) on (.+?) \((.+?)[,)]", line)
                if m:
                    mounts.append((m.group(2), m.group(3).split(",")[0], m.group(1)))
        except Exception:
            pass
    mounts.sort(key=lambda x: -len(x[0]))
    return mounts


def classify_fs(fstype):
    fstype = fstype.lower()
    if fstype in VOLATILE_FS:
        return "volatile", "内存盘，实例重启即清空"
    if fstype in EPHEMERAL_FS:
        return "ephemeral", "叠加层（容器常见），实例销毁后通常不保留"
    if fstype in SHARED_FS:
        return "shared", "共享/网络卷（宿主机挂载），通常能活过重启，建议探针实测"
    if fstype in PERSISTENT_FS:
        return "persistent", "真实磁盘卷，通常能活过重启"
    if fstype in SPECIAL_FS:
        return "special", "系统虚拟文件系统，与持久性无关"
    return "unknown", "未知类型，建议用跨重启探针实测"


SYSTEM_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/boot", "/etc/hosts",
                   "/etc/hostname", "/etc/resolv.conf")


def user_relevant_mounts(mounts):
    """过滤系统虚拟挂载，只留用户关心的卷。"""
    out = []
    for mp, fstype, dev in mounts:
        if any(mp == p or mp.startswith(p.rstrip("/") + "/") for p in SYSTEM_PREFIXES):
            continue
        if classify_fs(fstype)[0] == "special":
            continue
        out.append((mp, fstype, dev))
    return out


def mount_for(path, mounts):
    path = os.path.abspath(path)
    for mp, fstype, dev in mounts:
        if path == mp or path.startswith(mp.rstrip("/") + "/"):
            return mp, fstype, dev
    return "/", mounts[-1][1] if mounts else "?", "?"


def cgroup_limits():
    """读取内存/CPU 配额（cgroup v2 优先，回退 v1）。"""
    limits = {}
    for v2, v1, key in [
        ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes", "memory_bytes"),
        ("/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "cpu_quota"),
    ]:
        val = None
        for p in (v2, v1):
            try:
                with open(p) as f:
                    val = f.read().strip()
                break
            except Exception:
                continue
        limits[key] = val
    return limits


def uptime_seconds():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except Exception:
        try:
            import subprocess
            out = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"sec\s*=\s*(\d+)", out)
            if m:
                import time
                return time.time() - int(m.group(1))
        except Exception:
            pass
    return None


def human_bytes(n):
    if n is None:
        return "未知"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def net_check(timeout=3):
    hosts = [("pypi.org", 443), ("github.com", 443), ("huggingface.co", 443),
             ("registry.npmjs.org", 443), ("api.openai.com", 443)]
    results = []
    for host, port in hosts:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            results.append((host, "可达"))
        except Exception as e:
            results.append((host, f"不通（{type(e).__name__}）"))
    return results


def scan_memory_dirs(mounts):
    found = []
    for raw in MEMORY_DIR_CANDIDATES:
        p = os.path.expanduser(raw)
        if os.path.isdir(p):
            mp, fstype, _ = mount_for(p, mounts)
            kind, desc = classify_fs(fstype)
            n_files = 0
            for _, _, files in os.walk(p):
                n_files += len(files)
                if n_files > 500:
                    break
            found.append({"path": p, "mount": mp, "fs": fstype,
                          "kind": kind, "desc": desc, "files": n_files})
    return found


def gather(target_dir):
    mounts = read_mounts()
    home_mp, home_fs, _ = mount_for(os.path.expanduser("~"), mounts)
    cwd_mp, cwd_fs, _ = mount_for(target_dir, mounts)
    tmp_mp, tmp_fs, _ = mount_for("/tmp", mounts)
    up = uptime_seconds()
    lim = cgroup_limits()

    findings = []

    def add(sev, title, detail, advice):
        findings.append({"severity": sev, "title": title, "detail": detail, "advice": advice})

    home_kind, _ = classify_fs(home_fs)
    cwd_kind, _ = classify_fs(cwd_fs)
    tmp_kind, _ = classify_fs(tmp_fs)

    if home_kind == "volatile":
        add("high", "家目录在内存盘上", f"~ 挂载在 {home_fs}（{home_mp}）",
            "家目录内容会随实例重启清空。把需要长期保留的记忆/配置迁移到持久卷，或每次会话开始时从外部同步。")
    elif home_kind == "ephemeral":
        add("high", "家目录疑似随实例销毁", f"~ 挂载在 {home_fs}（{home_mp}）",
            "容器叠加层通常不随实例保留。重要记忆文件应同步到外部仓库或持久卷，不要只存在家目录。")
    elif home_kind == "persistent":
        add("info", "家目录在真实磁盘卷上", f"~ 挂载在 {home_fs}（{home_mp}）",
            "相对安全，但仍建议用跨重启探针（--plant / --check）实测确认。")
    elif home_kind == "shared":
        add("info", "家目录在共享卷上", f"~ 挂载在 {home_fs}（{home_mp}）",
            "宿主机挂载的共享卷通常能活过重启；用跨重启探针（--plant / --check）实测确认。")
    else:
        add("medium", "家目录文件系统类型未知", f"~ 挂载在 {home_fs}（{home_mp}）",
            "用 --plant 播种探针，重启后再 --check 实测存活情况。")

    if tmp_kind == "volatile":
        add("medium", "/tmp 是内存盘", f"/tmp 挂载在 {tmp_fs}",
            "放在 /tmp 的任何东西重启即失。临时文件可以放这里，长期数据不要。")

    if cwd_kind in ("volatile", "ephemeral") and cwd_mp != home_mp:
        add("high", "当前工作目录疑似易失", f"{target_dir} 挂载在 {cwd_fs}（{cwd_mp}）",
            "智能体的项目文件、记忆文件如果放在这里，实例销毁就全没了。迁移到持久卷或纳入外部版本管理。")

    mem_dirs = scan_memory_dirs(mounts)
    for d in mem_dirs:
        if d["kind"] in ("volatile", "ephemeral"):
            add("high", f"记忆目录易失：{d['path']}", f"挂载在 {d['fs']}（{d['mount']}），约 {d['files']} 个文件",
                "这个目录里的记忆会随实例销毁。立即迁移到持久卷，或配置定期外发备份。")
        else:
            add("info", f"记忆目录在 {d['kind']} 卷：{d['path']}", f"挂载在 {d['fs']}（{d['mount']}）",
                "位置相对安全；用 --plant / --check 实测确认。")

    if not mem_dirs:
        add("medium", "未发现常见记忆目录", "常见路径（~/.memory、~/memories 等）均不存在",
            "智能体可能把记忆存在别处或根本没有持久记忆。确认你的 AI 把记忆写在哪里，再针对性检查。")

    if up is not None and up < 86400:
        add("info", f"实例运行时间不足一天（{up/3600:.1f} 小时）", "较新的实例，可能近期被重建过",
            "结合 --check 的探针结果判断：如果上次播种的标记消失了，说明实例确实被重置过。")

    mem_raw = lim.get("memory_bytes")
    mem_limit = None
    if mem_raw and mem_raw not in ("max", "-1"):
        try:
            mem_limit = int(mem_raw)
        except ValueError:
            pass
    if mem_limit:
        add("info", f"内存配额约 {human_bytes(mem_limit)}", "来自容器配额",
            "大模型推理或长上下文任务注意别超配额，超限会被强制终止。")

    try:
        du = shutil.disk_usage(target_dir)
        add("info", f"磁盘可用空间 {human_bytes(du.free)}（共 {human_bytes(du.total)}）",
            f"挂载点 {cwd_mp}", "空间紧张时智能体写入记忆会静默失败，留至少 10% 余量。")
    except Exception:
        pass

    if os.path.exists("/.dockerenv"):
        add("info", "检测到容器环境", "/.dockerenv 存在", "容器实例的持久性取决于平台卷挂载，以探针实测为准。")

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return {
        "generated_at": now_str(),
        "target_dir": target_dir,
        "platform": {"system": platform.system(), "release": platform.release(),
                     "python": platform.python_version(), "hostname": platform.node()},
        "uptime_seconds": up,
        "mounts": [{"mount": mp, "fs": fs, "device": dev,
                    "kind": classify_fs(fs)[0]} for mp, fs, dev in user_relevant_mounts(mounts)],
        "memory_dirs": mem_dirs,
        "cgroup_limits": lim,
        "findings": findings,
    }


def plant_markers(target_dir):
    os.makedirs(REPORT_DIR, exist_ok=True)
    registry = {}
    if os.path.exists(MARKER_REGISTRY):
        with open(MARKER_REGISTRY) as f:
            try:
                registry = json.load(f)
            except Exception:
                registry = {}
    planted = []
    candidates = [os.path.expanduser("~"), target_dir, "/tmp"] + [
        os.path.expanduser(p) for p in MEMORY_DIR_CANDIDATES]
    seen = set()
    for d in candidates:
        if not d or d in seen or not os.path.isdir(d):
            continue
        seen.add(d)
        token = uuid.uuid4().hex
        marker_path = os.path.join(d, MARKER_NAME)
        try:
            with open(marker_path, "w") as f:
                f.write(token)
            registry[d] = {"token": token, "planted_at": now_str()}
            planted.append(d)
        except Exception as e:
            planted.append(f"{d}（写入失败：{type(e).__name__}）")
    with open(MARKER_REGISTRY, "w") as f:
        json.dump(registry, f, ensure_ascii=False, indent=1)
    return planted


def check_markers():
    if not os.path.exists(MARKER_REGISTRY):
        return {"status": "no_registry", "note": "没有找到播种记录。先在重启前运行 --plant。"}
    with open(MARKER_REGISTRY) as f:
        registry = json.load(f)
    results = []
    for d, info in registry.items():
        marker_path = os.path.join(d, MARKER_NAME)
        if not os.path.exists(marker_path):
            results.append({"dir": d, "status": "lost",
                            "note": f"标记消失——该目录未在实例重建中保留（播种于 {info['planted_at']}）"})
            continue
        with open(marker_path) as f:
            token = f.read().strip()
        if token == info["token"]:
            results.append({"dir": d, "status": "survived", "note": "标记原样保留——该目录确实持久"})
        else:
            results.append({"dir": d, "status": "rewritten",
                            "note": "标记存在但内容不同——目录被重建过（同路径新实例）"})
        try:
            os.remove(marker_path)
        except Exception:
            pass
    os.remove(MARKER_REGISTRY)
    return {"status": "ok", "checked_at": now_str(), "results": results}


def render_md(data):
    lines = [f"# 记忆存活性体检报告", "",
             f"- 生成时间：{data['generated_at']}",
             f"- 被检目录：`{data['target_dir']}`",
             f"- 系统：{data['platform']['system']} {data['platform']['release']}（Python {data['platform']['python']}）",
             f"- 主机名：`{data['platform']['hostname']}`", ""]
    up = data.get("uptime_seconds")
    if up is not None:
        lines.append(f"- 实例已运行：{up/3600:.1f} 小时")
    lines += ["", "## 会丢什么、能留什么", "",
              "| 位置 | 文件系统 | 判断 |", "|---|---|---|"]
    for m in data["mounts"]:
        label = {"volatile": "⚠️ 重启即失", "ephemeral": "⚠️ 疑似随实例销毁",
                 "persistent": "✅ 通常持久", "shared": "✅ 共享卷（通常持久）",
                 "unknown": "❓ 未知，建议探针实测"}[m["kind"]]
        lines.append(f"| `{m['mount']}` | {m['fs']} | {label} |")
    lines += ["", "## 发现（按严重程度）", ""]
    sev_label = {"high": "🔴 高", "medium": "🟡 中", "low": "🔵 低", "info": "⚪ 信息"}
    for f_ in data["findings"]:
        lines += [f"### {sev_label[f_['severity']]} {f_['title']}", "",
                  f_["detail"], "", f"**建议**：{f_['advice']}", ""]
    if data.get("memory_dirs"):
        lines += ["## 记忆目录盘点", "",
                  "| 路径 | 挂载点 | 类型 | 文件数 |", "|---|---|---|---|"]
        for d in data["memory_dirs"]:
            lines.append(f"| `{d['path']}` | `{d['mount']}` | {d['kind']} | {d['files']} |")
        lines.append("")
    lines += ["## 下一步", "",
              "1. 高危项先处理：把易失目录里的记忆迁移到持久卷或外部仓库。",
              "2. 用跨重启探针实测：重启前 `--plant`，重启后 `--check`，报告会告诉你哪些目录真的能活。",
              "3. 把本报告（不含任何敏感内容）发给你的服务商，可换取针对性的持久化改造方案。", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="记忆存活性体检（只读）")
    ap.add_argument("target", nargs="?", default=os.getcwd(), help="被检目录，默认当前目录")
    ap.add_argument("--plant", action="store_true", help="播种跨重启探针标记")
    ap.add_argument("--check", action="store_true", help="收获探针标记（重启后运行）")
    ap.add_argument("--net", action="store_true", help="附带出口网络检测")
    ap.add_argument("--output", default=REPORT_DIR, help="报告输出目录")
    args = ap.parse_args()

    if args.check:
        result = check_markers()
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return
    if args.plant:
        planted = plant_markers(args.target)
        print("已在以下位置播种标记（重启后运行 --check 收获）：")
        for p in planted:
            print(f"  {p}")
        return

    data = gather(args.target)
    if args.net:
        data["network"] = [{"host": h, "result": r} for h, r in net_check()]

    os.makedirs(args.output, exist_ok=True)
    md_path = os.path.join(args.output, "memory_persistence_report.md")
    json_path = os.path.join(args.output, "memory_persistence_report.json")
    with open(md_path, "w") as f:
        f.write(render_md(data))
    with open(json_path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    counts = {}
    for f_ in data["findings"]:
        counts[f_["severity"]] = counts.get(f_["severity"], 0) + 1
    print(f"体检完成：高危 {counts.get('high', 0)} · 中危 {counts.get('medium', 0)} · "
          f"低危 {counts.get('low', 0)} · 信息 {counts.get('info', 0)}")
    print(f"报告：{md_path}")
    if counts.get("high", 0) > 0:
        print("存在高危项：你的部分记忆大概率活不过下一次实例重建，建议先处理高危项。")
    print("提示：重启前运行 --plant、重启后运行 --check，可实测各目录的真实存活情况。")


if __name__ == "__main__":
    main()
