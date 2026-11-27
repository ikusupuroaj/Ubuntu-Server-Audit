#!/usr/bin/env python3
"""Ubuntu-Server-Audit｜官方資料更新（update-data.py）

版本：0.8.0
在「能上網」的電腦執行（Python 3.6 以上，只用標準函式庫）。從 Canonical 官方網站下載
套件清單版的 OVAL 弱點資料，並留下來源紀錄，方便帶進離線環境後核對。

用法：
  python3 update-data.py                     # 下載所有 LTS 版本到 data/（已是最新就跳過）
  python3 update-data.py --releases 20.04,22.04     # 用版本號或代號（focal,jammy）都可以
  python3 update-data.py --from github       # 連不到 Canonical 時，改從本專案 GitHub 每天更新的副本下載
  python3 update-data.py --verify            # 核對 data/ 內檔案與下載紀錄是否一致（離線環境也能跑）
  python3 update-data.py --list              # 列出目前資料的日期

用 git clone 下載本專案時，GitHub 上每天更新的資料（data 分支）會一起下載下來；
hc 第一次執行時會自動把它放進 data/，不需要網路。之後執行 git pull 就會帶回最新的一份。

產出（data/ 資料夾）：
  oci.com.ubuntu.<代號>.usn.oval.xml.bz2   官方原始檔，未經修改
  SOURCES.json                              每個檔案的下載網址、官方更新時間、下載時間、SHA-256
  SHA256SUMS                                可用 `sha256sum -c SHA256SUMS` 核對

資料來源：https://security-metadata.canonical.com/oval/
說明文件：https://documentation.ubuntu.com/security/security-updates/oval/
需要經過 Proxy 時，設定環境變數 https_proxy 即可。
"""
import argparse
import bz2
import datetime

import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request

VERSION = "0.6"
BASE = "https://security-metadata.canonical.com/oval/"
# 本專案在 GitHub 上每天更新的副本（data 分支，內容是官方原始檔，未經修改）
MIRROR_REPO = "ikusupuroaj/Ubuntu-Server-Audit"
MIRROR = os.environ.get("HC_MIRROR") or "https://raw.githubusercontent.com/%s/data/" % MIRROR_REPO  # HC_MIRROR 只在測試時用
DATA_REF = "refs/remotes/origin/data"
# LTS 版本代號與版本號（使用者多半記版本號，畫面上兩個一起顯示）
LTS_VERSIONS = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04",
                "jammy": "22.04", "noble": "24.04", "resolute": "26.04"}
LTS = list(LTS_VERSIONS)


def label(code):
    v = LTS_VERSIONS.get(code)
    return "%s（%s）" % (code, v) if v else code


def label_of_file(name):
    m = re.match(r"oci\.com\.ubuntu\.([a-z]+)\.", name)
    return label(m.group(1)) if m else name
HERE = os.path.dirname(os.path.abspath(__file__))


def fname(code):
    return "oci.com.ubuntu.%s.usn.oval.xml.bz2" % code


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_sources(dest):
    p = os.path.join(dest, "SOURCES.json")
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            pass
    return {"source": BASE, "files": {}}


def save_sources(dest, src):
    p = os.path.join(dest, "SOURCES.json")
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(src, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(p + ".tmp", p)
    with open(os.path.join(dest, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for n, r in sorted(src["files"].items()):
            f.write("%s  %s\n" % (r["sha256"], n))


def check_content(path):
    """確認是可解壓、套件清單版的官方 OVAL；回傳官方產生時間。"""
    head = b""
    d = bz2.BZ2Decompressor()
    with open(path, "rb") as f:
        while len(head) < 4000:
            chunk = f.read(65536)
            if not chunk:
                break
            head += d.decompress(chunk)
    text = head.decode("utf-8", "replace")
    if "<oval_definitions" not in text:
        raise ValueError("內容不是 OVAL 資料")
    m = re.search(r"<oval:timestamp>([^<]+)</oval:timestamp>", text)
    # 完整解壓一次，確保檔案沒有截斷，並確認是套件清單版
    with bz2.open(path, "rb") as f:
        tail_ok = False
        manifest = False
        prev = b""
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            buf = prev + chunk  # 保留上一段的結尾，避免標記剛好被切開
            if b"<ind-def:filename>manifest</ind-def:filename>" in buf:
                manifest = True
            if b"</oval_definitions>" in buf:
                tail_ok = True
            prev = chunk[-64:]
    if not tail_ok:
        raise ValueError("檔案不完整")
    if not manifest:
        raise ValueError("不是套件清單版（oci.）的 OVAL")
    return m.group(1) if m else ""


def download(code, dest, src, timeout, quiet):
    name = fname(code)
    url = BASE + name
    rec = src["files"].get(name, {})
    target = os.path.join(dest, name)
    req = urllib.request.Request(url, headers={"User-Agent": "Ubuntu-Server-Audit/%s" % VERSION})
    if rec.get("last_modified") and os.path.isfile(target) and sha256(target) == rec.get("sha256"):
        req.add_header("If-Modified-Since", rec["last_modified"])
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 304:
            if not quiet:
                print("  %s 已是最新（官方更新時間 %s）" % (label(code), rec.get("last_modified")))
            return True
        print("  %s 下載失敗：HTTP %d" % (label(code), e.code), file=sys.stderr)
        return False
    except (urllib.error.URLError, OSError) as e:
        print("  %s 下載失敗：%s" % (label(code), e), file=sys.stderr)
        return False
    fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=dest)
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        stamp = check_content(tmp)
        os.chmod(tmp, 0o644)  # mkstemp 預設 0600；改成其他帳號也能讀，方便放在共用分析主機
        os.replace(tmp, target)
    except Exception as e:
        os.path.exists(tmp) and os.remove(tmp)
        print("  %s 內容檢查失敗，保留舊檔：%s" % (label(code), e), file=sys.stderr)
        return False
    src["files"][name] = {
        "url": url,
        "last_modified": resp.headers.get("Last-Modified", ""),
        "downloaded_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator_timestamp": stamp,
        "size": os.path.getsize(target),
        "sha256": sha256(target),
    }
    if not quiet:
        print("  %s 已下載（官方產生時間 %s）" % (label(code), stamp))
    return True


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def adopt(name, dest, src, rec, fetch, where, quiet):
    """從副本（git 的 data 分支或 GitHub）取一個資料檔。
    本機已有同一份或比較新的就不動；取回後核對 SHA-256 與內容，才換掉舊檔。回傳 "same"、"updated" 或 "failed"。"""
    target = os.path.join(dest, name)
    local = src["files"].get(name, {})
    if (os.path.isfile(target) and local.get("sha256") == sha256(target)
            and local.get("generator_timestamp", "") >= rec.get("generator_timestamp", "")):
        return "same"
    fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=dest)
    os.close(fd)
    try:
        fetch(name, tmp)
        if sha256(tmp) != rec.get("sha256"):
            raise ValueError("SHA-256 與副本的清單不符")
        stamp = check_content(tmp)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except Exception as e:
        os.path.exists(tmp) and os.remove(tmp)
        print("  %s 取得失敗，保留舊檔：%s" % (label_of_file(name), e), file=sys.stderr)
        return "failed"
    new = dict(rec)
    new.update(generator_timestamp=stamp, copied_from=where, copied_at=now_utc())
    src["files"][name] = new
    if not quiet:
        print("  %s 已更新（官方產生時間 %s）" % (label_of_file(name), stamp))
    return "updated"


def _git(args, **kw):
    import subprocess
    return subprocess.run(["git", "-C", HERE] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def sync_from_git(dest, quiet=True):
    """把 git clone 時一起下載的 data 分支放進 data/，不需要網路。
    不是用 git 下載、或沒有 data 分支時回傳 None；否則回傳更新了幾個檔案。"""
    if not os.path.isdir(os.path.join(HERE, ".git")):
        return None
    try:
        p = _git(["rev-parse", "--verify", "-q", DATA_REF + "^{commit}"], timeout=30)
    except (OSError, Exception):
        return None
    if p.returncode != 0:
        return None
    commit = p.stdout.decode().strip()
    os.makedirs(dest, exist_ok=True)
    marker = os.path.join(dest, ".from-git-commit")
    try:
        with open(marker, encoding="utf-8") as f:
            if f.read().strip() == commit:
                return 0
    except OSError:
        pass
    p = _git(["show", "%s:SOURCES.json" % commit], timeout=60)
    try:
        bundled = json.loads(p.stdout.decode("utf-8")) if p.returncode == 0 else {}
    except ValueError:
        bundled = {}
    if not bundled.get("files"):
        return None

    def fetch(name, tmp):
        with open(tmp, "wb") as f:
            q = _git(["cat-file", "blob", "%s:%s" % (commit, name)], timeout=300)
            if q.returncode != 0:
                raise ValueError("git 裡找不到這個檔案")
            f.write(q.stdout)

    src = load_sources(dest)
    n, failed = 0, 0
    for name, rec in sorted(bundled["files"].items()):
        r = adopt(name, dest, src, rec, fetch, "git data 分支 %s" % commit[:12], quiet)
        n += r == "updated"
        failed += r == "failed"
    save_sources(dest, src)
    if not failed:  # 有檔案失敗就不記號，下次執行再試
        with open(marker, "w", encoding="utf-8") as f:
            f.write(commit + "\n")
    return n


def from_github(dest, codes, timeout, quiet):
    """連不到 Canonical 時，從本專案 GitHub 上每天更新的副本下載。"""
    ua = {"User-Agent": "Ubuntu-Server-Audit/%s" % VERSION}
    try:
        with urllib.request.urlopen(urllib.request.Request(MIRROR + "SOURCES.json", headers=ua), timeout=timeout) as r:
            mirror = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        print("  無法讀取 GitHub 上的資料清單：%s" % e, file=sys.stderr)
        return 1

    def fetch(name, tmp):
        with urllib.request.urlopen(urllib.request.Request(MIRROR + name, headers=ua), timeout=timeout) as r, \
                open(tmp, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)

    src = load_sources(dest)
    fail = 0
    for c in codes:
        name = fname(c)
        rec = mirror.get("files", {}).get(name)
        if not rec:
            print("  %s：GitHub 上沒有這個版本的資料" % label(c), file=sys.stderr)
            fail += 1
            continue
        r = adopt(name, dest, src, rec, fetch, MIRROR, quiet)
        if r == "same" and not quiet:
            print("  %s 已是最新（官方產生時間 %s）" % (label(c), src["files"][name].get("generator_timestamp", "?")))
        fail += r == "failed"
        save_sources(dest, src)
    return 1 if fail else 0


def verify(dest):
    src = load_sources(dest)
    if not src["files"]:
        print("找不到下載紀錄（%s/SOURCES.json）" % dest, file=sys.stderr)
        return 1
    bad = 0
    for name, r in sorted(src["files"].items()):
        p = os.path.join(dest, name)
        if not os.path.isfile(p):
            print("  缺檔    %s　%s" % (label_of_file(name), name))
            bad += 1
        elif sha256(p) != r.get("sha256"):
            print("  不一致  %s　%s（檔案在下載後被改過或損毀，請重新下載）" % (label_of_file(name), name))
            bad += 1
        else:
            print("  一致    %s　官方產生時間 %s" % (label_of_file(name), r.get("generator_timestamp", "?")))
    return 1 if bad else 0


def main():
    class ZhHelp(argparse.RawDescriptionHelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            return super().add_usage(usage, actions, groups, prefix="用法：")

        def format_help(self):
            return super().format_help().replace(":\n", "：\n")
    ap = argparse.ArgumentParser(description="下載或核對 Canonical 官方 OVAL 弱點資料（掃描時用來比對還沒裝的安全更新）",
                                 formatter_class=ZhHelp, add_help=False,
                                 epilog="範例：\n  ./hc update                      下載全部 LTS 版本的最新資料\n"
                                        "  ./hc update --releases 20.04,22.04\n"
                                        "  ./hc update --from github        連不到 Canonical 官方網站時改用 GitHub 副本\n"
                                        "  ./hc update --list               看目前資料的日期\n"
                                        "  ./hc update --verify             帶進離線環境後，核對官方資料有沒有被改過或損毀")
    ap._optionals.title = "選項"
    ap.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="顯示這份說明")
    ap.add_argument("--dest", default=os.path.join(HERE, "data"), help="存放資料的資料夾（預設：程式旁的 data/）")
    ap.add_argument("--releases", default=",".join(LTS), help="版本號或代號，以逗號分隔，例如 20.04,22.04（預設：全部 LTS）")
    ap.add_argument("--from", dest="source", choices=["canonical", "github"], default="canonical",
                    help="下載來源：canonical 官方網站（預設）；github 本專案每天更新的副本（連不到官方時用）")
    ap.add_argument("--verify", action="store_true", help="只核對，不下載")
    ap.add_argument("--list", action="store_true", help="列出目前資料的日期")
    ap.add_argument("--timeout", type=int, default=120, help="每個檔案下載的逾時秒數（預設 120）")
    ap.add_argument("--quiet", action="store_true", help="只輸出錯誤（排程用）")
    args = ap.parse_args()

    os.makedirs(args.dest, exist_ok=True)
    if os.path.abspath(args.dest) == os.path.join(HERE, "data"):
        try:  # 用 git 下載的，先把一起下載的內建資料放進來，--list、--verify 才看得到
            n = sync_from_git(args.dest, quiet=True)
            if n and not args.quiet:
                print("已從 git 下載的內建資料放入 %d 個版本（不需要網路）" % n)
        except Exception as e:
            print("注意：無法讀取 git 裡的內建官方資料（%s）" % e, file=sys.stderr)
    if args.verify:
        return verify(args.dest)
    if args.list:
        for n, r in sorted(load_sources(args.dest)["files"].items()):
            print("%s　官方產生 %s　取得 %s%s" % (label_of_file(n), r.get("generator_timestamp", "?"),
                                          r.get("copied_at") or r.get("downloaded_at", "?"),
                                          "（來自 GitHub 副本）" if r.get("copied_from") else ""))
        return 0
    by_ver = {v: c for c, v in LTS_VERSIONS.items()}
    codes = [by_ver.get(c.strip(), c.strip()) for c in args.releases.split(",") if c.strip()]
    bad = [c for c in codes if not re.match(r"^[a-z]+$", c)]
    if bad:
        ap.error("看不懂的版本：%s（請用 20.04 這類版本號或 focal 這類代號）" % ", ".join(bad))
    if args.source == "github":
        if not args.quiet:
            print("來源：%s（本專案每天從 Canonical 官方網站取得的副本，檔案未經修改）" % MIRROR)
        rc = from_github(args.dest, codes, args.timeout, args.quiet)
        if rc:
            print("有版本沒有更新成功（見上方訊息），其餘已完成。資料夾：%s" % args.dest, file=sys.stderr)
        elif not args.quiet:
            print("完成。資料夾：%s（帶進離線環境後，執行 ./hc update --verify 核對）" % args.dest)
        return rc
    src = load_sources(args.dest)
    if not args.quiet:
        print("來源：%s" % BASE)
    fail = 0
    for c in codes:
        if not download(c, args.dest, src, args.timeout, args.quiet):
            fail += 1
        save_sources(args.dest, src)
    if fail:
        print("有 %d 個版本沒有更新成功（見上方訊息）。連不到 Canonical 官方網站時，可改用：./hc update --from github" % fail,
              file=sys.stderr)
    elif not args.quiet:
        print("完成。資料夾：%s（帶進離線環境後，執行 ./hc update --verify 核對）" % args.dest)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
