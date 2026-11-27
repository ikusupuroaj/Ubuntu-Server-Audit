#!/usr/bin/env python3
"""Ubuntu-Server-Audit｜統一入口（hc）

版本：0.8.1
一個指令完成收集與分析。只用 Python 3.6 以上的標準函式庫。

不熟指令的話，直接輸入 ./hc（後面不加任何字）會出現選單，一步一步帶你做完。
主機清單、收集檔都可以在選單裡處理，不用自己記指令。

常用指令（都在 Ubuntu-Server-Audit 資料夾裡執行）：
  ./hc                         開啟選單
  ./hc local                   檢查這台電腦自己（會先試 sudo，可能問你的登入密碼；不能用 sudo 就自動改用一般權限）
  ./hc local --no-sudo         不用 sudo、不問密碼，直接用一般權限檢查這台電腦
  ./hc scan                    用 SSH 逐台檢查主機清單 inventory.txt 上的主機（主機上不留下任何檔案）
  ./hc report 收集檔...         分析主機管理者交回來的收集檔（hc-*.tar.gz）
  ./hc update                  從 Canonical 官方網站更新弱點資料（要能上網）
  ./hc update --verify         帶進離線環境後，核對官方資料有沒有被改過或損毀
  ./hc --version               顯示版本

用一般權限檢查時，SSH 設定、主機防火牆、空密碼帳號 3 項讀不到，報告會列在「未能檢查」，其他項目照常檢查。

主機清單 inventory.txt 每行一台：「代號  帳號@IP  [其他 ssh 參數]」，例如：
  H01  admin@10.0.0.5
  H02  ops@10.0.0.6 -p 2222      ← 「-p 2222」只有 SSH 不是 22 埠時才需要
「#」開頭是註解。代號會出現在報告上，帳號與 IP 不會。範本：inventory.example.txt。
0.7 以前的 hosts.txt 照樣可以用：./hc scan hosts.txt

用 git clone 下載時，GitHub 上每天更新的官方資料會一起下載，第一次執行時自動放進 data/。

每個指令都可以加 -h 看完整說明，例如：./hc scan -h
"""
import argparse
import datetime
import importlib.util
import re
import os
import ipaddress
import shlex
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze as A  # noqa: E402

COLLECT = os.path.join(HERE, "collect.sh")


def load_updater():
    spec = importlib.util.spec_from_file_location("update_data", os.path.join(HERE, "update-data.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def is_gzip(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def tilde(path):
    """畫面上顯示的完整路徑，家目錄寫成 ~。"""
    path = os.path.abspath(path)
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if home not in ("", "/") and (path == home or path.startswith(home + os.sep)) else path


def ask(question, default_no=True):
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(question + (" [y/N] " if default_no else " [Y/n] ")).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes") if default_no else ans not in ("n", "no")


# ---------------------------------------------------------------------------
# 掃描前：確認官方資料
# ---------------------------------------------------------------------------
TAG_RX = re.compile(r"^[A-Za-z0-9._-]{1,40}$")


def check_tag(tag, where):
    if not TAG_RX.match(tag):
        sys.exit("錯誤：%s 的代號「%s」只能用英文字母、數字與 . _ -（最多 40 字）" % (where, tag))
    return tag


def do_update(args, codes):
    up = load_updater()
    os.makedirs(args.data, exist_ok=True)
    src = up.load_sources(args.data)
    for code in codes:
        up.download(code, args.data, src, 120, False)
        up.save_sources(args.data, src)


DEFAULT_DATA = os.path.join(HERE, "data")


def sync_bundled(args):
    """用 git clone 下載時，把一起下載的 data 分支放進 data/（不需要網路）。"""
    if args.oval or os.path.abspath(args.data) != DEFAULT_DATA:
        return
    try:
        n = load_updater().sync_from_git(args.data, quiet=True)
    except Exception as e:  # 內建資料取不到不影響其他功能
        print("注意：無法讀取 git 裡的內建官方資料（%s）" % e)
        return
    if n:
        print("已從 git 下載的內建資料放入 %d 個版本的官方弱點資料（不需要網路）" % n)


CHECK_TIMEOUT = 15  # --refresh-data 連線檢查的逾時秒數


def refresh(args, codes):
    """向 Canonical 檢查這些版本有沒有新資料，有就下載。連不上就停，不再試其他版本、也不中斷掃描。
    回傳 {代號: "updated"／"same"／"failed"／"skipped"}。"""
    up = load_updater()
    os.makedirs(args.data, exist_ok=True)
    src = up.load_sources(args.data)
    result, offline = {}, False
    print("向 Canonical 檢查官方資料（最多等 %d 秒）…" % CHECK_TIMEOUT)
    for code in codes:
        if offline:
            result[code] = "skipped"
            continue
        before = src["files"].get(up.fname(code), {}).get("sha256")
        if up.download(code, args.data, src, CHECK_TIMEOUT, True):
            up.save_sources(args.data, src)
            result[code] = "same" if src["files"].get(up.fname(code), {}).get("sha256") == before else "updated"
        else:
            result[code] = "failed"
            offline = True
    args.offline = offline
    return result


def local_codename(rules):
    """hc local：這台機器自己的版本代號（讀 /etc/os-release）。"""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            osr = A.parse_kv(f.read())
    except OSError:
        return None
    return (rules["lifecycle"].get(osr.get("VERSION_ID", "")) or {}).get("codename") or osr.get("VERSION_CODENAME") or None


SOURCE_TEXT = {"updated": "剛從 Canonical 更新", "same": "已向 Canonical 確認是最新的一份",
               "failed": "無法連線，改用已下載的資料", "skipped": "無法連線，改用已下載的資料"}


def data_statement(args, rules, codes, found, status):
    """開始收集前，在畫面說明這次用的官方資料來源與時間點。"""
    print("本次使用的官方弱點資料（%s）：" % args.data)
    if not codes:
        print("  還沒有任何版本的資料")
        return
    for code in codes:
        ds = found.get(code)
        st = status.get(code)
        if not ds:
            print("  %s：沒有資料檔%s" % (A.code_label(rules, code), "（無法連線，沒辦法下載）" if st in ("failed", "skipped") else ""))
            continue
        ts, age = A.quick_data_info(ds["path"])
        print("  %s：官方產生於 %s（%s 天前），%s" % (A.code_label(rules, code), ts[:10] or "?",
                                              age if age is not None else "?", SOURCE_TEXT.get(st, "使用已下載的資料")))


def preflight_data(args, rules, codes=None):
    """收集之前先看一次官方資料，並在畫面說明這次用哪一份。
    加 --refresh-data 時先向 Canonical 檢查新資料；連不上就用已下載的，不中斷。
    沒加時，資料都沒有或有過舊的，先問要不要更新，免得收完才發現。
    codes：已知要用到的版本（local、report）；scan 收集前還不知道主機版本，就看已下載的那些。"""
    args.offline = False
    if args.oval:
        ts, age = A.quick_data_info(args.oval)
        print("本次使用的官方弱點資料：指定的資料檔 %s（官方產生於 %s，%s 天前）"
              % (os.path.basename(args.oval), ts[:10] or "?", age if age is not None else "?"))
        return
    sync_bundled(args)
    try:
        found = A.find_datasets(args)
    except ValueError as e:
        sys.exit("錯誤：%s" % e)
    ver = {lc.get("codename"): v for v, lc in rules["lifecycle"].items()}
    targets = sorted(codes or found, key=lambda c: (ver.get(c, "99"), c))  # 依版本號排列
    if args.refresh_data:
        status = refresh(args, targets) if targets else {}
        found = A.find_datasets(args)
        args.asked_stale = True  # 已經向官方確認過，收集完不再問過舊的資料
        if not args.offline and args.update == "ask":
            args.update = "yes"  # 收集後才知道缺的版本，也直接下載
        data_statement(args, rules, targets, found, status)
        if found or args.offline:  # 連不上時，缺資料的版本在收集後統一提醒一次
            return
    else:
        data_statement(args, rules, targets, found, {})
    lim = rules["thresholds"]["data_max_age_days"]
    stale = []
    for code, ds in sorted(found.items()):
        ts, age = A.quick_data_info(ds["path"])
        if age is not None and age > lim:
            stale.append(code)
    if not found:
        print("注意：%s 裡沒有官方弱點資料。" % args.data)
        todo = [lc["codename"] for lc in rules["lifecycle"].values()]
    elif stale:
        print("注意：這些版本的官方資料已超過 %d 天：%s" % (lim, "、".join(A.code_label(rules, c) for c in stale)))
        todo = stale
    else:
        return
    args.asked_stale = True  # 已經問過過舊的資料，收集完不再重問同一件事
    if args.update == "yes" or (args.update == "ask" and ask("要先從 Canonical 官方網站下載最新資料嗎？（需要網路）")):
        do_update(args, todo)
    else:
        args.declined_update = True  # 使用者說不要，收集完不再問同一件事
        print("　沒有網路時照樣可以分析，只是之後公布的弱點不會列入。能上網時可執行 ./hc update，"
              "或在 git 下載的資料夾執行 git pull 取得 GitHub 上每天更新的一份。")


def check_data(loaded, args, rules):
    """列出這次會用到的官方資料與日期；缺少或過舊時詢問要不要先更新。"""
    need = sorted(A.needed_codenames(loaded, rules))
    if not need:
        return
    try:
        found = A.find_datasets(args)
    except ValueError as e:
        sys.exit("錯誤：%s" % e)
    lim = rules["thresholds"]["data_max_age_days"]
    missing, stale = [], []
    for code in need:
        ds = found.get(code)
        if not ds:
            missing.append(code)
            continue
        ts, age = A.quick_data_info(ds["path"])
        if age is not None and age > lim:
            stale.append(code)
    if not (missing or stale):
        return  # 資料日期在最後的摘要會列出，這裡不重複
    if getattr(args, "offline", False) and missing:  # --refresh-data 剛確認連不上，不再試一次
        print("注意：%s 沒有官方資料，這些主機只能參考 Ubuntu Pro 用戶端；能上網時執行 ./hc update 再重跑。"
              % "、".join(A.code_label(rules, c) for c in missing))
        return
    print("官方弱點資料（%s）：" % (args.oval or args.data))
    for code in missing:
        print("  %s：沒有資料檔" % A.code_label(rules, code))
    for code in stale:
        ts, age = A.quick_data_info(found[code]["path"])
        print("  %s：官方產生於 %s（%s 天前），已超過 %d 天" % (A.code_label(rules, code), ts[:10] or "?", age, lim))
    if args.oval:  # 使用者指定了單一資料檔，就不自動下載，只說明
        if missing:
            print("注意：指定的資料檔不涵蓋 %s，這些主機只能參考 Ubuntu Pro 用戶端；請改用 --data 指定含所有版本的資料夾。"
                  % "、".join(A.code_label(rules, c) for c in missing))
        if stale:
            print("注意：指定的資料檔已超過 %d 天。" % lim)
        return
    if getattr(args, "asked_stale", False):
        stale = []
        if not missing:
            return
    todo = missing + stale
    if getattr(args, "declined_update", False):
        print("注意：缺少資料的版本，只能參考主機上的 Ubuntu Pro 用戶端；可先執行 ./hc update 再重跑。")
        return
    if args.update == "yes" or (args.update == "ask" and ask("要先從 Canonical 官方網站下載最新資料嗎？（需要網路）")):
        do_update(args, todo)
    elif missing:
        print("注意：缺少資料的版本，只能參考主機上的 Ubuntu Pro 用戶端；可先執行 ./hc update 再重跑。")


def finish(loaded, args, rules):
    check_data(loaded, args, rules)
    try:
        hosts, datasets, warnings = A.run_analysis(
            loaded, args, rules, log=lambda m: m.startswith("警告") and print(m, file=sys.stderr))
    except (RuntimeError, ValueError) as e:
        sys.exit("錯誤：%s" % e)
    A.print_summary(hosts, datasets, warnings, args, rules)


# ---------------------------------------------------------------------------
# 子指令
# ---------------------------------------------------------------------------
def parse_hosts(path):
    hosts = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = shlex.split(line)
            if len(parts) < 2:
                sys.exit("錯誤：%s 第 %d 行格式不對，應為「代號 SSH目標 [ssh 參數]」" % (path, n))
            tag = check_tag(parts[0], "%s 第 %d 行" % (path, n))
            if tag in [h[0] for h in hosts]:
                sys.exit("錯誤：%s 第 %d 行的代號「%s」重複了，每台主機的代號要不同" % (path, n, tag))
            hosts.append((tag, parts[1], parts[2:]))
    if not hosts:
        sys.exit("錯誤：%s 裡沒有主機" % path)
    return hosts


def collect_via(cmd, out_path, use_stdin=True, timeout=900):
    """執行收集指令，把標準輸出存成 tar.gz；回傳 (成功, 錯誤訊息)。"""
    with open(out_path, "wb") as out:
        stdin = open(COLLECT, "rb") if use_stdin else None
        try:
            p = subprocess.run(cmd, stdin=stdin, stdout=out, stderr=subprocess.PIPE, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError, KeyboardInterrupt) as e:
            out.close()
            os.remove(out_path)
            if isinstance(e, KeyboardInterrupt):
                raise
            return False, ("超過 %d 秒沒有完成" % timeout) if isinstance(e, subprocess.TimeoutExpired) else str(e)
        finally:
            if stdin:
                stdin.close()
    err = p.stderr.decode("utf-8", "replace").strip()
    if p.returncode != 0 or not is_gzip(out_path):
        try:
            os.remove(out_path)  # 不留下空的或壞的收集檔
        except OSError:
            pass
    if p.returncode != 0:
        return False, (err.splitlines()[-1] if err else "結束碼 %d" % p.returncode)
    if not is_gzip(out_path):
        return False, "傳回的不是收集檔（主機可能沒有 bash，或登入時印出的訊息混進了輸出）"
    return True, ""


def ssh_hint(err, target, extra=()):
    """常見的 SSH 錯誤，補一句白話說明。extra 是主機清單裡的 ssh 參數（例如 -p 2222）。"""
    e = err.lower()
    host = target.split("@")[-1]
    extra = list(extra)
    port = extra[extra.index("-p") + 1] if "-p" in extra[:-1] else ""
    key = '"[%s]:%s"' % (host, port) if port and port != "22" else host
    login = " ".join(["ssh"] + [shlex.quote(x) for x in extra] + [target])
    if "host key verification failed" in e or "remote host identification has changed" in e:
        return ("\n        這台主機的識別碼和這台電腦上次記下的不同（常見原因：主機重灌，或 IP 換給了另一台）。"
                "\n        向主機管理者確認是同一台主機後，執行 ssh-keygen -R %s 刪掉舊紀錄，再用 %s 登入一次並回答 yes。"
                "\n        無法確認原因時不要刪，請先通報資安人員（見使用者手冊 7.2 節）。" % (key, login))
    if "permission denied" in e:
        if IN_MENU:
            return "\n        帳號或金鑰不對。回到主機清單選「4. 測試 SSH 連線」，可以讓工具幫你把金鑰放到主機上。"
        return ("\n        帳號或金鑰不對。請先確認 %s 能不用密碼登入（見使用者手冊 3.2 節）；"
                "\n        也可以輸入 ./hc 開啟選單，在「2. 用 SSH 檢查多台主機」→「4. 測試 SSH 連線」讓工具幫你放金鑰。" % login)
    if "could not resolve hostname" in e:
        return "\n        找不到這個主機名稱，請改寫 IP 位址。"
    if "timed out" in e or "no route to host" in e or "connection refused" in e:
        return "\n        連不上主機：確認 IP 正確、主機有開機、SSH 服務有啟動，以及防火牆允許連線。"
    return ""


def collected_dir(args):
    """收集檔含原始代號與套件清單：去識別化時放在報告資料夾外面，免得整包交給顧問時一起送出。"""
    return (args.out + "-collected") if args.deidentify else os.path.join(args.out, "collected")


INVENTORY = "inventory.txt"
OLD_INVENTORY = "hosts.txt"  # 0.7 以前的檔名，照樣可以用


def cmd_scan(args, rules):
    if not args.hosts:
        args.hosts = INVENTORY
        if not os.path.isfile(INVENTORY) and os.path.isfile(OLD_INVENTORY):
            args.hosts = OLD_INVENTORY
            print("使用舊檔名的主機清單 hosts.txt（0.8 起改叫 inventory.txt，可以執行 mv hosts.txt inventory.txt 改名）")
    if not os.path.isfile(args.hosts):
        sys.exit("找不到主機清單 %s。\n"
                 "最簡單的做法：輸入 ./hc 開啟選單，選「2. 用 SSH 檢查多台主機」，照畫面輸入主機資料，選單會幫你建好清單。\n"
                 "也可以自己建立這個檔案，每行一台主機：「代號  帳號@IP」，例如：\n"
                 "  H01   admin@10.0.0.5\n"
                 "或複製範本再修改：cp %s %s" % (tilde(args.hosts), shlex.quote(os.path.join(HERE, "inventory.example.txt")),
                                                shlex.quote(args.hosts)))
    hosts = parse_hosts(args.hosts)
    if args.only:  # 選單用：跳過登不進去的主機
        keep = set(args.only.split(","))
        hosts = [h for h in hosts if h[0] in keep]
    preflight_data(args, rules)
    cdir = collected_dir(args)
    os.makedirs(cdir, exist_ok=True)
    print("開始收集 %d 台主機（收集檔存放在 %s，內含套件清單，請妥善保管）" % (len(hosts), cdir))
    bundles, failed = [], []
    for i, (tag, target, extra) in enumerate(hosts, 1):
        path = os.path.join(cdir, "hc-%s.tar.gz" % tag)
        remote = "bash -s -- --tag %s --stdout" % shlex.quote(tag)
        # BatchMode：不停下來問密碼（要用金鑰）；accept-new：第一次連線記下識別碼，識別碼變了照樣擋下
        base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new"] + extra + [target]
        t0 = time.time()
        note = ""
        if not args.no_sudo:
            ok, err = collect_via(base + ["sudo -n " + remote], path)
            if not ok and "sudo" in err.lower():
                note = "（這台主機沒有設定免密碼 sudo，改用一般權限；SSH 設定、防火牆、空密碼帳號會列為未能檢查）"
                ok, err = collect_via(base + [remote], path)
        else:
            ok, err = collect_via(base + [remote], path)
        if not ok:
            err += ssh_hint(err, target, extra)
        print("  [%d/%d] %s：%s%s" % (i, len(hosts), tag, ("完成，%d 秒" % (time.time() - t0)) if ok else "失敗：" + err, note))
        if ok:
            bundles.append(path)
        else:
            failed.append(tag)
            if os.path.exists(path):
                os.remove(path)
    if not bundles:
        sys.exit("沒有任何主機收集成功。請先確認能用 ssh 登入，例如：ssh %s" % hosts[0][1])
    finish(A.load_inputs(bundles), args, rules)
    if failed:
        print("注意：清單上 %d 台，其中 %d 台沒有收集成功，沒有列入這份報告：%s（原因見上方「失敗」那幾行）"
              % (len(hosts), len(failed), "、".join(failed)))


def cmd_report(args, rules):
    missing = [b for b in args.bundles if not os.path.exists(b)]
    if missing:
        sys.exit("錯誤：找不到檔案：%s" % "、".join(missing))
    loaded = A.load_inputs(args.bundles)
    preflight_data(args, rules, A.needed_codenames(loaded, rules))
    finish(loaded, args, rules)


IN_MENU = False  # 從選單執行時為 True
NO_SUDO_NOTE = "SSH 設定、主機防火牆、空密碼帳號 3 項會列為「未能檢查」，其他項目照常檢查"


def sudo_ready():
    """hc local 用：這個帳號現在能不能用 sudo。
    已有免密碼 sudo 或剛輸入過密碼就直接通過；要密碼時，有人在終端機前才詢問。
    密碼錯、帳號沒有 sudo 權限、按 Ctrl+C 跳過，都回傳 False，由呼叫端改用一般權限。"""
    try:
        if subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
    except OSError:  # 這台電腦沒有 sudo
        return False
    if not sys.stdin.isatty():
        return False
    print("要用 sudo（系統管理員權限）才能檢查完整，請輸入你登入這台電腦的密碼（輸入時畫面不會顯示）。\n"
          "沒有 sudo 權限或不知道密碼的話，按 Ctrl+C 跳過，會自動改用一般權限。")
    try:
        return subprocess.run(["sudo", "-v"]).returncode == 0
    except KeyboardInterrupt:
        print()
        return False


def cmd_local(args, rules):
    check_tag(args.tag, "--tag")
    code = local_codename(rules)
    preflight_data(args, rules, [code] if code else None)
    cdir = collected_dir(args)
    os.makedirs(cdir, exist_ok=True)
    path = os.path.join(cdir, "hc-%s.tar.gz" % args.tag)
    use_sudo = not args.no_sudo and os.geteuid() != 0
    if use_sudo and not sudo_ready():
        use_sudo = False
        args.sudo_fallback = True
        print("沒辦法使用 sudo，改用一般權限收集（%s）。" % NO_SUDO_NOTE)
        if not IN_MENU:  # 選單最後會印「下次可以直接打」，這裡不重複
            print("下次可以直接打：./hc local --no-sudo，就不會再問密碼。")
    cmd = (["sudo"] if use_sudo else []) + ["bash", COLLECT, "--tag", args.tag, "--stdout"]
    print("收集本機資料%s…" % ("（使用 sudo）" if use_sudo else "（一般權限）"))
    ok, err = collect_via(cmd, path, use_stdin=False)
    if not ok:
        sys.exit("收集失敗：%s%s" % (err, ("\n可以試試加 --no-sudo 改用一般權限（%s）。" % NO_SUDO_NOTE) if use_sudo else ""))
    finish(A.load_inputs([path]), args, rules)


def cmd_update(argv):
    up = load_updater()
    sys.argv = ["hc update"] + argv  # 讓 -h 的用法行顯示「hc update」
    return up.main()


class ZhHelp(argparse.RawDescriptionHelpFormatter):
    """說明畫面的固定字改成中文。"""
    def add_usage(self, usage, actions, groups, prefix=None):
        return super().add_usage(usage, actions, groups, prefix="用法：")

    def format_help(self):
        text = super().format_help().replace(":\n", "：\n")   # 段落標題的冒號改全形
        return text.replace("指令：\n  指令\n", "指令：\n")   # 拿掉 argparse 自動產生的佔位行


class ZhParser(argparse.ArgumentParser):
    """常見的參數錯誤訊息改成中文。"""
    MSG = [("the following arguments are required:", "缺少必填的參數："), ("unrecognized arguments:", "看不懂的參數："),
           ("invalid choice:", "沒有這個選項："), ("choose from", "可以選"), ("expected one argument", "後面要接一個值")]

    def error(self, message):
        for en, zh_msg in self.MSG:
            message = message.replace(en, zh_msg)
        self.print_usage(sys.stderr)
        self.exit(2, "%s：%s\n（加 -h 看說明，例如 %s -h）\n" % (self.prog, message, self.prog))


def zh(p, example=None):
    """把 argparse 的英文標題換成中文，並加上 -h 與範例。"""
    p._positionals.title = "必填"
    p._optionals.title = "常用選項"
    p.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="顯示這份說明")
    if example:
        p.epilog = "範例：\n" + "\n".join("  " + x for x in example)
    return p


def build_parser():
    ap = zh(ZhParser(prog="hc", description="\n\n".join(__doc__.split("\n\n")[1:6]),
                     formatter_class=ZhHelp, add_help=False))
    ap.epilog = ("更新官方資料的其他選項：--releases 20.04,22.04（只下載某些版本）、--from github（連不到官方網站時）、"
                 "--list（看資料日期）；完整說明：./hc update -h")
    ap.add_argument("--version", action="version", version="hc（Ubuntu-Server-Audit）%s" % A.TOOL_VERSION, help="顯示版本")
    sub = ap.add_subparsers(dest="cmd", title="指令", metavar="指令")
    kw = dict(formatter_class=ZhHelp, add_help=False)
    p1 = zh(sub.add_parser("scan", prog="hc scan", help="用 SSH 逐台檢查主機清單上的主機", **kw),
            ["./hc scan                        檢查 inventory.txt 上的主機",
             "./hc scan --agency 資訊室         報告表頭印上受檢單位",
             "./hc scan hosts.txt              使用其他檔名的主機清單（例如 0.7 以前的 hosts.txt）"])
    p1._positionals.title = "主機清單（可省略）"
    p1.add_argument("hosts", nargs="?", default=None,
                    help="主機清單檔（每行：代號 帳號@IP [ssh 參數]）；不寫就用 inventory.txt，範本見 inventory.example.txt")
    p1.add_argument("--no-sudo", action="store_true",
                    help="不用 sudo，只用一般權限收集。預設會用 sudo -n 收集；主機沒有設定免密碼 sudo 時自動改用一般權限")
    p1.add_argument("--sudo", action="store_true", help=argparse.SUPPRESS)  # 0.7.0 以前的寫法，現在是預設，保留不報錯
    p1.add_argument("--only", default="", help=argparse.SUPPRESS)  # 選單用：只掃這些代號（逗號分隔）
    p2 = zh(sub.add_parser("report", prog="hc report", help="分析主機管理者交回來的收集檔", **kw),
            ["./hc report hc-H01-*.tar.gz", "./hc report hc-H01-*.tar.gz hc-H02-*.tar.gz"])
    p2.add_argument("bundles", nargs="+", metavar="BUNDLE", help="主機上 collect.sh 產生的 hc-*.tar.gz（不用解壓縮，可一次給多個）")
    p3 = zh(sub.add_parser("local", prog="hc local", help="檢查這台電腦自己", **kw),
            ["./hc local                       先試 sudo（可能問密碼），不能用就自動改一般權限",
             "./hc local --no-sudo             不用 sudo、不問密碼，直接用一般權限"])
    p3.add_argument("--no-sudo", action="store_true",
                    help="不用 sudo，只用一般權限收集（%s）。預設會先試 sudo，不能用就自動改一般權限" % NO_SUDO_NOTE)
    p3.add_argument("--sudo", action="store_true", help=argparse.SUPPRESS)  # 0.7.0 以前的寫法，現在是預設，保留不報錯
    p3.add_argument("--tag", default="LOCAL", help="報告上的代號（預設 LOCAL）")
    sub.add_parser("update", help="從 Canonical 官方網站更新弱點資料；加 --verify 核對資料（./hc update -h 看全部選項）")
    for p in (p1, p2, p3):
        adv = p.add_argument_group("進階選項（一般不需要）")
        A.add_common_args(p, adv)
        adv.add_argument("--update", choices=["ask", "yes", "no"], default="ask",
                       help="官方資料缺少或過舊時：ask 詢問（預設）、yes 自動更新、no 不更新")
        adv.add_argument("--refresh-data", action="store_true",
                       help="開始前先向 Canonical 檢查有沒有新的官方資料，有就下載（最多等 %d 秒）；"
                            "連不上就用已下載的資料，不中斷" % CHECK_TIMEOUT)
    return ap


CMDS = {"scan": cmd_scan, "report": cmd_report, "local": cmd_local}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "update":
        return cmd_update(sys.argv[2:])
    ap = build_parser()
    if len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty():
        return menu(ap)
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0
    rules = A.validate_common(ap, args)
    CMDS[args.cmd](args, rules)
    return 0


# ---------------------------------------------------------------------------
# 選單（輸入 ./hc 不加任何字時出現）
# ---------------------------------------------------------------------------
SETTINGS = os.path.join(HERE, "settings.ini")


def load_settings():
    """讀 settings.ini；檔案不在或寫錯時用預設值。"""
    import configparser
    cfg = {"ask_open_report": True}
    cp = configparser.ConfigParser()
    try:
        cp.read(SETTINGS, encoding="utf-8")
        cfg["ask_open_report"] = cp.getboolean("menu", "ask_open_report", fallback=True)
    except (configparser.Error, ValueError) as e:
        print("注意：settings.ini 有看不懂的設定（%s），先用預設值" % e)
    return cfg


class Back(Exception):
    """使用者輸入 0：回上一層。"""


def prompt(text, default=""):
    """讀一行輸入。直接按 Enter 用預設值；輸入 0 回上一層。"""
    try:
        if default:  # 「帳號：」→「帳號 [admin]：」
            text = text[:-1] + " [%s]" % default + text[-1] if text.endswith("：") else text + "[%s] " % default
        ans = input(text).strip()
    except EOFError:
        raise KeyboardInterrupt
    if ans == "0":
        raise Back
    return ans or default


def yes(text, default_yes=True):
    ans = prompt(text + (" [Y/n]：" if default_yes else " [y/N]：")).lower()
    return ans not in ("n", "no") if default_yes else ans in ("y", "yes")


def pause():
    try:
        input("\n按 Enter 回主選單")
    except EOFError:
        pass


def show_cmd(argv):
    return "./hc " + " ".join(shlex.quote(a) for a in argv)


def run_cmd(ap, argv):
    """用和打指令一樣的方式執行；錯誤只印訊息，不離開選單。成功時回傳 args。"""
    print()
    try:
        args = ap.parse_args(argv)
        rules = A.validate_common(ap, args)
        CMDS[args.cmd](args, rules)
        return args
    except SystemExit as e:
        if e.code not in (None, 0):
            if isinstance(e.code, str):
                print(e.code, file=sys.stderr)
            print("\n這一步沒有完成，請看上面的訊息。")
    except KeyboardInterrupt:
        print("\n已取消。")
    return None


def can_open_browser():
    if sys.platform == "darwin":
        return "open"
    if (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and shutil.which("xdg-open"):
        return "xdg-open"
    return None


def after_report(args, argv, settings):
    """報告產生後：給完整路徑、問要不要打開、教下次怎麼直接打。"""
    report = os.path.abspath(os.path.join(args.out, "report-%s.html" % args.stamp))
    print("\n報告的完整位置：%s" % tilde(report))
    opener = can_open_browser()
    if opener and settings["ask_open_report"] and os.path.isfile(report):
        if yes("要用瀏覽器打開報告嗎？"):
            subprocess.Popen([opener, report], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if getattr(args, "sudo_fallback", False):
        argv = argv + ["--no-sudo"]
    print("下次可以直接打：%s" % show_cmd(argv))


def data_line(rules):
    ns = argparse.Namespace(data=DEFAULT_DATA, oval=None)
    try:
        found = A.find_datasets(ns)
    except ValueError:
        found = {}
    if not found:
        return "官方弱點資料：還沒有，建議先選 4 下載"
    ages = [(A.quick_data_info(ds["path"]) or ("", None)) for ds in found.values()]
    oldest = max((a for _, a in ages if a is not None), default=None)
    dates = sorted(ts[:10] for ts, _ in ages if ts)
    lim = rules["thresholds"]["data_max_age_days"]
    line = "官方弱點資料：%d 個版本，最舊的一份產生於 %s（%s 天前）" % (len(found), dates[0] if dates else "?",
                                                         oldest if oldest is not None else "?")
    if oldest is not None and oldest > lim:
        line += "\n  已超過 %d 天，建議先選 4 更新" % lim
    return line


def menu(ap):
    global IN_MENU
    IN_MENU = True
    os.chdir(HERE)  # 主機清單、報告都放在工具資料夾裡，路徑才固定
    settings = load_settings()
    rules = A.load_rules(None)
    try:
        sync_bundled(argparse.Namespace(data=DEFAULT_DATA, oval=None))
    except Exception:
        pass
    items = [("1", "檢查這台電腦", menu_local), ("2", "用 SSH 檢查多台主機", menu_scan),
             ("3", "分析別人交回來的收集檔", menu_report), ("4", "更新官方弱點資料（要能上網）", menu_update),
             ("5", "核對官方資料、查看日期（帶進離線環境後用）", menu_verify)]
    while True:
        print("\nUbuntu 健檢工具 %s（非 Canonical 官方工具）" % A.TOOL_VERSION)
        print("工具資料夾：%s（下載下來的 Ubuntu-Server-Audit 資料夾，hc 和 collect.sh 都在裡面）" % tilde(HERE))
        print(data_line(rules))
        print()
        for k, label, _ in items:
            print("  %s. %s" % (k, label))
        print("\n  0. 離開")
        try:
            ans = input("請輸入數字：").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if ans in ("0", "q", "quit", "exit"):
            return 0
        fn = next((f for k, _, f in items if k == ans), None)
        if not fn:
            if ans:
                print("沒有「%s」這個選項，請輸入 0～5。" % ans)
            continue
        try:
            if fn(ap, settings) == BACK:
                continue
        except Back:
            print("已取消。")
            continue
        except KeyboardInterrupt:
            print("\n已取消。")
        pause()


def ask_agency():
    print("（任何問題直接按 Enter 用括號裡的預設值；輸入 0 回主選單）")
    a = prompt("受檢單位名稱（印在報告表頭，可空白，直接按 Enter 跳過）：")
    return ["--agency", a] if a else []


def menu_local(ap, settings):
    print("\n檢查這台電腦")
    print("會先試著用 sudo（系統管理員權限）收集，檢查最完整；不能用 sudo 時，會自動改用一般權限。")
    argv = ["local"] + ask_agency()
    args = run_cmd(ap, argv)
    if args:
        after_report(args, argv, settings)


# --- 主機清單 ---------------------------------------------------------------
INV_HEADER = """# 主機清單（./hc 的選單會幫你維護這份檔案，也可以用文字編輯器直接改）
# 每行一台主機：代號  帳號@IP  [其他 ssh 參數]
#   代號：報告上顯示的名稱，只能用英文字母、數字與 . _ -，每台要不同
#   帳號@IP：SSH 登入用的帳號與主機 IP（主機名稱要這台電腦查得到才能用）
#   其他 ssh 參數：例如 SSH 不是 22 埠時加 -p 2222
# 「#」開頭的行是註解。報告上只會出現代號，這份清單請留在自己的單位。
"""


def read_inventory(path):
    """寬鬆讀取主機清單，給選單顯示用：回傳 [(行號, 代號, 帳號@IP, ssh 參數)] 與看不懂的行。"""
    hosts, bad = [], []
    if not os.path.isfile(path):
        return hosts, bad
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            try:
                parts = shlex.split(body)
            except ValueError:
                parts = []
            if len(parts) < 2:
                bad.append(n)
            else:
                hosts.append((n, parts[0], parts[1], parts[2:]))
    return hosts, bad


def inv_line(tag, target, extra):
    return ("%-6s %s %s" % (tag, target, " ".join(shlex.quote(x) for x in extra))).rstrip()


def choose_inventory():
    if os.path.isfile(INVENTORY) or not os.path.isfile(OLD_INVENTORY):
        return INVENTORY
    print("找到 0.7 以前的主機清單 %s。" % tilde(OLD_INVENTORY))
    if yes("要改名成 inventory.txt 嗎？（內容不變）"):
        os.rename(OLD_INVENTORY, INVENTORY)
        print("已改名：%s" % tilde(INVENTORY))
        return INVENTORY
    return OLD_INVENTORY


BACK = "back"  # 選單函式回傳這個：使用者選了「0. 回主選單」，不用再按 Enter


def menu_scan(ap, settings):
    inv = choose_inventory()
    while True:
        hosts, bad = read_inventory(inv)
        print("\n用 SSH 檢查多台主機")
        print("主機清單：%s" % tilde(inv))
        try:
            if not os.path.isfile(inv):
                print("  還沒有主機清單，先新增第一台主機。")
                res = add_host(inv, [])
                if res and start_scan(ap, settings, inv, *res):
                    return
                continue
            if hosts:
                print("  目前 %d 台：" % len(hosts))
                for i, (_, tag, target, extra) in enumerate(hosts, 1):
                    print("    %d. %s" % (i, inv_line(tag, target, extra)))
            else:
                print("  清單裡還沒有主機。")
            if bad:
                print("  注意：第 %s 行格式看不懂（應為「代號 帳號@IP」），掃描前請用文字編輯器修正。" % "、".join(map(str, bad)))
            print("\n  1. 開始掃描\n  2. 新增主機\n  3. 刪除主機\n  4. 測試 SSH 連線\n  0. 回主選單")
            try:
                ans = prompt("請輸入數字：")
            except Back:
                return BACK
            if ans == "1":
                if not hosts:
                    print("清單裡還沒有主機，請先選 2 新增。")
                    continue
                print("\n開始掃描前，先逐台確認登得進去。")
                if start_scan(ap, settings, inv, test_hosts(hosts), [], ask=False):
                    return
            elif ans == "2":
                res = add_host(inv, hosts)
                if res and start_scan(ap, settings, inv, *res):
                    return
            elif ans == "3":
                del_host(inv, hosts)
            elif ans == "4":
                failed = test_hosts(hosts)
                if hosts and start_scan(ap, settings, inv, failed, []):
                    return
            elif ans:
                print("沒有「%s」這個選項，請輸入 0～4。" % ans)
        except Back:  # 新增、刪除、測試到一半輸入 0：回到主機清單
            print("已取消。")


def start_scan(ap, settings, inv, failed, tested, ask=True):
    """SSH 測試做完後接著掃描。failed：登不進去的代號；tested：已經測過的代號（其餘的掃描前先測）。
    ask=True 時先問要不要開始（預設不要）。回傳有沒有掃描。"""
    if ask and not yes("要開始掃描清單上的主機嗎？", default_yes=False):
        return False
    hosts, _ = read_inventory(inv)
    if tested:  # 剛新增、測過的那幾台以外，其他主機掃描前也確認一次
        rest = [h for h in hosts if h[1] not in tested]
        if rest:
            print("\n也確認一下清單上其他 %d 台：" % len(rest))
            failed = failed + test_hosts(rest)
    only = []
    if failed:
        ok = [h[1] for h in hosts if h[1] not in failed]
        print("\n有 %d 台還登不進去：%s" % (len(failed), "、".join(failed)))
        if not ok:
            print("沒有能登入的主機，沒有開始掃描。請照上面的說明處理，再選 4 測試一次。")
            return False
        if not yes("要跳過這 %d 台，只掃描其他 %d 台（%s）嗎？" % (len(failed), len(ok), "、".join(ok)), default_yes=False):
            print("沒有開始掃描。")
            return False
        only = ["--only", ",".join(ok)]
    argv = ["scan"] + ([] if inv == INVENTORY else [inv]) + ask_agency()
    args = run_cmd(ap, argv + only)
    if args:
        if failed:
            print("這次跳過、沒有列入報告：%s" % "、".join(failed))
        after_report(args, argv, settings)
    return True


def valid_host(host):
    """IP 照 IPv4 規則檢查（四段、每段 0～255）；不是全數字的當成主機名稱。"""
    if re.match(r"^[0-9.]+$", host):
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            return False
    return bool(HOST_RX.match(host))


def port_open(host, port, timeout=3):
    try:
        socket.create_connection((host, int(port)), timeout).close()
        return True
    except (OSError, ValueError):
        return False


HOST_RX = re.compile(r"^[A-Za-z0-9.:_\[\]-]+$")
USER_RX = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]*$")


def add_host(inv, hosts):
    """一台一台問：代號 → IP → 帳號 → 埠號，寫進清單後問要不要再加一台；全部加完再一起測連線。"""
    import getpass
    print("\n新增主機（直接按 Enter 用括號裡的預設值；輸入 0 取消）")
    hosts, added = list(hosts), []
    while True:
        used = {h[1] for h in hosts}
        n = len(hosts) + 1
        while "H%02d" % n in used:
            n += 1
        print("\n第 %d 台" % (len(hosts) + 1))
        while True:
            tag = prompt("代號（報告上顯示的名稱，不會出現 IP）：", "H%02d" % n)
            if not TAG_RX.match(tag):
                print("  代號只能用英文字母、數字與 . _ -（最多 40 字）")
            elif tag in used:
                print("  代號 %s 已經用過了，每台要不同" % tag)
            else:
                break
        last_user = hosts[-1][2].split("@")[0] if hosts and "@" in hosts[-1][2] else ""
        while True:
            while True:
                host = prompt("%s 的 IP 位址（或主機名稱）：" % tag)
                if valid_host(host):
                    break
                print("  IP 格式不對：要是四段 0～255 的數字，例如 10.0.0.5（不要有空白或 @）")
            while True:
                user = prompt("登入 %s 的帳號：" % tag, last_user or getpass.getuser())
                if USER_RX.match(user):
                    break
                print("  帳號只能有英文字母、數字與 . _ -")
            while True:
                port = prompt("SSH 埠號（沒特別設定就是 22）：", "22")
                if port.isdigit() and 0 < int(port) < 65536:
                    break
                print("  請輸入 1～65535 的數字")
            print("  確認連得到 %s 的 %s 埠…" % (host, port))
            if port_open(host, port):
                print("  連得到。")
                break
            print("  連不到 %s 的 %s 埠（3 秒內沒有回應）。常見原因：IP 打錯、主機沒開機、SSH 沒有啟動或被防火牆擋住。" % (host, port))
            if not yes("要重新輸入 IP 與埠號嗎？（選 n 就照樣新增）"):
                break
        extra = ["-p", port] if port != "22" else []
        target = "%s@%s" % (user, host)
        line = inv_line(tag, target, extra)
        print("\n會寫進主機清單：%s" % line)
        if yes("確定新增嗎？"):
            new = not os.path.isfile(inv)
            with open(inv, "a", encoding="utf-8") as f:
                if new:
                    f.write(INV_HEADER + "\n")
                else:
                    with open(inv, encoding="utf-8") as r:
                        txt = r.read()
                    if txt and not txt.endswith("\n"):
                        f.write("\n")
                f.write(line + "\n")
            print("已新增到 %s（目前 %d 台）" % (tilde(inv), len(hosts) + 1))
            hosts.append((0, tag, target, extra))
            added.append((0, tag, target, extra))
        else:
            print("這台沒有新增。")
        if not yes("要再新增一台嗎？", default_yes=False):
            break
    if added and yes("要現在測試剛才新增的 %d 台的 SSH 連線嗎？" % len(added)):
        return test_hosts(added), [h[1] for h in added]  # 測完接著問要不要掃描
    return None


def del_host(inv, hosts):
    if not hosts:
        print("清單裡沒有主機。")
        return
    ans = prompt("要刪除第幾台？（輸入編號）：")
    if not ans.isdigit() or not 1 <= int(ans) <= len(hosts):
        print("沒有這個編號。")
        return
    lineno, tag, target, extra = hosts[int(ans) - 1]
    if not yes("確定從清單刪除 %s（%s）嗎？" % (tag, target), default_yes=False):
        print("沒有刪除。")
        return
    with open(inv, encoding="utf-8") as f:
        lines = f.readlines()
    del lines[lineno - 1]
    with open(inv, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print("已刪除 %s。" % tag)


def has_ssh_key():
    d = os.path.expanduser("~/.ssh")
    return any(os.path.isfile(os.path.join(d, k + ".pub")) for k in ("id_ed25519", "id_ecdsa", "id_rsa"))


def test_hosts(hosts):
    """逐台試 SSH 登入（不用密碼）與免密碼 sudo；登入不了時可以幫忙放金鑰。回傳最後仍登不進去的主機。"""
    if not hosts:
        print("清單裡沒有主機。")
        return []
    print("\n測試 SSH 連線（每台最多等 15 秒；第一次連線的主機，會記下它的識別碼）")
    return [h[1] for h in hosts if not ssh_ok(h)]


def ssh_ok(h):
    """試一台；登入被拒時問要不要放金鑰，放好再試一次。回傳最後能不能登入。"""
    _, tag, target, extra = h
    base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new"] + extra + [target]
    try:
        p = subprocess.run(base + ["sudo -n true >/dev/null 2>&1 && echo SUDO_OK || echo SUDO_NO"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace").strip()
        rc = p.returncode
    except subprocess.TimeoutExpired:
        out, err, rc = "", "連線逾時（超過 40 秒）", 1
    except OSError as e:
        out, err, rc = "", str(e), 1
    if rc == 0 and "SUDO_" in out:
        print("  %s：可以登入。%s" % (tag, "有免密碼 sudo，檢查最完整。" if "SUDO_OK" in out else
                                "沒有免密碼 sudo，會用一般權限收集（%s）。要完整檢查，請主機管理者設定免密碼 sudo。" % NO_SUDO_NOTE))
        return True
    last = err.splitlines()[-1] if err else "結束碼 %d" % rc
    if "permission denied" in last.lower():
        print("  %s：無法登入：%s\n        帳號不對，或這台電腦的金鑰還沒放到主機上。" % (tag, last))
        return offer_key(tag, target, extra)
    print("  %s：無法登入：%s%s" % (tag, last, ssh_hint(last, target, extra)))
    return False


def offer_key(tag, target, extra):
    """登入被拒時：沒有金鑰就先建立，再用 ssh-copy-id 放到主機上（會問一次主機密碼）。回傳放好後能不能登入。"""
    if not shutil.which("ssh-copy-id"):
        return False
    if not has_ssh_key():
        print("        這台電腦還沒有 SSH 金鑰。")
        if not yes("        要現在建立嗎？（建立時問的 passphrase，直接按 Enter 就是不設）"):
            return False
        if subprocess.run(["ssh-keygen", "-t", "ed25519"]).returncode != 0:
            print("        金鑰沒有建立成功。")
            return False
    if not yes("        要把這台電腦的金鑰放到 %s 上嗎？（會問一次 %s 的登入密碼）" % (tag, target)):
        print("        可以之後自己執行：%s" % " ".join(["ssh-copy-id"] + [shlex.quote(x) for x in extra] + [target]))
        return False
    print("        接下來的英文訊息是 ssh-copy-id 印的。看到 password: 時輸入 %s 的密碼（畫面不會顯示）。\n"
          "        如果出現 post-quantum 的 WARNING，代表那台主機的 SSH 版本比較舊，不影響使用。" % target)
    if subprocess.run(["ssh-copy-id"] + extra + [target]).returncode == 0:
        print("        已放好，重新測試一次：")
        return ssh_ok((0, tag, target, extra))
    print("        沒有成功，請確認帳號與密碼，或請主機管理者協助。")
    return False


# --- 分析收集檔 -------------------------------------------------------------
def find_bundles():
    dirs = [HERE] + [os.path.expanduser(d) for d in ("~/Downloads", "~/下載")]
    seen, out = set(), []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.realpath(os.path.join(d, name))
            if name.startswith("hc-") and name.endswith(".tar.gz") and os.path.isfile(p) and p not in seen:
                seen.add(p)
                out.append(p)
    return out


def menu_report(ap, settings):
    print("\n分析別人交回來的收集檔（檔名像 hc-H01-20261127-103000.tar.gz）")
    found = find_bundles()
    where = "、".join(tilde(d) for d in [HERE, os.path.expanduser("~/Downloads")])
    if found:
        print("在 %s 找到 %d 個收集檔：" % (where, len(found)))
        for i, p in enumerate(found, 1):
            print("  %d. %s" % (i, tilde(p)))
        ans = prompt("要分析哪些？（直接按 Enter＝全部；或輸入編號，例如 1,3；或輸入檔案位置）：")
    else:
        print("在 %s 沒有找到收集檔。" % where)
        print("請把收集檔複製到 %s/，再選一次 3。\n"
              "在這台電腦桌面上開的終端機，也可以直接把檔案拖進這個視窗（會自動貼上檔案位置），再按 Enter。" % tilde(HERE))
        ans = prompt("收集檔：")
        if not ans:
            return
    if not ans:
        files = found
    elif re.match(r"^[\d,\s]+$", ans):
        idx = [int(x) for x in re.split(r"[,\s]+", ans) if x]
        if not idx or any(not 1 <= i <= len(found) for i in idx):
            print("沒有這個編號。")
            return
        files = [found[i - 1] for i in idx]
    else:
        try:
            files = [os.path.expanduser(x) for x in shlex.split(ans)]
        except ValueError:
            print("看不懂輸入的檔案位置。")
            return
    argv = ["report"] + files + ask_agency()
    args = run_cmd(ap, argv)
    if args:
        shown = [os.path.relpath(f, HERE) if os.path.abspath(f).startswith(HERE + os.sep) else os.path.abspath(f) for f in files]
        after_report(args, ["report"] + shown + argv[1 + len(files):], settings)


# --- 官方資料 ---------------------------------------------------------------
def run_update(argv):
    print()
    try:
        return cmd_update(argv) or 0
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
        return e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = ["hc"]


def menu_update(ap, settings):
    print("\n更新官方弱點資料（從 Canonical 官方網站下載，要能上網）")
    if yes("下載全部 LTS 版本？（選 n 可以只下載某幾個版本）"):
        argv = []
    else:
        rel = prompt("輸入版本號，用逗號分隔，例如 20.04,24.04：")
        if not rel:
            return
        argv = ["--releases", rel]
    print("下載全部版本通常要幾分鐘，請稍候；官方網站忙碌時會更久。")
    rc = run_update(argv)
    if rc and yes("有版本沒下載成功。要改從本專案 GitHub 每天更新的副本下載嗎？（內容是官方原始檔）"):
        argv += ["--from", "github"]
        rc = run_update(argv)
    print("下次可以直接打：%s" % show_cmd(["update"] + argv))


def menu_verify(ap, settings):
    print("\n核對官方資料（檢查檔案在下載後有沒有被改過或損毀，不需要網路）")
    rc = run_update(["--verify"])
    print("\n✓ 全部一致，可以開始檢查。" if rc == 0 else
          "\n有檔案不一致或缺檔：請在能上網的電腦重新執行 ./hc update，再把整個資料夾複製過來。")
    print("下次可以直接打：./hc update --verify")


if __name__ == "__main__":
    sys.exit(main())
