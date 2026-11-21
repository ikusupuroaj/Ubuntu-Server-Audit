#!/usr/bin/env python3
"""offline-ubuntu-healthcheck｜統一入口（hc）

版本：0.7.0
一個指令完成收集與分析。只用 Python 3.6 以上的標準函式庫。

  ./hc scan hosts.txt          用 SSH 逐台收集並分析（主機上不留下收集腳本與收集檔）
  ./hc report 收集檔...         分析別人交回來的收集檔（hc-*.tar.gz）
  ./hc local                   檢查這台機器自己
  ./hc update                  從 Canonical 官方網站更新弱點資料（要能上網）

hosts.txt 每行一台：「代號  SSH 目標  [其他 ssh 參數]」，例如：
  H01  admin@10.0.0.5
  H02  ops@db.internal -p 2222
「#」開頭是註解。代號會出現在報告上，SSH 目標不會。範本：hosts.example.txt。

用 git clone 下載時，GitHub 上每天更新的官方資料會一起下載，第一次執行時自動放進 data/。

每個指令都可以加 -h 看完整說明。
"""
import argparse
import datetime
import importlib.util
import re
import os
import shlex
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
        except subprocess.TimeoutExpired:
            return False, "超過 %d 秒沒有完成" % timeout
        except OSError as e:
            return False, str(e)
        finally:
            if stdin:
                stdin.close()
    err = p.stderr.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        return False, (err.splitlines()[-1] if err else "結束碼 %d" % p.returncode)
    if not is_gzip(out_path):
        return False, "傳回的不是收集檔（主機可能沒有 bash，或登入時印出的訊息混進了輸出）"
    return True, ""


def ssh_hint(err, target, extra=()):
    """常見的 SSH 錯誤，補一句白話說明。extra 是 hosts.txt 裡的 ssh 參數（例如 -p 2222）。"""
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
        return "\n        帳號或金鑰不對。請先確認 %s 能不用密碼登入（見使用者手冊 3.2 節）。" % login
    if "could not resolve hostname" in e:
        return "\n        找不到這個主機名稱，請改寫 IP 位址。"
    if "timed out" in e or "no route to host" in e or "connection refused" in e:
        return "\n        連不上主機：確認 IP 正確、主機有開機、SSH 服務有啟動，以及防火牆允許連線。"
    return ""


def collected_dir(args):
    """收集檔含原始代號與套件清單：去識別化時放在報告資料夾外面，免得整包交給顧問時一起送出。"""
    return (args.out + "-collected") if args.deidentify else os.path.join(args.out, "collected")


def cmd_scan(args, rules):
    if not os.path.isfile(args.hosts):
        sys.exit("找不到主機清單 %s。\n"
                 "請先建立這個檔案，每行一台主機：「代號  帳號@IP」，例如：\n"
                 "  H01   admin@10.0.0.5\n"
                 "可以複製範本再修改：cp %s %s" % (args.hosts, shlex.quote(os.path.join(HERE, "hosts.example.txt")),
                                                  shlex.quote(args.hosts)))
    hosts = parse_hosts(args.hosts)
    preflight_data(args, rules)
    cdir = collected_dir(args)
    os.makedirs(cdir, exist_ok=True)
    print("開始收集 %d 台主機（收集檔存放在 %s，內含套件清單，請妥善保管）" % (len(hosts), cdir))
    bundles = []
    for i, (tag, target, extra) in enumerate(hosts, 1):
        path = os.path.join(cdir, "hc-%s.tar.gz" % tag)
        remote = "bash -s -- --tag %s --stdout" % shlex.quote(tag)
        base = ["ssh", "-o", "ConnectTimeout=15"] + extra + [target]
        t0 = time.time()
        note = ""
        if args.sudo:
            ok, err = collect_via(base + ["sudo -n " + remote], path)
            if not ok and "sudo" in err.lower():
                note = "（sudo 需要密碼或不允許，改用一般權限）"
                ok, err = collect_via(base + [remote], path)
        else:
            ok, err = collect_via(base + [remote], path)
        if not ok:
            err += ssh_hint(err, target, extra)
        print("  [%d/%d] %s：%s%s" % (i, len(hosts), tag, ("完成，%d 秒" % (time.time() - t0)) if ok else "失敗：" + err, note))
        if ok:
            bundles.append(path)
        elif os.path.exists(path):
            os.remove(path)
    if not bundles:
        sys.exit("沒有任何主機收集成功。請先確認能用 ssh 登入，例如：ssh %s" % hosts[0][1])
    finish(A.load_inputs(bundles), args, rules)


def cmd_report(args, rules):
    missing = [b for b in args.bundles if not os.path.exists(b)]
    if missing:
        sys.exit("錯誤：找不到檔案：%s" % "、".join(missing))
    loaded = A.load_inputs(args.bundles)
    preflight_data(args, rules, A.needed_codenames(loaded, rules))
    finish(loaded, args, rules)


def cmd_local(args, rules):
    check_tag(args.tag, "--tag")
    code = local_codename(rules)
    preflight_data(args, rules, [code] if code else None)
    cdir = collected_dir(args)
    os.makedirs(cdir, exist_ok=True)
    path = os.path.join(cdir, "hc-%s.tar.gz" % args.tag)
    cmd = (["sudo"] if args.sudo else []) + ["bash", COLLECT, "--tag", args.tag, "--stdout"]
    print("收集本機資料%s…" % ("（使用 sudo）" if args.sudo else ""))
    ok, err = collect_via(cmd, path, use_stdin=False)
    if not ok:
        sys.exit("收集失敗：%s" % err)
    finish(A.load_inputs([path]), args, rules)


def cmd_update(argv):
    up = load_updater()
    sys.argv = ["hc update"] + argv  # 讓 -h 的用法行顯示「hc update」
    return up.main()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "update":
        return cmd_update(sys.argv[2:])
    ap = argparse.ArgumentParser(prog="hc", description="\n\n".join(__doc__.split("\n\n")[2:4]),
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="更新官方資料：./hc update（可加 --releases 20.04,22.04、--from github、--verify、--list；"
                                        "完整說明：./hc update -h）")
    sub = ap.add_subparsers(dest="cmd")
    p1 = sub.add_parser("scan", help="用 SSH 逐台收集並分析")
    p1.add_argument("hosts", help="主機清單檔（每行：代號 SSH目標 [ssh 參數]）")
    p1.add_argument("--sudo", action="store_true", help="用 sudo -n 收集（需要免密碼 sudo；不行時自動改用一般權限）")
    p2 = sub.add_parser("report", help="分析交回來的收集檔")
    p2.add_argument("bundles", nargs="+", help="hc-*.tar.gz")
    p3 = sub.add_parser("local", help="檢查這台機器自己")
    p3.add_argument("--sudo", action="store_true", help="用 sudo 執行收集（會詢問密碼）")
    p3.add_argument("--tag", default="LOCAL", help="報告上的代號（預設 LOCAL）")
    sub.add_parser("update", help="從 Canonical 官方網站更新弱點資料")
    for p in (p1, p2, p3):
        A.add_common_args(p)
        p.add_argument("--update", choices=["ask", "yes", "no"], default="ask",
                       help="官方資料缺少或過舊時：ask 詢問（預設）、yes 自動更新、no 不更新")
        p.add_argument("--refresh-data", action="store_true",
                       help="開始前先向 Canonical 檢查有沒有新的官方資料，有就下載（最多等 %d 秒）；"
                            "連不上就用已下載的資料，不中斷" % CHECK_TIMEOUT)
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0
    rules = A.validate_common(ap, args)
    {"scan": cmd_scan, "report": cmd_report, "local": cmd_local}[args.cmd](args, rules)
    return 0


if __name__ == "__main__":
    sys.exit(main())
