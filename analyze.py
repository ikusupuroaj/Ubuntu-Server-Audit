#!/usr/bin/env python3
"""offline-ubuntu-healthcheck｜分析程式（analyze.py）

版本：0.7.0
在分析用的電腦執行（Python 3.6 以上，只用標準函式庫，不需連網）。

用法：
  python3 analyze.py hc-H01-*.tar.gz [更多收集檔 ...] [--data data] \
      [--engine auto|oscap|builtin|both] [--rules my-rules.json] [--deidentify] \
      [--agency "受檢單位"] [--assessor "執行單位"] [--date 2026-11] [--out 輸出資料夾]

比對資料：Canonical 官方 OVAL 的套件清單版（檔名 oci.com.ubuntu.<代號>.usn.oval.xml.bz2），
  用 ./hc update 下載到 data/。每台主機依版本代號自動挑選對應的檔案。
比對引擎：
  oscap    呼叫 OpenSCAP（Canonical 文件示範的工具），需先安裝 oscap
  builtin  本程式內建的比對，依同一份官方 OVAL 的判斷條件實作
  auto     有 oscap 就用 oscap，否則用 builtin（預設）
  both     兩個都跑並比較結果，用來驗證內建比對（需要 oscap）

產出：
  report-<日期時間>.html       健檢報告，用瀏覽器打開
  findings-ai-<日期時間>.json  去識別化的結果摘要（主機代號改成 H01、H02…），交給顧問分析
  oval-detail.json             官方弱點比對的完整明細（含每則公告的 CVE 清單與套件版本），自己留存即可
  <日期時間>是分析當下的時間，格式 YYYYMMDD-HHMMSS，和報告資料夾名稱同一個時間

判讀規則（分類、嚴重度、建議文字、維護時程）在 rules/default-rules.json，可用 --rules 覆蓋。
"""
import argparse
import bz2
import copy
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from html import escape as html_escape

TOOL_VERSION = "0.7.0"
HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# 1. 規則檔
# ---------------------------------------------------------------------------
def deep_merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_rules(extra):
    with open(os.path.join(HERE, "rules", "default-rules.json"), encoding="utf-8") as f:
        rules = json.load(f)
    if extra:
        with open(extra, encoding="utf-8") as f:
            deep_merge(rules, json.load(f))
    return rules


# ---------------------------------------------------------------------------
# 2. Debian 版本比較（dpkg 的規則）
# ---------------------------------------------------------------------------
def _order(c):
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _cmp_part(a, b):
    while a or b:
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            ac = _order(a[0]) if a else 0
            bc = _order(b[0]) if b else 0
            if ac != bc:
                return ac - bc
            a, b = a[1:], b[1:]
        da = re.match(r"\d*", a).group()
        db = re.match(r"\d*", b).group()
        a, b = a[len(da):], b[len(db):]
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return ia - ib
    return 0


def _split_ver(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e or 0)
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, "0"
    return epoch, up, rev


def vercmp(a, b):
    ea, ua, ra = _split_ver(a)
    eb, ub, rb = _split_ver(b)
    if ea != eb:
        return ea - eb
    c = _cmp_part(ua, ub)
    if c:
        return c
    return _cmp_part(ra, rb)


# ---------------------------------------------------------------------------
# 3. 讀取收集結果
# ---------------------------------------------------------------------------
def load_bundle(path):
    """回傳 {檔名: 內容文字}。支援 tar.gz 或已解壓的資料夾。"""
    files = {}
    if os.path.isdir(path):
        for root, _, names in os.walk(path):
            for n in names:
                with open(os.path.join(root, n), "r", encoding="utf-8", errors="replace") as f:
                    files[n] = f.read()
    else:
        with tarfile.open(path, "r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile():
                    files[os.path.basename(m.name)] = tf.extractfile(m).read().decode("utf-8", "replace")
    return files


def strip_exit(text):
    return re.sub(r"\n?__EXIT__=\d+\s*$", "", text or "").strip()


def exit_code(text):
    m = re.search(r"__EXIT__=(\d+)\s*$", text or "")
    return int(m.group(1)) if m else None


def parse_kv(text):
    out = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def load_json(text):
    """回傳 dict；找不到合法的 JSON 物件就回傳 None（某些版本會在 JSON 前印警告文字）。"""
    body = strip_exit(text)
    dec = json.JSONDecoder()
    i = body.find("{")
    while i >= 0:
        try:
            obj, _ = dec.raw_decode(body[i:])
            return obj if isinstance(obj, dict) else None
        except ValueError:
            i = body.find("{", i + 1)
    return None


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def api_attrs(text):
    d = load_json(text)
    if not d or d.get("result") != "success":
        return None
    attrs = (d.get("data") or {}).get("attributes")
    return attrs if isinstance(attrs, dict) else None


def parse_dpkg(text):
    """回傳 [(套件, 版本, 來源套件)]，只含已安裝的套件。"""
    out = []
    for line in strip_exit(text).splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].endswith(" installed") or "not-installed" in parts[2]:
            continue
        src = (parts[3] if len(parts) > 3 and parts[3] else parts[0]).split(" ")[0]
        out.append((parts[0], parts[1], src))
    return out


# ---------------------------------------------------------------------------
# 4. 官方 OVAL（套件清單版）
#    Canonical 的 oci.com.ubuntu.<代號>.usn.oval.xml 以「目前目錄的 manifest 檔」為比對對象：
#    每行「套件名稱 版本」，用正規表示式取出版本，與修補版本比較（debian_evr_string less than）。
# ---------------------------------------------------------------------------
def _local(tag):
    return tag.split("}", 1)[-1]


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_oval_bytes(path):
    raw = open(path, "rb").read()
    return bz2.decompress(raw) if path.endswith(".bz2") else raw


def _parse_criteria(el):
    node = {"op": (el.get("operator") or "AND").upper(), "negate": el.get("negate") == "true", "children": []}
    for c in el:
        t = _local(c.tag)
        if t == "criteria":
            node["children"].append(_parse_criteria(c))
        elif t == "criterion":
            node["children"].append({"test": c.get("test_ref"), "comment": c.get("comment", ""),
                                     "negate": c.get("negate") == "true"})
    return node


def load_oval(path):
    raw = read_oval_bytes(path)
    root = ET.parse(io.BytesIO(raw)).getroot()
    o = {"path": path, "variables": {}, "objects": {}, "states": {}, "tests": {}, "defs": [],
         "timestamp": "", "product": "", "manifest_based": False}
    for el in root.iter():
        t = _local(el.tag)
        if t == "timestamp" and not o["timestamp"]:
            o["timestamp"] = (el.text or "").strip()
        elif t == "product_name" and not o["product"]:
            o["product"] = (el.text or "").strip()
        elif t == "constant_variable":
            o["variables"][el.get("id")] = [v.text for v in el if _local(v.tag) == "value" and v.text]
        elif t == "textfilecontent54_object":
            fn = pat = None
            for c in el:
                if _local(c.tag) == "filename":
                    fn = (c.text or "").strip()
                elif _local(c.tag) == "pattern":
                    pat = ("var", c.get("var_ref")) if c.get("var_ref") else ("txt", c.text or "")
            if fn == "manifest":
                o["manifest_based"] = True
            o["objects"][el.get("id")] = pat
        elif t == "textfilecontent54_state":
            for c in el:
                if _local(c.tag) == "subexpression":
                    o["states"][el.get("id")] = (c.get("operation", "equals"), c.get("datatype", ""),
                                                 (c.text or "").strip())
        elif t == "textfilecontent54_test":
            ob = st = None
            for c in el:
                if _local(c.tag) == "object":
                    ob = c.get("object_ref")
                elif _local(c.tag) == "state":
                    st = c.get("state_ref")
            o["tests"][el.get("id")] = {"object": ob, "state": st, "check": el.get("check", "all"),
                                        "existence": el.get("check_existence", "at_least_one_exists")}
        elif t == "definition" and el.get("class") in ("patch", "vulnerability"):
            d = {"id": el.get("id"), "title": "", "severity": "", "cves": [], "pro": False, "criteria": None,
                 "cvss": {}, "issued": ""}
            for c in el.iter():
                lt = _local(c.tag)
                if lt == "title" and not d["title"]:
                    d["title"] = (c.text or "").strip()
                elif lt == "severity" and not d["severity"]:
                    d["severity"] = (c.text or "").strip()
                elif lt == "cve" and c.text:
                    d["cves"].append(c.text.strip())
                    av = AV_RX.search(c.get("cvss_vector") or "")
                    if av:
                        try:
                            sc = float(c.get("cvss_score") or 0)
                        except ValueError:
                            sc = 0.0
                        d["cvss"][c.text.strip()] = (sc, av.group(1))
                elif lt == "issued" and not d["issued"]:
                    d["issued"] = (c.get("date") or "")[:10]
                elif lt == "description" and "Available with Ubuntu Pro" in (c.text or ""):
                    d["pro"] = True
            for c in el:
                if _local(c.tag) == "criteria":
                    d["criteria"] = _parse_criteria(c)
            d["cves"] = sorted(set(d["cves"]))
            o["defs"].append(d)
    for oid, pat in list(o["objects"].items()):
        if pat is None:
            o["objects"][oid] = []
        elif pat[0] == "var":
            o["objects"][oid] = o["variables"].get(pat[1], [])
        else:
            o["objects"][oid] = [pat[1]]
    o["compiled"] = {}
    return o


def oval_info(path, rules):
    """資料檔的來源資訊：雜湊值、官方產生時間、距今天數、是否與下載紀錄一致。"""
    info = {"file": os.path.basename(path), "sha256": file_sha256(path), "timestamp": "", "age_days": None,
            "recorded": None}
    src = os.path.join(os.path.dirname(path), "SOURCES.json")
    if os.path.isfile(src):
        try:
            rec = json.load(open(src, encoding="utf-8")).get("files", {}).get(info["file"])
            if rec:
                info["recorded"] = (rec.get("sha256") == info["sha256"])
        except ValueError:
            info["recorded"] = False
    return info


# 官方 OVAL 的套件樣式幾乎都是 ^套件名稱(?::\w+|)\s+(.*)$；能拆出套件名稱的就直接查表，
# 拆不出來的才逐行比對正規表示式（結果相同，只是比較快）。
SIMPLE_PAT = re.compile(r"^\^((?:[A-Za-z0-9]|\\[.+\-])+)\(\?::\\w\+\|\)\\s\+\(\.\*\)\$$")


class Manifest:
    def __init__(self, lines):
        self.lines = lines
        self.by_name = {}
        for line in lines:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                self.by_name.setdefault(parts[0].split(":", 1)[0], []).append(parts[1])


def _items(oval, oid, man):
    """物件比對：回傳 manifest 中符合的版本字串。"""
    if oid not in oval["compiled"]:
        names, regexes = [], []
        for p in oval["objects"].get(oid, []):
            m = SIMPLE_PAT.match(p)
            if m:
                names.append(re.sub(r"\\(.)", r"\1", m.group(1)))
                continue
            try:
                regexes.append(re.compile(p))
            except re.error:
                pass
        oval["compiled"][oid] = (names, regexes)
    names, regexes = oval["compiled"][oid]
    out = []
    for n in names:
        out.extend(man.by_name.get(n, []))
    if regexes:
        for line in man.lines:
            for rx in regexes:
                m = rx.search(line)
                if m:
                    out.append(m.group(1) if m.groups() else line)
                    break
    return out


def _test_builtin(oval, tid, man, cache):
    if tid in cache:
        return cache[tid]
    t = oval["tests"].get(tid)
    res = (False, [])
    if t:
        items = _items(oval, t["object"], man)
        op, dtype, evr = oval["states"].get(t["state"], ("", "", ""))
        ex = t["existence"]
        if ex == "none_exist":
            res = (not items, [])
        elif items or ex in ("any_exist",):
            if op == "less than" and evr:
                hits = [v for v in items if vercmp(v, evr) < 0]
                if t["check"] == "at least one":
                    ok = bool(hits)
                elif t["check"] == "none satisfy":
                    ok = not hits
                else:  # all（OVAL 預設）
                    ok = bool(items) and len(hits) == len(items)
                res = (ok, hits)
            elif not t["state"]:
                res = (bool(items), items)
    cache[tid] = res
    return res


def _eval(node, testres):
    """依 criteria 樹計算結果；回傳 (結果, 成立的 criterion 清單)。"""
    if "test" in node:
        ok = testres(node["test"])
        ok = (not ok) if node["negate"] else ok
        return ok, ([node] if ok and not node["negate"] else [])
    vals, leaves = [], []
    for c in node["children"]:
        v, lv = _eval(c, testres)
        vals.append(v)
        if v:
            leaves.extend(lv)
    if not vals:
        r = False
    elif node["op"] == "OR":
        r = any(vals)
    elif node["op"] == "ONE":
        r = sum(vals) == 1
    elif node["op"] == "XOR":
        r = sum(vals) % 2 == 1
    else:
        r = all(vals)
    if node["negate"]:
        r = not r
    return r, (leaves if r else [])


# 修補來源有兩種寫法：「in esm-apps/focal,」（延伸維護）與「in jammy,」（一般套件庫）
POCKET_RX = re.compile(r"source package in ([a-z0-9.+-]+)")
PKG_RX = re.compile(r"^(\S+) source package")
FIXED_RX = re.compile(r"note: '([^']+)'")


def _binaries(oval, tid, man, fixed):
    """這個條件實際比對到、而且版本比修補版本舊的二進位套件名稱（apt install 要用二進位套件名稱）。"""
    t = oval["tests"].get(tid, {})
    names = (oval["compiled"].get(t.get("object")) or ([], []))[0]
    return sorted(n for n in set(names)
                  if any(not fixed or vercmp(v, fixed) < 0 for v in man.by_name.get(n, [])))


AV_RX = re.compile(r"AV:([NALP])")
AV_ORDER = "NALP"  # 可及範圍由大到小：網路、相鄰網路、本機、實體接觸
AV_LABEL = {"N": "網路", "A": "相鄰網路", "L": "本機", "P": "實體接觸"}
LABEL_ORDER = [AV_LABEL[c] for c in AV_ORDER]


def cvss_summary(cvss):
    """一則公告所有 CVE 的 CVSS 摘要：最高分數、可及範圍最大的攻擊途徑、可從網路利用的 CVE 數。
    資料來自官方 OVAL 的 cvss_score／cvss_vector（CVSS 3.x 與 4.0 混用，分數照官方原值，尺度不完全相同）。"""
    vals = list(cvss.values())
    if not vals:
        return {"cvss_max": None, "attack_vector": "官方未提供", "cves_network": 0}
    av = min((v[1] for v in vals), key=AV_ORDER.index)
    return {"cvss_max": max(v[0] for v in vals), "attack_vector": AV_LABEL[av],
            "cves_network": sum(1 for v in vals if v[1] == "N")}


def vector_text(f):
    """報告用：「網路（最高 9.2）」。"""
    if f.get("cvss_max") is None:
        return f.get("attack_vector") or "官方未提供"
    return "%s（最高 %.1f）" % (f["attack_vector"], f["cvss_max"])


def _hit(oval, d, leaves, hits_by_test, man):
    pockets, pkgs = set(), []
    for lf in leaves:
        cm = lf["comment"]
        m = POCKET_RX.search(cm)
        pocket = m.group(1) if m else ""
        pockets.add(pocket)
        t = oval["tests"].get(lf["test"], {})
        fixed = oval["states"].get(t.get("state"), ("", "", ""))[2]
        pm, fm = PKG_RX.search(cm), FIXED_RX.search(cm)
        pkgs.append({"source": pm.group(1) if pm else "?", "pocket": pocket,
                     "fixed": fm.group(1) if fm else fixed,
                     "installed": sorted(set(hits_by_test.get(lf["test"], [])))[:3],
                     "binaries": _binaries(oval, lf["test"], man, fm.group(1) if fm else fixed)})
    known = [p for p in pockets if p]
    # 只看「這台主機實際缺的」那幾個修補；來源都讀不到時，才退回公告說明裡的「Available with Ubuntu Pro」
    needs_pro = any(p.startswith("esm") for p in known) if known else d["pro"]
    out = {"id": d["id"], "title": d["title"], "severity": d["severity"] or "None", "cves": d["cves"],
           "pockets": sorted(p for p in pockets if p), "needs_pro": needs_pro, "packages": pkgs,
           "issued": d.get("issued", "")}
    out.update(cvss_summary(d.get("cvss", {})))
    return out


def match_builtin(oval, manifest_lines):
    man = Manifest(manifest_lines)
    cache = {}
    hits = []
    for d in oval["defs"]:
        if not d["criteria"]:
            continue
        ok, leaves = _eval(d["criteria"], lambda tid: _test_builtin(oval, tid, man, cache)[0])
        if ok:
            hits.append(_hit(oval, d, leaves, {k: v[1] for k, v in cache.items()}, man))
    return hits


def oscap_version():
    try:
        out = subprocess.run(["oscap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=30).stdout.decode("utf-8", "replace")
        m = re.search(r"OpenSCAP[^\n]*?(\d+\.\d+\.\d+)", out)
        return m.group(1) if m else "?"
    except (OSError, subprocess.SubprocessError):
        return None


def match_oscap(oval, manifest_lines):
    """用 OpenSCAP 評估同一份 OVAL；在暫存資料夾放 manifest 與解壓後的 OVAL。"""
    tmp = tempfile.mkdtemp(prefix="hc-oscap-")
    try:
        with open(os.path.join(tmp, "manifest"), "w", encoding="utf-8") as f:
            f.write("\n".join(manifest_lines) + "\n")
        defs = os.path.join(tmp, "oval.xml")
        with open(defs, "wb") as f:
            f.write(read_oval_bytes(oval["path"]))
        p = subprocess.run(["oscap", "oval", "eval", "--results", "results.xml", "oval.xml"], cwd=tmp,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
        res = os.path.join(tmp, "results.xml")
        if not os.path.isfile(res):
            raise RuntimeError("oscap 沒有產生結果（結束碼 %d）：%s" % (
                p.returncode, p.stderr.decode("utf-8", "replace")[-300:]))
        droot = ET.parse(res).getroot()
        def_res, test_res = {}, {}
        for el in droot.iter():
            t = _local(el.tag)
            if t == "definition" and el.get("definition_id"):
                def_res[el.get("definition_id")] = el.get("result")
            elif t == "test" and el.get("test_id"):
                test_res[el.get("test_id")] = el.get("result")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    hits = []
    man = Manifest(manifest_lines)
    for d in oval["defs"]:
        if def_res.get(d["id"]) != "true" or not d["criteria"]:
            continue
        _, leaves = _eval(d["criteria"], lambda tid: test_res.get(tid) == "true")
        # 已安裝版本由內建比對補上（oscap 結果檔不直接列出）
        hb = {}
        for lf in leaves:
            hb[lf["test"]] = _test_builtin(oval, lf["test"], man, {})[1]
        hits.append(_hit(oval, d, leaves, hb, man))
    return hits


# ---------------------------------------------------------------------------
# 5. 單台主機分析
# ---------------------------------------------------------------------------
class Ctx:
    def __init__(self, rules):
        self.rules = rules
        self.findings = []

    def add(self, fid, severity=None, **kw):
        r = self.rules["findings"].get(fid)
        if not r or not r.get("enabled", True):
            return
        cat = r["category"]
        sev = severity if r.get("severity") == "auto" and severity else r.get("severity", "中")
        if sev == "auto":
            sev = "中"
        class _Keep(dict):
            def __missing__(self, k):
                return "{" + k + "}"

        def fmt(s):
            try:
                return s.format_map(_Keep(kw)) if s else ""
            except (ValueError, IndexError):
                return s
        self.findings.append({
            "id": fid, "category": cat, "severity": sev, "title": fmt(r.get("title")),
            "detail": fmt(r.get("detail")) or kw.get("detail", ""), "action": fmt(r.get("action")),
            "pro_helps": self.rules["categories"][cat]["pro_helps"]})
        if r.get("short"):
            self.findings[-1]["short"] = r["short"]


def support_status(rules, version_id, is_lts, ym):
    lc = rules["lifecycle"].get(version_id)
    if version_id in ("", "?"):
        return ("unknown", "沒有取得作業系統版本資訊，無法判斷維護狀態", None)
    if not lc:
        if is_lts:
            return ("unknown", "規則檔的時程表沒有這個版本，請到官方版本時程頁確認", None)
        return ("nonlts", "非 LTS 版本：Ubuntu Pro 不適用，只能升級到 LTS", None)
    std, esm, leg = lc["standard_end"], lc["esm_end"], lc["legacy_end"]
    if ym <= std:
        return ("standard", "標準維護期內（到 %s）" % std, lc)
    if ym <= esm:
        return ("esm", "標準維護已於 %s 結束；訂閱 Ubuntu Pro（ESM）才有安全更新，到 %s" % (std, esm), lc)
    if ym <= leg:
        return ("legacy", "ESM 已於 %s 結束；需 Ubuntu Pro 加購 Legacy，最長到 %s" % (esm, leg), lc)
    return ("eol", "所有官方維護（含 Legacy）都已結束，只能升級", lc)


def kernel_of(pkgname):
    m = re.match(r"linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+)-(\S+)$", pkgname)
    return (m.group(1), m.group(2)) if m else None


def is_kernel(hit):
    return any(p["source"].startswith("linux") for p in hit["packages"])


def package_names(hits, limit=8):
    """依嚴重度列出要更新的來源套件名稱；超過 limit 個時加上「等 N 個」。"""
    rows = group_by_package(hits)
    names = [e["source"] for e in rows]
    text = "、".join(names[:limit]) + (" 等 %d 個" % len(names) if len(names) > limit else "")
    return names, text


def summarize_hits(hits):
    """公告統計與套件清單，給發現事項的文字使用。
    核心公告常一則帶上千個 CVE，所以 CVE 數另外算「核心以外」的版本。"""
    crit = sum(1 for h in hits if h["severity"] in ("Critical", "High"))
    kern = [h for h in hits if is_kernel(h)]
    other = [h for h in hits if not is_kernel(h)]
    cves_other = len({c for h in other for c in h["cves"]})
    parts = []
    if kern:
        parts.append("核心 %d 則" % len(kern))
    if other:
        parts.append("其他套件 %d 則（%s）" % (len(other), "涉及 CVE %d 個" % cves_other if cves_other
                                             else "官方資料沒有列出 CVE 編號"))
    names, text = package_names(hits)
    return {"usns": len(hits), "cves": len({c for h in hits for c in h["cves"]}), "crit_high": crit,
            "kernel_usns": len(kern), "other_usns": len(other), "cves_other": cves_other,
            "breakdown": "、".join(parts), "packages": text, "n_packages": len(names),
            "package_list": names,
            "reboot_note": "。其中包含核心更新，安裝後要重開機才生效" if kern else "",
            "severity": "高" if crit else "中"}


def analyze_host(files, args, rules, datasets):
    ctx = Ctx(rules)
    unchecked = []

    def ok(name):
        return name in files and exit_code(files[name]) in (0, None)

    osr = parse_kv(strip_exit(files.get("os-release.txt", "")))
    meta = parse_kv(files.get("meta.txt", ""))
    vid = osr.get("VERSION_ID", "?")
    pretty = osr.get("PRETTY_NAME", vid)
    is_lts = "LTS" in osr.get("VERSION", "") or "LTS" in pretty
    status, status_text, lc = support_status(rules, vid, is_lts, args.date)
    codename = (lc or {}).get("codename") or osr.get("VERSION_CODENAME", "")
    pkglist = parse_dpkg(files.get("dpkg.txt", ""))
    pkgs = {n: v for n, v, _ in pkglist}
    if not pkglist:
        unchecked.append("已安裝套件清單（套件相關檢查都沒有執行）")
    pro_status = load_json(files.get("pro-status.json", "")) or {}
    attached = bool(pro_status.get("attached"))
    services = {s.get("name"): s for s in pro_status.get("services", []) or [] if isinstance(s, dict)}
    if not services:
        unchecked.append("Ubuntu Pro 註冊與服務啟用狀態（若主機其實已訂閱，維護狀態與 Livepatch 的判斷可能不準）")
    enabled = {n for n, s in services.items() if attached and s.get("status") == "enabled"}

    # --- 版本維護狀態 ---
    if status == "esm" and "esm-infra" not in enabled:
        ctx.add("os_esm_period", detail=status_text)
    elif status == "legacy":
        if not any("legacy" in n for n in enabled):  # 已啟用 Legacy 服務就不再提示（服務名稱待實機確認）
            ctx.add("os_legacy_period", detail=status_text)
    elif status in ("eol", "nonlts"):
        ctx.add("os_no_support", detail=status_text)
    elif status == "unknown":
        unchecked.append("作業系統維護狀態：" + status_text)

    # --- Pro 用戶端的更新清單（當作對照；沒有官方資料時才作為主要依據） ---
    attrs = api_attrs(files.get("pro-api-updates.json", ""))
    pc_pending, pc_not_applied, pc_free = [], [], []
    if attrs is not None:
        for u in attrs.get("updates", []) or []:
            if not isinstance(u, dict):
                continue
            prov, st = str(u.get("provided_by", "")), str(u.get("status", ""))
            if prov.startswith("esm") and st in ("pending_attach", "pending_enable"):
                pc_pending.append(u)
            elif prov.startswith("esm") and st == "upgrade_available":
                pc_not_applied.append(u)
            elif prov == "standard-security" and st == "upgrade_available":
                pc_free.append(u)

    # --- 官方 OVAL 比對 ---
    patch = {"source": "none", "unit": "", "needs_pro": 0, "pro_not_applied": 0, "free_not_applied": 0,
             "engine": "", "data_file": "", "pro_client_pending_packages": len(pc_pending) if attrs else None}
    hits, engine_check, free = [], None, []
    ds = datasets.get(codename) if codename else None
    if pkglist and ds and ds.get("oval"):
        manifest = ["%s\t%s" % (n, v) for n, v, _ in pkglist]
        try:
            if args.engine_used == "oscap":
                hits = match_oscap(ds["oval"], manifest)
            elif args.engine_used == "both":
                hits = match_oscap(ds["oval"], manifest)
                b = match_builtin(ds["oval"], manifest)
                a_ids, b_ids = {h["id"] for h in hits}, {h["id"] for h in b}
                engine_check = {"oscap": len(a_ids), "builtin": len(b_ids),
                                "only_oscap": sorted(a_ids - b_ids)[:50], "only_builtin": sorted(b_ids - a_ids)[:50]}
            else:
                hits = match_builtin(ds["oval"], manifest)
            patch.update(source="oval", unit="則安全公告", engine=args.engine_label, data_file=ds["info"]["file"])
        except Exception as e:  # 比對失敗不影響其他檢查
            unchecked.append("官方弱點資料比對（%s：%s）" % (type(e).__name__, str(e)[:120]))
    elif pkglist and status not in ("eol",):
        unchecked.append("官方弱點資料比對（缺少 %s 版本的資料檔，請用 ./hc update 下載）" % (codename or vid))

    if patch["source"] == "oval":
        need_pro = [h for h in hits if h["needs_pro"]]
        free = [h for h in hits if not h["needs_pro"]]
        pro_ok = [h for h in need_pro if all(p in enabled for p in h["pockets"] if p.startswith("esm"))
                  and any(p.startswith("esm") for p in h["pockets"])]
        pro_missing = [h for h in need_pro if h not in pro_ok]
        for h in need_pro:  # 報告明細分組用：已訂閱、只是還沒安裝
            h["subscribed"] = h in pro_ok
        if pro_missing and status not in ("eol", "nonlts"):
            s = summarize_hits(pro_missing)
            pockets = {}
            for h in pro_missing:
                for p in h["pockets"]:
                    if p.startswith("esm"):
                        pockets[p] = pockets.get(p, 0) + 1
            s["pockets"] = "、".join("%s（%d 則）" % (k, v) for k, v in sorted(pockets.items())) or "Ubuntu Pro"
            ctx.add("oval_needs_pro", s.pop("severity"), **s)
            if attrs is not None:
                ctx.findings[-1]["detail"] += "。主機上的 Ubuntu Pro 用戶端另外回報 %d 個套件待取得，可互相對照" % len(pc_pending)
        if pro_ok:
            s = summarize_hits(pro_ok)
            ctx.add("oval_pro_not_applied", s.pop("severity"), **s)
        if free:
            s = summarize_hits(free)
            ctx.add("oval_free_not_applied", s.pop("severity"), **s)
        patch.update(needs_pro=len(pro_missing), pro_not_applied=len(pro_ok), free_not_applied=len(free),
                     needs_pro_crit_high=sum(1 for h in pro_missing if h["severity"] in ("Critical", "High")),
                     packages_needs_pro=package_names(pro_missing)[0],
                     packages_pro_not_applied=package_names(pro_ok)[0],
                     packages_free=package_names(free)[0])
    elif attrs is not None:
        if pc_pending and status not in ("nonlts", "eol"):
            infra = sum(1 for u in pc_pending if u.get("provided_by") == "esm-infra")
            ctx.add("pro_client_pending", n=len(pc_pending), infra=infra, apps=len(pc_pending) - infra)
        if pc_not_applied:
            ctx.add("pro_client_not_applied", n=len(pc_not_applied))
        if pc_free:
            ctx.add("pro_client_free_not_applied", n=len(pc_free))
        patch.update(source="pro-client", unit="個套件", needs_pro=len(pc_pending),
                     pro_not_applied=len(pc_not_applied), free_not_applied=len(pc_free))
    else:
        unchecked.append("Ubuntu Pro 用戶端的更新清單（主機沒有 pro 用戶端、版本不支援，或執行失敗）")

    # --- B：核心 ---
    running = strip_exit(files.get("kernel-release.txt", "")).strip()
    if not running:
        parts = strip_exit(files.get("uname.txt", "")).split()
        running = parts[1] if len(parts) > 1 and parts[0] == "Linux" and re.match(r"\d", parts[1]) else ""
    newest = ""
    rk = re.match(r"(\d+\.\d+)\.\d+-\d+-(\S+)$", running or "")
    if rk:
        series, flavor = rk.group(1), rk.group(2)
        for name in pkgs:
            k = kernel_of(name)
            if not k or k[1] != flavor or not k[0].startswith(series + "."):
                continue
            if not newest or vercmp(k[0], newest.rsplit("-", 1)[0]) > 0:
                newest = k[0] + "-" + k[1]
    uptime_days = None
    try:
        uptime_days = int(float(strip_exit(files.get("uptime.txt", "")).split()[0]) // 86400)
    except (ValueError, IndexError):
        unchecked.append("連續運作天數")
    lp_on = "livepatch" in enabled
    if not running:
        unchecked.append("執行中的核心版本")
    elif newest and running != newest and vercmp(newest.rsplit("-", 1)[0], running.rsplit("-", 1)[0]) > 0:
        ctx.add("kernel_not_running_newest", running=running, newest=newest)
    elif "reboot-required.txt" in files:
        ctx.add("reboot_required")
    if uptime_days is not None and uptime_days >= rules["thresholds"]["uptime_days_warn"] and not lp_on:
        ctx.add("long_uptime", days=uptime_days)

    # --- C：合規 ---
    if pkglist and "usg" not in pkgs and vid in rules.get("usg_versions", []):
        ctx.add("usg_not_used")

    # --- D：設定與其他 ---
    sshd_raw = strip_exit(files.get("sshd.txt", ""))
    sshd_notes = [ln[1:].strip() for ln in sshd_raw.splitlines() if ln.startswith("#")]
    if not ok("sshd.txt"):
        if "sshd.txt" not in files:
            unchecked.append("SSH 設定（主機沒有安裝 SSH 服務）")
        elif meta.get("uid") == "0":
            why = ("主機也沒有 python3 可改讀設定檔" if meta.get("collector_version", "0") >= "0.5"
                   else "請改用 0.5 版以後的收集腳本，會改讀設定檔")
            unchecked.append("SSH 設定（已用 sudo，但 sshd -T 無法執行；%s%s）"
                             % (why, "。錯誤訊息：" + sshd_notes[0][:120] if sshd_notes else ""))
        else:
            unchecked.append("SSH 設定（需要 sudo）")
    else:
        sshd = sshd_raw.lower()
        n0 = len(ctx.findings)
        if re.search(r"^permitrootlogin yes", sshd, re.M):
            ctx.add("ssh_root_login")
        if re.search(r"^permitemptypasswords yes", sshd, re.M):
            ctx.add("ssh_empty_passwords")
        if re.search(r"^passwordauthentication yes", sshd, re.M):
            ctx.add("ssh_password_auth")
        if any("改讀設定檔" in x for x in sshd_notes):  # 不是 sshd 實際生效的值，要註明
            for x in ctx.findings[n0:]:
                x["detail"] += "（sshd -T 無法執行，依設定檔判斷，請在主機上確認）"
    if not ok("ufw.txt"):
        unchecked.append("主機防火牆（ufw）狀態（需要 sudo，或主機未安裝 ufw）")
    elif "inactive" in strip_exit(files["ufw.txt"]):
        ctx.add("ufw_inactive")
    u0 = strip_exit(files.get("uid0.txt", ""))
    if "uid0_accounts=" in u0:  # v0.3 起只記數量
        n_extra = max(to_int(parse_kv(u0).get("uid0_accounts")) - 1, 0)
    else:  # 舊版收集檔記的是帳號名稱
        n_extra = len([u for u in u0.split() if u != "root"])
    if n_extra:
        ctx.add("extra_uid0", n=n_extra)
    if "shadow-summary.txt" not in files:
        unchecked.append("空密碼帳號（需要 sudo）")
    else:
        n = to_int(parse_kv(files["shadow-summary.txt"]).get("empty_password_accounts"))
        if n:
            ctx.add("empty_password_accounts", n=n)
    # 套件清單最後一次成功更新（apt update）的日期，以收集當天為準計算天數
    apt_last, apt_age = "", None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", strip_exit(files.get("apt-update-stamp.txt", "")))
    cm = re.match(r"(\d{4})-(\d{2})-(\d{2})", meta.get("collected_at", ""))
    if m and ok("apt-update-stamp.txt"):
        apt_last = m.group(0)
        if cm:
            apt_age = (datetime.date(*map(int, cm.groups())) - datetime.date(*map(int, m.groups()))).days
    auto_on = 'Unattended-Upgrade "1"' in strip_exit(files.get("unattended-upgrades.txt", ""))
    auto_failing = False
    if not auto_on:
        ctx.add("no_auto_updates")
        if apt_age is not None and apt_age > rules["thresholds"]["apt_update_stale_days"]:
            ctx.findings[-1]["detail"] += "；套件清單上次成功更新是 %s（收集當天往前 %d 天）" % (apt_last, apt_age)
    elif apt_age is not None and apt_age > rules["thresholds"]["apt_update_stale_days"]:
        ctx.add("auto_updates_failing", days=apt_age, last=apt_last)
        auto_failing = any(x["id"] == "auto_updates_failing" for x in ctx.findings)
    elif apt_age is None and pkglist and "apt-update-stamp.txt" not in files:
        unchecked.append("自動更新是否正常運作（主機上沒有套件清單更新成功的紀錄）")
    elif apt_age is None and pkglist:
        unchecked.append("自動更新是否正常運作（套件清單更新紀錄讀取失敗）")
    # 自動更新有開、套件清單也有更新，卻還有發布超過門檻天數的免費修補沒裝：自動更新沒有實際安裝
    lag = rules["thresholds"].get("auto_update_lag_days", 7)
    fresh = apt_age is not None and apt_age <= rules["thresholds"]["apt_update_stale_days"]
    not_applying = False
    if auto_on and fresh and cm and free:
        today = datetime.date(*map(int, cm.groups()))
        old = []
        for h in free:
            im = re.match(r"(\d{4})-(\d{2})-(\d{2})", h.get("issued") or "")
            if im and (today - datetime.date(*map(int, im.groups()))).days > lag:
                old.append(h["issued"])
        if old:
            ctx.add("auto_updates_not_applying", n=len(old), days=lag, oldest=min(old))
            not_applying = any(x["id"] == "auto_updates_not_applying" for x in ctx.findings)
    if auto_failing and patch["source"] == "pro-client":
        for x in ctx.findings:
            if x["id"] == "auto_updates_failing":
                x["detail"] += "。主機上 Ubuntu Pro 用戶端的修補數也是用這份舊清單算的，可能偏低"
    if auto_failing:  # 這台的自動更新沒在運作：免費修補的建議不再寫「啟用自動安全更新」
        for x in ctx.findings:
            alt = rules["findings"].get(x["id"], {}).get("action_if_auto_update_failing")
            if alt:
                x["action"] = alt
    elif not_applying:  # 自動更新有開但沒有實際安裝：同樣不再建議「啟用自動安全更新」
        for x in ctx.findings:
            alt = rules["findings"].get(x["id"], {}).get("action_if_auto_update_not_applying")
            if alt:
                x["action"] = alt
    sattrs = api_attrs(files.get("pro-api-summary.json", ""))
    if sattrs:
        s = sattrs.get("summary") if isinstance(sattrs.get("summary"), dict) else {}
        third = to_int(s.get("num_third_party_packages")) + to_int(s.get("num_unknown_packages"))
        if third:
            ctx.add("third_party_packages", n=third)

    order = {"高": 0, "中": 1, "低": 2}
    ctx.findings.sort(key=lambda x: (x["category"], order.get(x["severity"], 9)))
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "None": 5}
    hits.sort(key=lambda h: (not h["needs_pro"], sev_rank.get(h["severity"], 9), h["title"]))
    crit_fixes = crit_high_fixes(hits) if patch["source"] == "oval" else []
    return {
        "tag": meta.get("tag", "?"),
        "collected_at": meta.get("collected_at", "?"),
        "collector_version": meta.get("collector_version", "?"),
        "run_as_root": meta.get("uid") == "0",
        "os": pretty, "version_id": vid, "codename": codename, "lts": is_lts,
        "support_status": status, "support_text": status_text,
        "lifecycle": lc,
        "pro_attached": attached, "pro_services_enabled": sorted(enabled),
        "livepatch_enabled": lp_on,
        "running_kernel": running, "newest_installed_kernel": newest,
        "uptime_days": uptime_days,
        "package_count": len(pkglist),
        "patches": patch,
        "oval_matches": hits,
        "engine_check": engine_check,
        "apt_last_update": apt_last or None,
        "apt_update_age_days": apt_age,
        "auto_updates_enabled": auto_on,
        "crit_high_fixes": crit_fixes,
        "unchecked": unchecked,
        "findings": ctx.findings,
    }


USN_RX = re.compile(r"\b(USN-\d+-\d+)\b")


def crit_high_fixes(hits):
    """重大與高風險公告：逐則附上「只修這一則」的指令。
    pro fix 用公告編號；apt 用這台主機實際裝了、版本比修補版本舊的二進位套件名稱。
    核心公告的新版本是不同的套件名稱，apt --only-upgrade 裝不到，改寫全面更新後重開機。"""
    out = []
    for h in hits:
        if h["severity"] not in ("Critical", "High"):
            continue
        m = USN_RX.search(h["title"])
        usn = m.group(1) if m else ""
        kern = is_kernel(h)
        bins = sorted({b for p in h["packages"] for b in p.get("binaries", [])})
        cmds = []
        if usn:
            cmds.append("sudo pro fix %s" % usn)
        if kern:
            cmds.append("sudo apt update && sudo apt upgrade（核心公告：安裝後要重開機才生效）")
        elif bins:
            cmds.append("sudo apt update && sudo apt install --only-upgrade %s" % " ".join(bins))
        out.append({"usn": usn or h["title"].split(" ", 1)[0], "title": h["title"], "severity": h["severity"],
                    "needs_pro": h["needs_pro"], "subscribed": bool(h.get("subscribed")), "kernel": kern,
                    "packages": sorted({p["source"] for p in h["packages"]}), "binaries": bins,
                    "attack_vector": h.get("attack_vector", "官方未提供"), "cvss_max": h.get("cvss_max"),
                    "cves_network": h.get("cves_network", 0), "issued": h.get("issued", ""),
                    "commands": cmds})
    return out


def error_host(path, err):
    return {"tag": os.path.basename(str(path)), "error": "資料損壞或格式不符，未分析（%s）" % type(err).__name__,
            "os": "?", "version_id": "?", "codename": "", "support_status": "unknown", "support_text": "未分析",
            "running_kernel": "", "uptime_days": None, "run_as_root": True,
            "patches": {"source": "none", "unit": "", "needs_pro": 0, "pro_not_applied": 0, "free_not_applied": 0},
            "oval_matches": [], "engine_check": None, "unchecked": [], "findings": [], "crit_high_fixes": []}


# ---------------------------------------------------------------------------
# 6. 顯示用的小工具
# ---------------------------------------------------------------------------
STATUS_LABEL = {"standard": "標準維護期內", "esm": "需 Pro（ESM）", "legacy": "需 Pro＋Legacy",
                "eol": "已無維護", "nonlts": "非 LTS，需升級", "unknown": "待確認"}
SRC_LABEL = {"oval": "官方 OVAL", "pro-client": "Pro 用戶端", "none": "無"}
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "None": 5}


def code_label(rules, code):
    """版本代號加上版本號，例如 focal（20.04）。"""
    for vid, lc in rules["lifecycle"].items():
        if lc.get("codename") == code:
            return "%s（%s）" % (code, vid)
    return code or "?"


def group_by_package(matches):
    """把逐則公告依來源套件彙整：一個套件一列。"""
    g = {}
    for m in matches:
        for p in m["packages"]:
            k = p["source"]
            e = g.setdefault(k, {"source": k, "usns": set(), "severity": "None", "needs_pro": False,
                                 "pockets": set(), "installed": set(), "fixed": ""})
            e["usns"].add(m["title"].split(" ", 1)[0])
            if SEV_RANK.get(m["severity"], 9) < SEV_RANK.get(e["severity"], 9):
                e["severity"] = m["severity"]
            if p["pocket"].startswith("esm") or (m["needs_pro"] and not p["pocket"]):
                e["needs_pro"] = True
            if p["pocket"]:
                e["pockets"].add(p["pocket"])
            e["installed"].update(p["installed"])
            if p["fixed"] and (not e["fixed"] or vercmp(p["fixed"], e["fixed"]) > 0):
                e["fixed"] = p["fixed"]
    rows = list(g.values())
    rows.sort(key=lambda e: (not e["needs_pro"], SEV_RANK.get(e["severity"], 9), -len(e["usns"]), e["source"]))
    return rows


def detail_groups(matches):
    """報告明細的分組：免費的放前面，再來是已訂閱但還沒安裝，最後是要訂閱才拿得到。"""
    return [g for g in (
        ("免費就能修補", [m for m in matches if not m["needs_pro"]], True),
        ("已訂閱 Ubuntu Pro，還沒安裝", [m for m in matches if m["needs_pro"] and m.get("subscribed")], True),
        ("要訂閱 Ubuntu Pro 才能修補", [m for m in matches if m["needs_pro"] and not m.get("subscribed")], False),
    ) if g[1]]


def pocket_label(pockets):
    """修補來源：延伸維護照寫（esm-infra 等），一般套件庫寫成「Ubuntu 一般更新」。"""
    out = sorted({p if p.startswith("esm") else "Ubuntu 一般更新" for p in pockets})
    return "、".join(out) or "?"


def dedupe_tags(hosts):
    """代號重複時自動加上序號，回傳被改名的代號清單。"""
    seen, renamed = {}, []
    for h in hosts:
        seen[h["tag"]] = seen.get(h["tag"], 0) + 1
    used = set(seen)
    count = {}
    for h in hosts:
        t = h["tag"]
        if seen[t] > 1:
            n = count.get(t, 0)
            while True:  # 加上序號後若撞到既有代號，就再往後編
                n += 1
                new = "%s-%d" % (t, n)
                if new not in used:
                    break
            count[t] = n
            used.add(new)
            h["tag"] = new
            renamed.append(new)
    return renamed


def deidentify(hosts):
    for i, h in enumerate(hosts, 1):
        h["tag"] = "H%02d" % i
    return hosts


PATCH_IDS = {"oval_free_not_applied", "oval_pro_not_applied", "pro_client_not_applied", "pro_client_free_not_applied"}


def _host_list(tags, limit=10):
    tags = list(dict.fromkeys(tags))
    return "、".join(tags[:limit]) + (" 等 %d 台" % len(tags) if len(tags) > limit else "")


def priority_steps(hosts, rules):
    """「建議處理順序」：只列這份報告實際出現的項目。自訂規則仍用舊的 priority_steps（固定文字）時照舊。"""
    rt = rules["report_text"]
    if rt.get("priority_steps"):
        return list(rt["priority_steps"])
    tpl = rt.get("priority", {})
    groups = {}  # 步驟 → ([主機], [項目])

    def put(key, tag, item=None):
        g = groups.setdefault(key, ([], []))
        g[0].append(tag)
        if item and item not in g[1]:
            g[1].append(item)
    for h in hosts:
        if h.get("error"):
            put("broken", h["tag"])
            continue
        for x in h["findings"]:
            fid, cat = x.get("id"), x["category"]
            item = x.get("short") or x["title"]
            if fid == "auto_updates_failing":
                put("auto_update_failing", h["tag"])
            elif fid == "auto_updates_not_applying":
                put("auto_update_not_applying", h["tag"])
            elif fid in PATCH_IDS:
                put("patches_available", h["tag"])
            elif fid == "os_no_support":
                put("no_support", h["tag"])
            elif cat == "A":
                put("a_class", h["tag"])
            elif cat == "B":
                put("b_class", h["tag"])
            elif cat == "C":
                put("c_class", h["tag"])
            elif x["severity"] == "高":
                put("d_high", h["tag"], item)
            else:
                put("d_other", h["tag"], item)
        if h.get("unchecked"):
            put("unchecked", h["tag"])
    order = ["auto_update_failing", "auto_update_not_applying", "d_high", "patches_available", "no_support", "a_class", "b_class",
             "d_other", "c_class", "broken", "unchecked"]
    out = []
    for key in order:
        if key in groups and tpl.get(key):
            tags, items = groups[key]
            out.append(tpl[key].replace("{hosts}", _host_list(tags)).replace("{items}", "、".join(items)))
    if not [k for k in groups if k not in ("unchecked", "broken")] and tpl.get("none"):
        out.insert(0, tpl["none"])
    return out


def cat_counts(h):
    c = {"A": 0, "B": 0, "C": 0, "D": 0}
    for x in h["findings"]:
        c[x["category"]] = c.get(x["category"], 0) + 1
    return c


# ---------------------------------------------------------------------------
# 7. 報告：Markdown
# ---------------------------------------------------------------------------
def fix_rows(fx, sevname):
    """報告用的列：一般套件逐則列出；核心公告合併成一列（新核心是不同的套件名稱，處理方式都一樣）。
    回傳 [(公告, 嚴重度, 攻擊途徑, 套件, 前置說明, [指令])]。findings-ai 檔仍逐則保留。"""
    rows, kern = [], []
    for f in fx:
        if f["kernel"]:
            kern.append(f)
            continue
        pre = "要先訂閱 Ubuntu Pro 並執行 sudo pro attach；之後：" if f["needs_pro"] and not f["subscribed"] else ""
        rows.append((f["title"], sevname.get(f["severity"], f["severity"]), vector_text(f), "、".join(f["packages"]),
                     pre, f["commands"]))
    if kern:
        sev = "重大" if any(f["severity"] == "Critical" for f in kern) else sevname.get("High", "High")
        ids = [f["usn"] for f in kern]
        title = "核心公告 %d 則：%s" % (len(kern), "、".join(ids[:6]) + (" 等" if len(ids) > 6 else ""))
        np = sum(1 for f in kern if f["needs_pro"] and not f["subscribed"])
        pre = ("要先訂閱 Ubuntu Pro 並執行 sudo pro attach；之後：" if np == len(kern) else
               "其中 %d 則要先訂閱 Ubuntu Pro（sudo pro attach）才能取得，其餘免費：" % np if np else "")
        scored = [f for f in kern if f.get("cvss_max") is not None]
        kv = (vector_text({"attack_vector": min((f["attack_vector"] for f in scored), key=LABEL_ORDER.index),
                           "cvss_max": max(f["cvss_max"] for f in scored)}) if scored else "官方未提供")
        rows.insert(0, (title, sev, kv, "、".join(sorted({p for f in kern for p in f["packages"]})), pre,
                        ["sudo apt update && sudo apt upgrade，完成後重開機（sudo reboot）；停機困難時評估 Livepatch"]))
    return rows


def _e(x):
    return html_escape(str(x), quote=True)


HTML_CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--mut:#5f6368;--line:#e2e4e8;--card:#f6f7f9;--a:#c62828;--b:#ef6c00;--c:#1565c0;--d:#546e7a;--warn:#fff4e5}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8eaed;--mut:#9aa0a6;--line:#2f3337;--card:#1c1f23;--warn:#3a2c12}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,"Noto Sans TC","Microsoft JhengHei",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:17px;margin:24px 0 8px}
.mut{color:var(--mut)}.warn{background:var(--warn);border-left:4px solid var(--b);padding:10px 14px;border-radius:6px;margin:12px 0}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:14px}th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}th{color:var(--mut);font-weight:600;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:12px 0}.card{background:var(--card);border-radius:10px;padding:14px;border-top:4px solid var(--line)}
.card b{font-size:28px;display:block}.card.A{border-color:var(--a)}.card.B{border-color:var(--b)}.card.C{border-color:var(--c)}.card.D{border-color:var(--d)}
.tag{display:inline-block;border-radius:4px;padding:0 6px;font-size:12px;font-weight:700;color:#fff}.tA{background:var(--a)}.tB{background:var(--b)}.tC{background:var(--c)}.tD{background:var(--d)}
details{background:var(--card);border-radius:8px;padding:8px 12px;margin:10px 0}summary{cursor:pointer;font-weight:600}
h4{font-size:15px;margin:18px 0 4px}code{font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;background:var(--card);padding:1px 4px;border-radius:4px;word-break:break-all}
"""


def render_html(hosts, args, rules, datasets, warnings=()):
    rt = rules["report_text"]
    cats = rules["categories"]
    sevname = rules.get("severity_names", {})
    out = []
    w = out.append
    w('<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">'
      '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>%s</style></head><body><main>'
      % (_e(rt["title"]), HTML_CSS))
    w("<h1>%s</h1>" % _e(rt["title"]))
    w('<p class="mut">受檢單位：%s　執行單位：%s　判斷基準月份：%s　分析程式：offline-ubuntu-healthcheck %s</p>'
      % (_e(args.agency or "（未填）"), _e(args.dealer or "（未填）"), _e(args.date), TOOL_VERSION))
    for x in warnings:
        w('<div class="warn">注意：%s</div>' % _e(x))
    used = {c: ds for c, ds in datasets.items() if ds.get("used")}
    stale = stale_codes(datasets, rules)
    if stale:
        w('<div class="warn">官方資料已超過 %d 天：%s。之後公布的弱點不在比對範圍內，建議先更新資料再出報告。</div>'
          % (rules["thresholds"]["data_max_age_days"], _e("、".join(code_label(rules, c) for c in stale))))
    # 摘要卡片
    cnt = {c: 0 for c in cats}
    for h in hosts:
        for k, v in cat_counts(h).items():
            cnt[k] = cnt.get(k, 0) + v
    risky = [h for h in hosts if h["support_status"] in ("esm", "legacy", "eol", "nonlts")]
    w("<h2>一、摘要</h2>")
    w("<p>共 <b>%d</b> 台主機，其中 <b>%d</b> 台已過標準維護期；發現事項共 %d 項，依「Ubuntu Pro 能否解決」分成四類。</p>"
      % (len(hosts), len(risky), sum(cnt.values())))
    w('<div class="cards">')
    for c in sorted(cats):
        w('<div class="card %s"><span class="tag t%s">%s</span><b>%d</b>%s<br><span class="mut">Ubuntu Pro 能否解決：%s</span></div>'
          % (c, c, c, cnt.get(c, 0), _e(cats[c]["name"]), _e(cats[c]["pro_helps"])))
    w("</div><p class=\"mut\">D 類與 Ubuntu Pro 無關，同樣列出，讓受檢單位掌握完整風險。"
      "每一項發現的「建議」欄寫了處理方式；各類別的意思與處理步驟，見使用者手冊（docs/user-guide.pdf）第 5 章。</p>")
    # 主機總覽
    show_ai = not args.deidentify
    w("<h2>二、主機總覽</h2><div class=\"tw\"><table><tr><th>主機</th>%s<th>版本</th>" % ("<th>交件代號</th>" if show_ai else "") + "<th>維護狀態</th><th>A</th><th>B</th><th>C</th><th>D</th>"
      "<th>需 Pro 才能取得的修補</th><th>未套用的免費修補</th><th>執行中核心</th><th>未重開機天數</th></tr>")
    for h in hosts:
        p, c = h["patches"], cat_counts(h)
        unit = p.get("unit", "")
        w("<tr><td><b>%s</b></td>%s<td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _e(h["tag"]), ("<td>%s</td>" % _e(h.get("ai_tag", ""))) if show_ai else "", _e(h["os"]), _e(STATUS_LABEL.get(h["support_status"], "?")), c["A"], c["B"], c["C"], c["D"],
            _e(("%d %s" % (p["needs_pro"], unit)) if p["source"] != "none" else "?"),
            _e(("%d %s" % (p["free_not_applied"], unit)) if p["source"] != "none" else "?"),
            _e(h["running_kernel"] or "?"), _e(h["uptime_days"] if h["uptime_days"] is not None else "?")))
    w("</table></div><p class=\"mut\">%s</p>" % _e(rt["year_note"]))
    if show_ai:
        w('<p class="mut">交件代號是 findings-ai-%s.json（交給顧問分析的去識別化檔案）裡的主機代號；這張對照表只在本報告，請不要一起寄出。</p>' % _e(args.stamp))
    # 各主機
    w("<h2>三、發現事項（依主機）</h2>")
    n = rules["thresholds"]["detail_rows_per_host"]
    for h in hosts:
        w("<h3>%s（%s）</h3>" % (_e(h["tag"]), _e(h["os"])))
        if h.get("error"):
            w('<div class="warn">%s</div>' % _e(h["error"]))
            continue
        w("<p>維護狀態：%s</p>" % _e(h["support_text"]))
        if not h["run_as_root"]:
            w('<p class="mut">以一般使用者收集（預設）：SSH 設定、防火牆、空密碼帳號需要 sudo 才能檢查，列在「未能檢查」。</p>')
        w("<div class=\"tw\"><table><tr><th>類別</th><th>嚴重度</th><th>發現</th><th>說明</th><th>建議</th><th>Pro 能否解決</th></tr>")
        for x in h["findings"]:
            w('<tr><td><span class="tag t%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                _e(x["category"]), _e(x["category"]), _e(x["severity"]), _e(x["title"]), _e(x["detail"]),
                _e(x["action"]), _e(x["pro_helps"])))
        w("</table></div>")
        if h["unchecked"]:
            w('<p class="mut">未能檢查的項目（不計入上表）：%s</p>' % _e("；".join(h["unchecked"])))
        if h.get("engine_check"):
            e = h["engine_check"]
            same = not e["only_oscap"] and not e["only_builtin"]
            w('<p class="mut">比對引擎對照：OpenSCAP %d 則、內建 %d 則，%s。</p>' % (
                e["oscap"], e["builtin"], "結果一致" if same else "有差異（只有 OpenSCAP 有 %d 則、只有內建有 %d 則）"
                % (len(e["only_oscap"]), len(e["only_builtin"]))))
        fx = h.get("crit_high_fixes") or []
        if fx:
            frows = fix_rows(fx, sevname)
            # 列數多時預設收合，和下方的比對明細一致；點標題可展開
            w("<details%s><summary>重大與高風險公告（%d 則）：只修這一則的指令</summary><p class=\"mut\">%s</p>"
              % (" open" if len(frows) <= 10 else "", len(fx), _e(rt.get("crit_high_note", ""))))
            w("<div class=\"tw\"><table><tr><th>安全公告</th><th>嚴重度</th><th>攻擊途徑（CVSS）</th><th>套件</th><th>指令</th></tr>")
            for title, sev, av, pk, pre, cmds in frows:
                c = "<br>".join("<code>%s</code>" % _e(x) for x in cmds) or "（無法組出指令，請用 sudo apt update 與 sudo apt upgrade）"
                w("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s%s</td></tr>" % (
                    _e(title), _e(sev), _e(av), _e(pk), _e(pre) + ("<br>" if pre else ""), c))
            w("</table></div>")
            w("</details>")
        matches = h.get("oval_matches") or []
        for label, group, opened in detail_groups(matches):
            rows = group_by_package(group)
            w("<details%s><summary>%s：%d 個套件、%d 則公告</summary>"
              % (" open" if opened and len(rows) <= n else "", label, len(rows), len(group)))
            w("<div class=\"tw\"><table><tr><th>套件（原始碼套件名稱）</th><th>最高嚴重度</th><th>公告數</th><th>修補來源</th><th>已安裝 → 修補版本</th></tr>")
            for e in rows:
                w("<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s → %s</td></tr>" % (
                    _e(e["source"]), _e(sevname.get(e["severity"], e["severity"])), len(e["usns"]),
                    _e(pocket_label(e["pockets"])),
                    _e("/".join(sorted(e["installed"])[:2]) or "?"), _e(e["fixed"] or "?")))
            w("</table></div>")
            w("<details><summary>逐則公告（%d 則）</summary><div class=\"tw\"><table><tr><th>安全公告</th><th>嚴重度</th><th>CVE 數</th><th>修補來源</th></tr>"
              % len(group))
            for m in group:
                w("<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>" % (
                    _e(m["title"]), _e(sevname.get(m["severity"], m["severity"])), len(m["cves"]),
                    _e(pocket_label(m["pockets"]))))
            w("</table></div></details></details>")
    w("<h2>四、建議處理順序</h2><ol>%s</ol>" % "".join("<li>%s</li>" % _e(s) for s in priority_steps(hosts, rules)))
    w("<h2>五、檢查範圍與限制</h2><ul>%s</ul>" % "".join("<li>%s</li>" % _e(s) for s in rt["limitations"]))
    w("<h2>附錄：資料來源</h2>")
    if used:
        w("<p>比對引擎：%s</p>" % _e(args.engine_label))
        w("<div class=\"tw\"><table><tr><th>版本</th><th>檔案</th><th>官方產生時間</th><th>距分析日</th><th>SHA-256（前 16 碼）</th><th>與下載紀錄</th></tr>")
        for code, ds in sorted(used.items()):
            i = ds["info"]
            rec = {True: "一致", False: "不一致，請重新下載", None: "無紀錄"}[i["recorded"]]
            w("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _e(code_label(rules, code)), _e(i["file"]), _e(i["timestamp"] or "?"),
                _e("%d 天" % i["age_days"] if i["age_days"] is not None else "?"), _e(i["sha256"][:16]), _e(rec)))
        w("</table></div><p class=\"mut\">弱點資料：Canonical 官方 OVAL（security-metadata.canonical.com），授權 CC BY-SA 4.0。</p>")
    else:
        w("<p>未使用官方資料檔；僅參考主機上的 Ubuntu Pro 用戶端。</p>")
    # 列印或另存 PDF 前把收合的段落全部展開，紙本才不會漏掉表格
    w("<script>window.addEventListener('beforeprint',function(){"
      "document.querySelectorAll('details').forEach(function(d){d.open=true;});});</script>")
    w("</main></body></html>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 9. 對外的分析流程（analyze.py 與 hc 共用）
# ---------------------------------------------------------------------------
def find_datasets(args):
    """依 --oval 或 --data 找出各版本代號的官方資料檔（還不載入）。"""
    found = {}
    paths = []
    if getattr(args, "oval", None):
        paths.append(args.oval)
    elif args.data and os.path.isdir(args.data):
        paths = [os.path.join(args.data, n) for n in sorted(os.listdir(args.data))]
    for p in paths:
        m = re.match(r"oci\.com\.ubuntu\.([a-z]+)\.usn\.oval\.xml(\.bz2)?$", os.path.basename(p))
        if m and os.path.isfile(p):
            found.setdefault(m.group(1), {"path": p})
        elif getattr(args, "oval", None):
            raise ValueError("指定的資料檔必須是官方套件清單版（檔名 oci.com.ubuntu.<代號>.usn.oval.xml.bz2）")
    return found


def quick_data_info(path):
    """不解壓整個檔案，只讀開頭取得官方產生時間（給掃描前的提示用）。"""
    try:
        d = bz2.BZ2Decompressor() if path.endswith(".bz2") else None
        with open(path, "rb") as f:
            head = f.read(65536)
        text = (d.decompress(head) if d else head).decode("utf-8", "replace")
        m = re.search(r"<oval:timestamp>([^<]+)</oval:timestamp>", text)
        ts = m.group(1) if m else ""
        age = (datetime.date.today() - datetime.date(*map(int, ts[:10].split("-")))).days if ts else None
        return ts, age
    except Exception:
        return "", None


def stale_codes(datasets, rules):
    lim = rules["thresholds"]["data_max_age_days"]
    return sorted(c for c, ds in datasets.items() if ds.get("used") and ds["info"]["age_days"] is not None
                  and ds["info"]["age_days"] > lim)


def setup_engine(args):
    """決定比對引擎；找不到 oscap 卻指定要用時丟出錯誤。"""
    ver = oscap_version() if args.engine in ("auto", "oscap", "both") else None
    if args.engine in ("oscap", "both") and not ver:
        raise RuntimeError("找不到 oscap 指令。Ubuntu 上可安裝 openscap-scanner（24.04 以後）或 libopenscap8（22.04 以前）")
    args.engine_used = "oscap" if (args.engine == "auto" and ver) else ("builtin" if args.engine == "auto" else args.engine)
    args.engine_label = {"oscap": "OpenSCAP %s" % ver, "builtin": "內建比對（依官方 OVAL 的同一套判斷條件實作）",
                         "both": "OpenSCAP %s（並以內建比對對照）" % ver}[args.engine_used]


def load_inputs(paths):
    out = []
    for b in paths:
        try:
            out.append((b, load_bundle(b)))
        except Exception as e:
            out.append((b, e))
    return out


def needed_codenames(loaded, rules):
    need = set()
    for _, f in loaded:
        if isinstance(f, dict):
            osr = parse_kv(strip_exit(f.get("os-release.txt", "")))
            code = (rules["lifecycle"].get(osr.get("VERSION_ID", "")) or {}).get("codename") or osr.get("VERSION_CODENAME", "")
            if code:
                need.add(code)
    return need


def run_analysis(loaded, args, rules, log=None):
    """分析已讀入的收集檔，寫出報告；回傳 (hosts, datasets, 警告)。"""
    log = log or (lambda m: print(m, file=sys.stderr))
    setup_engine(args)
    datasets = find_datasets(args)
    today = datetime.date.today()
    need = needed_codenames(loaded, rules)
    for code, ds in datasets.items():
        if code not in need:
            continue
        try:
            ds["oval"] = load_oval(ds["path"])
            if not ds["oval"]["manifest_based"]:
                raise ValueError("不是套件清單版（oci.）的 OVAL")
            ds["info"] = oval_info(ds["path"], rules)
            ts = ds["oval"]["timestamp"]
            ds["info"]["timestamp"] = ts
            try:
                ds["info"]["age_days"] = (today - datetime.date(*map(int, ts[:10].split("-")))).days
            except ValueError:
                pass
            ds["used"] = True
            log("已載入官方資料：%s，%d 則公告，官方產生時間 %s" % (code_label(rules, code), len(ds["oval"]["defs"]), ts))
        except Exception as e:
            log("警告：資料檔 %s 無法使用（%s: %s）" % (ds["path"], type(e).__name__, e))
            ds.pop("oval", None)
    hosts = []
    for b, f in loaded:
        try:
            if isinstance(f, Exception):
                raise f
            hosts.append(analyze_host(f, args, rules, datasets))
        except Exception as e:  # 單台資料壞掉不影響其他主機
            log("警告：%s 無法分析（%s: %s）" % (b, type(e).__name__, e))
            hosts.append(error_host(b, e))
    warnings = []
    renamed = dedupe_tags(hosts)
    if renamed and not args.deidentify:
        warnings.append("有主機代號重複，已自動加上序號：%s。請確認收集時的代號。" % "、".join(renamed))
    elif renamed:  # 去識別化版本不寫出原代號
        warnings.append("有 %d 台主機的代號重複，已自動編號。請確認收集時的代號。" % len(renamed))
    dup_ai = "有 %d 台主機的代號重複，已自動編號。請確認收集時的代號。" % len(renamed)
    warnings_ai = [x for x in warnings if not x.startswith("有主機代號重複") and x != dup_ai]
    if renamed:
        warnings_ai.append(dup_ai)
    for i, h in enumerate(hosts, 1):
        h["ai_tag"] = "H%02d" % i  # findings-ai.json 用的代號；對照只寫在地端的報告
    if args.deidentify:
        hosts = deidentify(hosts)
        args.agency = "（已去識別化）"
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "report-%s.html" % args.stamp), "w", encoding="utf-8") as f:
        f.write(render_html(hosts, args, rules, datasets, warnings))
    # 完整比對明細另存一檔，給客戶自己留存；findings-ai 只留摘要，交給顧問分析
    detail = [{"tag": h["tag"], "oval_matches": h.get("oval_matches", [])} for h in hosts]
    with open(os.path.join(args.out, "oval-detail.json"), "w", encoding="utf-8") as f:
        json.dump(detail, f, ensure_ascii=False, indent=1)
    slim = copy.deepcopy(hosts)
    for h in slim:
        matches = h.get("oval_matches", [])
        h["oval_matches"] = [{"title": m["title"], "severity": m["severity"], "needs_pro": m["needs_pro"],
                              "pockets": m["pockets"], "cve_count": len(m["cves"]),
                              "attack_vector": m.get("attack_vector", "官方未提供"), "cvss_max": m.get("cvss_max"),
                              "issued": m.get("issued", ""),
                              "packages": sorted({p["source"] for p in m["packages"]})}
                             for m in matches]
        # 每個套件「已安裝版本 → 修補版本」，AI 才能說明要更新到哪一版
        h["package_updates"] = [{"source": e["source"], "severity": e["severity"], "needs_pro": e["needs_pro"],
                                 "pockets": sorted(e["pockets"]), "usn_count": len(e["usns"]),
                                 "installed": sorted(e["installed"])[:2], "fixed": e["fixed"]}
                                for e in group_by_package(matches)]
        for x in h.get("findings", []):
            x.pop("short", None)
    out = {"schema": "offline-ubuntu-healthcheck/0.7", "tool_version": TOOL_VERSION, "basis_month": args.date,
           "generated_at": args.stamp,
           "deidentified": args.deidentify, "warnings": warnings_ai if args.deidentify else warnings,
           "engine": args.engine_label if any(ds.get("used") for ds in datasets.values()) else None,
           "data": {c: ds["info"] for c, ds in datasets.items() if ds.get("used")},
           "categories": rules["categories"], "priority_steps": priority_steps(hosts, rules), "hosts": slim}
    steps_ai = priority_steps([dict(h, tag=h["ai_tag"]) for h in hosts], rules)
    if rules["report_text"].get("priority_steps"):  # 自訂的固定文字裡可能寫了主機代號，逐一換成交件代號
        m = {h["tag"]: h["ai_tag"] for h in hosts}
        rx = re.compile(r"(?<![A-Za-z0-9._-])(%s)(?![A-Za-z0-9._-])" % "|".join(
            re.escape(t) for t in sorted(m, key=len, reverse=True)))
        steps_ai = [rx.sub(lambda g: m[g.group(1)], x) for x in steps_ai]
    ai = ai_view(out, warnings_ai, steps_ai)
    with open(os.path.join(args.out, "findings-ai-%s.json" % args.stamp), "w", encoding="utf-8") as f:
        json.dump(ai, f, ensure_ascii=False, indent=2)
    return hosts, datasets, warnings


def ai_view(out, warnings_ai, steps_ai):
    """去識別化版本：主機代號改用交件代號（H01、H02…），收集時間只留日期，警告不出現原代號，
    不放代號對照。"""
    ai = copy.deepcopy(out)
    ai["deidentified"] = True
    ai["warnings"] = list(warnings_ai)
    for h in ai["hosts"]:
        h["tag"] = h.pop("ai_tag", h["tag"])
        h["collected_at"] = str(h.get("collected_at", ""))[:10]
    ai["priority_steps"] = list(steps_ai)  # 用交件代號重新產生，不在文字裡替換代號
    return ai


def pad(text, width):
    """依顯示寬度補空白（中文字算兩格），讓畫面上的欄位對齊。"""
    text = str(text)
    w = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return text + " " * max(width - w, 1)


def print_summary(hosts, datasets, warnings, args, rules, stream=None):
    """在畫面上印出看得懂的摘要。"""
    stream = stream or sys.stdout
    p = lambda m="": print(m, file=stream)
    risky = sum(1 for h in hosts if h["support_status"] in ("esm", "legacy", "eol", "nonlts"))
    p()
    p("健檢完成：%d 台主機，其中 %d 台已過標準維護期" % (len(hosts), risky))
    p("-" * 60)
    for h in hosts:
        if h.get("error"):
            p("  " + pad(h["tag"], 16) + h["error"])
            continue
        c, pt = cat_counts(h), h["patches"]
        line = "  " + pad(h["tag"], 16) + pad(h.get("version_id", "?"), 8) + pad(STATUS_LABEL.get(h["support_status"], "?"), 16) + \
            "A %d｜B %d｜C %d｜D %d" % (c["A"], c["B"], c["C"], c["D"])
        if pt["source"] != "none":
            line += "｜需 Pro %d、免費可修 %d %s" % (pt["needs_pro"], pt["free_not_applied"], pt.get("unit", ""))
        e = h.get("engine_check")
        if e:
            line += "｜引擎對照%s" % ("一致" if not e["only_oscap"] and not e["only_builtin"] else "有差異")
        p(line)
        if h.get("unchecked"):
            p("  " + pad("", 16) + "未能檢查 %d 項（見報告）" % len(h["unchecked"]))
    p("-" * 60)
    p("A＝訂閱 Ubuntu Pro 可解決　B＝要重開機（Livepatch 可部分解決）　C＝合規工具　D＝與 Pro 無關")
    for x in warnings:
        p("注意：" + x)
    used = {c: ds for c, ds in datasets.items() if ds.get("used")}
    for c, ds in sorted(used.items()):
        i = ds["info"]
        p("官方資料：%s，產生於 %s（%s 天前），雜湊核對：%s" % (
            code_label(rules, c), (i["timestamp"] or "?")[:10], i["age_days"] if i["age_days"] is not None else "?",
            {True: "一致", False: "不一致！", None: "無紀錄"}[i["recorded"]]))
    p()
    p("報告：%s　← 用瀏覽器打開" % os.path.join(args.out, "report-%s.html" % args.stamp))
    p("完整明細：oval-detail.json（自己留存即可，不必寄出）")
    p("怎麼看報告：使用者手冊 docs/user-guide.pdf 第 5 章")
    p("交給顧問：%s（已去識別化，主機代號改成 H01、H02…%s）" % (os.path.join(args.out, "findings-ai-%s.json" % args.stamp),
      "" if args.deidentify else "，對照在報告的「交件代號」欄"))


def default_out(now):
    return os.path.join("reports", now.strftime("%Y-%m-%d-%H%M%S"))


def add_common_args(ap):
    ap.add_argument("--data", default=os.path.join(HERE, "data"), help="官方資料檔所在資料夾（預設：程式旁的 data/）")
    ap.add_argument("--oval", help="只用這一個官方資料檔（oci.com.ubuntu.<代號>.usn.oval.xml.bz2）")
    ap.add_argument("--engine", choices=["auto", "oscap", "builtin", "both"], default="auto",
                    help="比對引擎（預設 auto：有 oscap 就用，否則內建）")
    ap.add_argument("--rules", help="自訂規則檔（JSON），覆蓋在 rules/default-rules.json 上")
    ap.add_argument("--deidentify", action="store_true",
                    help="整份報告都去識別化：主機代號改為 H01、H02…（findings-ai 檔每次都是去識別化版本，不必加這個參數）")
    ap.add_argument("--agency", default="", help="受檢單位（報告表頭）")
    ap.add_argument("--assessor", dest="dealer", default="", help="執行單位（報告表頭）")
    ap.add_argument("--date", default=datetime.date.today().strftime("%Y-%m"), help="判斷基準月份 YYYY-MM（預設本月）")
    ap.add_argument("--out", default=None, help="輸出資料夾（預設 reports/<日期時間>/）")


def validate_common(ap, args):
    if not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", args.date):
        ap.error("--date 格式必須是 YYYY-MM，例如 2026-11")
    if args.oval and not os.path.isfile(args.oval):
        ap.error("找不到資料檔：%s" % args.oval)
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as e:
        ap.error("規則檔讀取失敗：%s" % e)
    now = datetime.datetime.now()
    args.stamp = now.strftime("%Y%m%d-%H%M%S")  # 輸出檔名與 generated_at 用同一個時間
    if not args.out:
        args.out = default_out(now) + ("-deid" if args.deidentify else "")
    return rules


def main():
    ap = argparse.ArgumentParser(description="offline-ubuntu-healthcheck 分析程式（一般使用建議改用 ./hc report）")
    ap.add_argument("bundles", nargs="+", help="collect.sh 產出的 tar.gz（或解壓後的資料夾）")
    add_common_args(ap)
    args = ap.parse_args()
    rules = validate_common(ap, args)
    try:
        hosts, datasets, warnings = run_analysis(load_inputs(args.bundles), args, rules)
    except (RuntimeError, ValueError) as e:
        ap.error(str(e))
    print_summary(hosts, datasets, warnings, args, rules)


if __name__ == "__main__":
    sys.exit(main())
