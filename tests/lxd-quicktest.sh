#!/bin/bash
# offline-ubuntu-healthcheck｜LXD 快速測試（tests/lxd-quicktest.sh）
# 版本：0.5
#
# 在一台裝好 LXD 的 Ubuntu（例如 Desktop 26.04）上，一個指令完成：
#   建立虛擬機 → 裝一個 Universe 套件 → 一般使用者與 sudo 各收集一次 → 斷網再收集一次並計時
#   → 檢查有沒有寫入其他檔案 → 檢查收集檔有沒有主機名稱與 IP → 兩個比對引擎分析並對照 → 印出測試結果表
#
# 用法（在專案根目錄或任何地方都可以）：
#   tests/lxd-quicktest.sh                       # 預設只測 20.04 24.04（其他版本用參數指定）
#   tests/lxd-quicktest.sh 16.04 20.04           # 指定版本
#   tests/lxd-quicktest.sh --allow-container 16.04   # 建不了虛擬機時改用容器（核心相關項目不準）
#   tests/lxd-quicktest.sh --keep 22.04          # 測完保留虛擬機（預設也保留，方便重跑）
#   tests/lxd-quicktest.sh --cleanup             # 刪除本腳本建立的所有測試機（名稱開頭 hc-t-）
#
# 結果放在 test-results/<日期時間>/，最後的 RESULTS.md 可以直接貼進測試紀錄。
# 需要：lxc、python3；建議另外安裝 openscap-scanner，才能做雙引擎對照。

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
PREFIX="hc-t-"

ALLOW_CT=0
VERSIONS=()
for a in "$@"; do
  case "$a" in
    --cleanup)
      names=$(lxc list -c n --format csv 2>/dev/null | grep "^${PREFIX}" || true)
      if [ -z "$names" ]; then echo "沒有要刪除的測試機。"; exit 0; fi
      echo "將刪除：$(echo $names)"
      for n in $names; do lxc delete --force "$n" && echo "  已刪除 $n"; done
      exit 0 ;;
    --allow-container) ALLOW_CT=1 ;;
    --keep) ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    [0-9][0-9].[0-9][0-9]) VERSIONS+=("$a") ;;
    *) echo "不認得的參數：$a（版本請寫成 22.04 這種格式）"; exit 2 ;;
  esac
done
[ ${#VERSIONS[@]} -eq 0 ] && VERSIONS=(20.04 24.04)

command -v lxc >/dev/null || { echo "找不到 lxc。請先安裝：sudo snap install lxd && sudo lxd init --minimal"; exit 1; }
command -v python3 >/dev/null || { echo "找不到 python3"; exit 1; }
ENGINE=builtin
if command -v oscap >/dev/null; then ENGINE=both; else
  echo "提醒：沒有 oscap，只用內建比對（要做雙引擎對照請先 sudo apt install openscap-scanner）"
fi

OUT="test-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/bundles" "$OUT/logs"
RES="$OUT/results.tsv"
: > "$RES"
log() { echo "[$(date +%H:%M:%S)] $*"; }
rec() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RES"; }   # 版本 項目 結果 說明

# 官方資料（T13）
log "更新官方資料"
if python3 update-data.py --releases "$(IFS=,; echo "${VERSIONS[*]}")" > "$OUT/logs/update.log" 2>&1 \
   && python3 update-data.py --verify >> "$OUT/logs/update.log" 2>&1; then
  rec all T13 通過 "下載與雜湊核對成功"
else
  rec all T13 不通過 "見 logs/update.log（沒有網路時可略過）"
fi

collect() {  # collect <機器> <代號> <sudo:0/1>
  local vm="$1" tag="$2" su="$3" pre=""
  [ "$su" = 1 ] && pre="sudo -n "
  lxc exec "$vm" -- su - ubuntu -c "${pre}bash -s -- --tag $tag --stdout" \
    < collect.sh > "$OUT/bundles/hc-$tag.tar.gz" 2> "$OUT/logs/collect-$tag.log"
  local rc=$?
  if [ $rc -eq 0 ] && [ "$(head -c2 "$OUT/bundles/hc-$tag.tar.gz" | od -An -tx1 | tr -d ' ')" = "1f8b" ]; then
    return 0
  fi
  rm -f "$OUT/bundles/hc-$tag.tar.gz"
  return 1
}

for V in "${VERSIONS[@]}"; do
  VM="${PREFIX}${V/./}"
  log "===== $V（$VM）====="
  KIND=vm
  if ! lxc info "$VM" >/dev/null 2>&1; then
    if ! lxc launch "ubuntu:$V" "$VM" --vm > "$OUT/logs/launch-$V.log" 2>&1; then
      if [ "$ALLOW_CT" = 1 ]; then
        log "無法建立虛擬機，改用容器（核心相關項目不準）"
        lxc launch "ubuntu:$V" "$VM" >> "$OUT/logs/launch-$V.log" 2>&1 || { rec "$V" 建機 略過 "容器也建不了，見 logs/launch-$V.log"; continue; }
        KIND=container
      else
        rec "$V" 建機 略過 "無法建立虛擬機（見 logs/launch-$V.log）；可加 --allow-container 改用容器"
        log "無法建立虛擬機，略過"; continue
      fi
    fi
  else
    [ "$(lxc list "$VM" -c t --format csv)" = "CONTAINER" ] && KIND=container
    lxc start "$VM" >/dev/null 2>&1 || true
  fi
  # 等開機完成（虛擬機的 agent 起來前 lxc exec 會失敗）
  ready=0
  for i in $(seq 1 60); do lxc exec "$VM" -- true >/dev/null 2>&1 && { ready=1; break; }; sleep 5; done
  if [ $ready = 0 ]; then rec "$V" 建機 不通過 "等 5 分鐘仍無法進入（LXD agent 沒有啟動）"; continue; fi
  lxc exec "$VM" -- cloud-init status --wait >/dev/null 2>&1 || true
  if ! lxc exec "$VM" -- id ubuntu >/dev/null 2>&1; then
    rec "$V" 建機 不通過 "映像檔沒有 ubuntu 帳號"; continue
  fi
  [ "$KIND" = container ] && rec "$V" 註記 容器 "核心版本、重開機等項目反映的是測試主機，不準"
  log "安裝一個 Universe 套件（nginx）"
  lxc exec "$VM" -- sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq nginx' \
    > "$OUT/logs/apt-$V.log" 2>&1 || log "安裝失敗（可能沒有網路），繼續"

  # T1、T6：一般使用者與 sudo
  lxc exec "$VM" -- sh -c 'rm -f /tmp/hc-marker; touch /tmp/hc-marker'; sleep 1
  t0=$(date +%s)
  if collect "$VM" "T-$V-user" 0; then rec "$V" T1-一般使用者 通過 "$(( $(date +%s) - t0 )) 秒"; else rec "$V" T1-一般使用者 不通過 "見 logs/collect-T-$V-user.log"; fi
  t0=$(date +%s)
  if collect "$VM" "T-$V-sudo" 1; then rec "$V" T1-sudo 通過 "$(( $(date +%s) - t0 )) 秒"; else rec "$V" T1-sudo 不通過 "見 logs/collect-T-$V-sudo.log"; fi

  # T2：除了收集之外，有沒有寫入其他檔案
  lxc exec "$VM" -- sh -c 'find / -xdev -newer /tmp/hc-marker -type f 2>/dev/null | grep -v -e "^/proc" -e "^/sys" -e "^/tmp/hc-marker$"' \
    > "$OUT/logs/written-$V.txt" 2>/dev/null
  nw=$(grep -c . "$OUT/logs/written-$V.txt")
  if [ "$nw" -eq 0 ]; then rec "$V" T2 通過 "沒有寫入其他檔案"; else rec "$V" T2 記錄 "$nw 個檔案被寫入，清單見 logs/written-$V.txt（多為系統自身活動，請人工判斷）"; fi

  # T3：斷網後收集
  nic=$(lxc exec "$VM" -- sh -c "ip -o route show default | awk '{print \$5; exit}'" 2>/dev/null)
  if [ -n "$nic" ]; then
    lxc exec "$VM" -- ip link set "$nic" down
    t0=$(date +%s)
    if collect "$VM" "T-$V-offline" 0; then rec "$V" T3 通過 "斷網收集 $(( $(date +%s) - t0 )) 秒"; else rec "$V" T3 不通過 "見 logs/collect-T-$V-offline.log"; fi
    lxc exec "$VM" -- ip link set "$nic" up
    rm -f "$OUT/bundles/hc-T-$V-offline.tar.gz"   # 只用來計時，不進報告
  else
    rec "$V" T3 略過 "找不到預設網卡"
  fi

  # T7：隱私（優先檢查 sudo 版，收得最多；沒有就用一般使用者版）
  pb=""
  for k in sudo user; do [ -f "$OUT/bundles/hc-T-$V-$k.tar.gz" ] && { pb="$OUT/bundles/hc-T-$V-$k.tar.gz"; break; }; done
  hn=$(lxc exec "$VM" -- hostname 2>/dev/null | tr -d '[:space:]')
  if [ -z "$pb" ]; then
    rec "$V" T7 略過 "沒有收集檔可檢查"
  elif [ -z "$hn" ]; then
    rec "$V" T7 略過 "取不到虛擬機的主機名稱"
  else
    chk="$OUT/logs/privacy-$V"; mkdir -p "$chk"; tar -xzf "$pb" -C "$chk"
    ips=$(lxc exec "$VM" -- sh -c "hostname -I 2>/dev/null")
    hits=$(grep -rl -F -- "$hn" "$chk" | wc -l | tr -d ' ')
    for ip in $ips; do hits=$(( hits + $(grep -rl -F -- "$ip" "$chk" | wc -l) )); done
    if [ "$hits" -eq 0 ]; then rec "$V" T7 通過 "收集檔中找不到主機名稱與 IP（檢查 ${pb##*/}）"; else rec "$V" T7 不通過 "有 $hits 個檔案含主機名稱或 IP，見 logs/privacy-$V"; fi
  fi

  # T4、T14：對照主機上 pro security-status
  lxc exec "$VM" -- sh -c 'pro security-status 2>/dev/null || ua security-status 2>/dev/null' > "$OUT/logs/security-status-$V.txt" 2>&1 || true
done

# 分析（T8、T10、T11、T15）
B=$(ls "$OUT"/bundles/*.tar.gz 2>/dev/null)
if [ -z "$B" ]; then echo "沒有任何收集檔，無法分析。"; else
  log "分析（引擎：$ENGINE）"
  python3 hc report $B --engine "$ENGINE" --update no --date "$(date +%Y-%m)" --out "$OUT/report" > "$OUT/logs/analyze.log" 2>&1
  python3 - "$OUT" "$ENGINE" <<'EOF' >> "$RES"
import json, sys, os
out, engine = sys.argv[1], sys.argv[2]
import glob
try:
    d = json.load(open(glob.glob(os.path.join(out, "report", "findings-ai-*.json"))[0], encoding="utf-8"))
    # findings-ai 的代號是 H01、H02…；oval-detail.json 的主機順序相同、保留原代號，用來對回 -user／-sudo
    tags = [x["tag"] for x in json.load(open(os.path.join(out, "report", "oval-detail.json"), encoding="utf-8"))]
    assert len(tags) == len(d["hosts"])
except Exception as e:
    print("all\t分析\t不通過\t找不到 findings-ai 或 oval-detail.json（%s），見 logs/analyze.log" % e); sys.exit()
for h, tag in zip(d["hosts"], tags):
    v = h.get("version_id", "?")
    if h.get("error"):
        print("%s\t分析-%s\t不通過\t%s" % (v, tag, h["error"])); continue
    e = h.get("engine_check")
    if e:
        same = not e["only_oscap"] and not e["only_builtin"]
        print("%s\tT10/T11-%s\t%s\tOpenSCAP %d 則、內建 %d 則" % (v, tag, "通過" if same else "不通過", e["oscap"], e["builtin"]))
    if tag.endswith("-user"):
        need = [x for x in h["unchecked"] if "sudo" in x]
        print("%s\tT6\t%s\t一般使用者有 %d 項列為「未能檢查」（應為 SSH、防火牆、空密碼帳號）" % (v, "通過" if len(need) >= 2 else "記錄", len(need)))
    if tag.endswith("-sudo"):
        ssh_un = [x for x in h["unchecked"] if x.startswith("SSH")]
        print("%s\tT12\t%s\t%s" % (v, "不通過" if ssh_un else "通過",
                                    "用 sudo 仍讀不到 SSH 設定，見收集檔裡的 sshd.txt" if ssh_un else "用 sudo 讀到 SSH 設定"))
        p = h["patches"]
        print("%s\tT8-摘要\t人工核對\t%s；需 Pro %s、免費未套用 %s（%s）" % (v, h["support_text"], p["needs_pro"], p["free_not_applied"], p.get("unit", "")))
        if v == "26.04":
            print("%s\tT15\t%s\t維護狀態：%s" % (v, "通過" if h["support_status"] == "standard" else "不通過", h["support_text"]))
EOF
fi

# 結果表
{
  echo "# LXD 快速測試結果（$(date '+%Y-%m-%d %H:%M')）"
  echo
  echo "工具版本：$(grep -m1 '^TOOL_VERSION' analyze.py | cut -d'"' -f2)　比對引擎：$ENGINE　原始資料：$OUT"
  echo
  echo "| 版本 | 項目 | 結果 | 說明 |"
  echo "|---|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4}' "$RES"
  echo
  echo "未自動化的項目：T8（人工核對報告內容）、T9（已註冊主機，需自行輸入 token）、T4／T5（請看 logs/security-status-*.txt 與收集檔中的 pro-api-updates.json）。"
} > "$OUT/RESULTS.md"
cat "$OUT/RESULTS.md"
echo
R=$(ls "$OUT"/report/report-*.html 2>/dev/null | head -1); [ -n "$R" ] && echo "報告：$R（用瀏覽器打開）"
echo "測試機都保留著，可以直接重跑；要刪除請執行：tests/lxd-quicktest.sh --cleanup"
