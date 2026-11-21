#!/bin/bash
# offline-ubuntu-healthcheck｜「只修這一則」指令的 LXD 驗證（tests/lxd-fixcheck.sh）
# 版本：0.6.5
#
# 驗證 v0.6 報告「重大與高風險公告」附的兩行指令：
#   sudo pro fix USN-…                                   （主機要能連到 Canonical）
#   sudo apt update && sudo apt install --only-upgrade …  （只升級這則公告點名的套件）
#
# 每個版本建一台全新的測試機，做這些事：
#   1. 關掉測試機的自動更新，免得測到一半套件被自動升回去
#   2. 把幾包不同類型的套件降回發行時的版本，製造確定存在的安全缺口：
#        openssl（單純，當基準）、curl、vim（一包拆成多個套件）、sudo、
#        Python 3（相依最複雜）、libxml2、expat（很多程式共用的函式庫）
#      不碰 libc6、systemd、apt、dpkg，降這些容易把測試機弄壞
#   3. 在測試機裡跑 ./hc local，取出報告列的重大與高風險公告（不含核心）
#   4. 記錄 pro 用戶端版本、pro fix 有沒有 --dry-run、changelog 裡提到 USN 的版本
#   5. 拍快照。每包原始碼挑一則公告（最多 HC_MAX_FIXES 則，預設 6），每則都從快照重新開始：
#        a. apt 模擬執行 --only-upgrade，記下會升級哪些套件
#        b. pro fix --dry-run 連網跑一次、拔掉網路卡再跑一次
#        c. 還原快照，真的用 apt --only-upgrade 升級，比對前後實際變動的套件
#        d. 升級後再跑 pro fix --dry-run，看它是否認定已修好
#   6. 照報告的建議全面更新（apt update、apt upgrade），重開測試機後再跑一次 hc local，取得「更新後」的報告
#   7. 把三台的收集檔各合成一份多主機報告：combined-before（更新前）、combined-after（更新後）
#
# 用法：
#   tests/lxd-fixcheck.sh                    # 預設測 20.04 22.04 24.04（用容器，不需要虛擬機）
#   tests/lxd-fixcheck.sh 24.04              # 指定版本
#   HC_MAX_FIXES=3 tests/lxd-fixcheck.sh     # 每個版本最多測幾則公告（0＝只產生報告，不測修補指令）
#   HC_AFTER_UPGRADE=0 tests/lxd-fixcheck.sh # 不做第 6 步（不產生更新後的報告）
#   HC_DATA=git tests/lxd-fixcheck.sh        # 不向 Canonical 下載，改用 git clone 內附的官方資料（官方網站故障時用）
#   HC_POOL=default tests/lxd-fixcheck.sh    # 指定儲存池；沒指定時自動挑 btrfs 或 zfs 的儲存池（快照與還原快很多），都沒有才用預設
#   tests/lxd-fixcheck.sh --cleanup          # 刪除本腳本建立的測試機（名稱開頭 hc-f-）
#
# 注意：名稱開頭 hc-f- 的容器會在每次執行時刪掉重建，--cleanup 也會刪掉它們。
# 結果放在 test-results/fixcheck-<日期時間>/，RESULTS.md 可以直接貼回來。
# 需要：lxc、python3，以及這台電腦能上網（下載官方資料、測試機要 apt）。
# 不在測試範圍：Landscape 離線（air-gapped）環境；那需要另外架設 Landscape，本腳本只用「拔網路卡」模擬連不到 Canonical。

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
PREFIX="hc-f-"
SNAP="hc-base"
MAX_FIXES="${HC_MAX_FIXES:-6}"
AFTER="${HC_AFTER_UPGRADE:-1}"
DATA_SRC="${HC_DATA:-canonical}"
POOL="${HC_POOL:-}"
# 要降版的原始碼套件（awk 正規表示式；不用反斜線，mawk 與 gawk 都能用）
# python3-defaults（python3 指令本身）要跟 python3.X 一起降，否則版本相依會卡住
SRC_RE='openssl|curl|vim|sudo|python3[.][0-9]+|python3-defaults|libxml2|expat'
# apt 共用選項：搶不到鎖就等、設定檔一律留舊的、不准為了解決相依而移除套件
APT_OPTS='-o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold'
VERSIONS=()
for a in "$@"; do
  case "$a" in
    --cleanup)
      names=$(lxc list -c n --format csv 2>/dev/null | grep "^${PREFIX}" || true)
      if [ -z "$names" ]; then echo "沒有要刪除的測試機。"; exit 0; fi
      for n in $names; do lxc delete --force "$n" && echo "已刪除 $n"; done
      exit 0 ;;
    -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
    [0-9][0-9].[0-9][0-9]) VERSIONS+=("$a") ;;
    *) echo "不認得的參數：$a"; exit 2 ;;
  esac
done
[ ${#VERSIONS[@]} -eq 0 ] && VERSIONS=(20.04 22.04 24.04)
command -v lxc >/dev/null || { echo "找不到 lxc。請先安裝：sudo snap install lxd && sudo lxd init --minimal"; exit 1; }
command -v python3 >/dev/null || { echo "找不到 python3"; exit 1; }

# 儲存池：沒指定時挑第一個 btrfs，其次 zfs；都沒有就用 LXD 預設（dir 的快照是整份複製，慢）
if [ -z "$POOL" ]; then
  POOL=$(lxc storage list --format json 2>/dev/null | python3 -c '
import json, sys
try:
    pools = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for drv in ("btrfs", "zfs"):
    for p in pools:
        if p.get("driver") == drv:
            print(p["name"]); sys.exit(0)')
fi
if [ -n "$POOL" ]; then
  lxc storage show "$POOL" >/dev/null 2>&1 || { echo "找不到儲存池：$POOL（用 lxc storage list 查名稱）"; exit 1; }
  POOL_ARGS=(-s "$POOL")
else
  POOL_ARGS=()
fi

OUT="$ROOT/test-results/fixcheck-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/data" "$OUT/logs"
log() { echo "[$(date +%H:%M:%S)] $*"; }
log "儲存池：${POOL:-LXD 預設}"

# 等測試機開好機、拿到網路（有預設路由，也查得到網域名稱）
wait_ready() {
  for _ in $(seq 1 60); do
    lxc exec "$1" -- sh -c 'ip -o route show default | grep -q . && getent hosts archive.ubuntu.com' </dev/null >/dev/null 2>&1 && return 0
    sleep 3
  done
  return 1
}
# 把測試機還原到快照（停機→還原→開機）
restore() {
  lxc stop --force "$1" >/dev/null 2>&1
  lxc restore "$1" "$SNAP" >/dev/null 2>&1 || { log "  [警告] $1 還原快照失敗"; lxc start "$1" >/dev/null 2>&1; return 1; }
  lxc start "$1" >/dev/null 2>&1
  wait_ready "$1" || { log "  [警告] $1 還原後等不到網路"; return 1; }
}

# 照報告建議全面更新、重開機，再跑一次 hc local，取得「更新後」的報告（測試機要在更新前的狀態）
after_upgrade() {
  [ "$AFTER" = 1 ] || return 0
  log "[$V] 照報告建議全面更新（apt update、apt upgrade），重開後再產生報告"
  lxc exec "$VM" -- sh -c "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a; apt-get update -q $APT_OPTS && apt-get upgrade -y $APT_OPTS" </dev/null > "$L/upgrade-all.log" 2>&1
  rc=$?
  echo "__EXIT__=$rc" >> "$L/upgrade-all.log"
  if [ $rc != 0 ]; then log "[$V] 全面更新失敗，不產生更新後的報告，見 $L/upgrade-all.log"; return 0; fi
  # 22.04 以後 apt 有分階段推送（phased updates），apt upgrade 可能暫緩少數套件，更新後報告留下幾則屬正常
  lxc restart --timeout 120 "$VM" >/dev/null 2>&1 || lxc restart --force "$VM" >/dev/null 2>&1
  wait_ready "$VM" || log "  [警告] $VM 重開後等不到網路"
  lxc exec "$VM" -- rm -rf /root/out-after </dev/null
  lxc exec "$VM" -- sh -c 'cd /root/hc && python3 hc local --update no --tag U'"${V/./}"' --out /root/out-after' </dev/null > "$L/hc-local-after.log" 2>&1
  mkdir -p "$L/report-after"
  lxc exec "$VM" -- tar -czf - -C /root/out-after . </dev/null 2>/dev/null | tar -xzf - -C "$L/report-after" 2>/dev/null
}

# 在測試機裡執行的降版程式（先推進測試機再執行，標準輸入接 /dev/null）
cat > "$OUT/logs/downgrade.sh" <<'EOS'
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
. /etc/os-release
# 只取真的裝著的套件（ii），只剩設定檔的不算
dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\t${Source}\n' \
  | awk -F'\t' -v re="^(${SRC_RE})\$" '$1 ~ /^ii/ {s=$4; if (s=="") s=$2; sub(/ .*/, "", s); if (s ~ re) print s "\t" $2 "\t" $3}' > /root/targets.tsv
: > /root/downgrade.tsv
while IFS="$(printf '\t')" read -r s p cur; do
  # 發行版本：apt-cache madison 裡來源是「<代號>/」那一行（不是 -updates、-security）
  rel=$(apt-cache madison "$p" | awk -F'|' -v c=" ${VERSION_CODENAME}/" 'index($3, c) {gsub(/ /, "", $2); print $2; exit}')
  if [ -n "$rel" ] && [ "$rel" != "$cur" ]; then
    printf '%s\t%s\t%s\t%s\n' "$s" "$p" "$cur" "$rel" >> /root/downgrade.tsv
  fi
done < /root/targets.tsv
echo "== 要降版的套件（原始碼／套件／目前版本／發行版本）"; cat /root/downgrade.tsv
args=$(awk -F'\t' '{printf " %s=%s", $2, $4}' /root/downgrade.tsv)
if [ -z "$args" ]; then echo "沒有可降版的套件"; else
  echo "== 一次降版"
  if ! apt-get install -y -q --no-remove --allow-downgrades $APT_OPTS $args; then
    # 逐組降版；python3.X 與 python3-defaults 同一組
    echo "== 一次降版失敗，改成逐組降版"
    for g in $(awk -F'\t' '{g=$1; if (g ~ /^python3/) g="python"; print g}' /root/downgrade.tsv | sort -u); do
      a=$(awk -F'\t' -v g="$g" '{x=$1; if (x ~ /^python3/) x="python"} x==g {printf " %s=%s", $2, $4}' /root/downgrade.tsv)
      echo "== $g：$a"
      apt-get install -y -q --no-remove --allow-downgrades $APT_OPTS $a || echo "== $g 降版失敗"
    done
  fi
fi
# 依實際裝著的版本判斷每包原始碼有沒有降成功
dpkg-query -W -f '${Package}\t${Version}\n' > /root/now.tsv
awk -F'\t' 'NR==FNR {v[$1]=$2; next} {if (v[$2]!=$4) bad[$1]=1; seen[$1]=1}
  END {for (s in seen) print s "\t" (s in bad ? "fail" : "ok")}' /root/now.tsv /root/downgrade.tsv > /root/downgrade-status.tsv
echo "== 降版結果"; cat /root/downgrade-status.tsv
EOS

log "下載官方資料"
# 從 git clone 一起下載的 data 分支取官方資料（不需要網路）
from_git() {
  python3 - "$OUT/data" >> "$OUT/logs/update.log" 2>&1 <<'PYG'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("updater", "update-data.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
n = m.sync_from_git(sys.argv[1], quiet=False)
print("git 內附資料：%s" % ("找不到（不是用 git clone 下載，或沒有 data 分支）" if n is None else "放入 %d 個檔案" % n))
sys.exit(1 if n is None else 0)
PYG
}
# 每個要測的版本都要有資料檔
have_all() {
  python3 - "$OUT/data" "${VERSIONS[@]}" <<'PYC'
import json, os, sys
lc = json.load(open("rules/default-rules.json", encoding="utf-8"))["lifecycle"]
miss = [v for v in sys.argv[2:] if not os.path.isfile(os.path.join(
    sys.argv[1], "oci.com.ubuntu.%s.usn.oval.xml.bz2" % lc.get(v, {}).get("codename", "?")))]
if miss:
    print("缺少這些版本的官方資料：" + "、".join(miss))
sys.exit(1 if miss else 0)
PYC
}
if [ "$DATA_SRC" = git ]; then
  log "HC_DATA=git：不下載，改用 git clone 內附的官方資料"
  from_git
else
  # 官方網站偶爾回 HTTP 503 等暫時錯誤：最多試 3 次，每次間隔 60 秒；仍失敗就改用 git 內附的資料
  ok=0
  for i in 1 2 3; do
    python3 update-data.py --dest "$OUT/data" --releases "$(IFS=,; echo "${VERSIONS[*]}")" >> "$OUT/logs/update.log" 2>&1 && { ok=1; break; }
    [ $i -lt 3 ] && { log "官方資料下載有失敗（第 $i 次），60 秒後重試"; sleep 60; }
  done
  [ $ok = 1 ] || { log "向 Canonical 下載失敗三次，改用 git clone 內附的官方資料"; from_git; }
fi
have_all || { echo "官方資料不齊，見 $OUT/logs/update.log"; exit 1; }
log "官方資料：$(cd "$OUT/data" && ls oci.com.ubuntu.*.usn.oval.xml.bz2 | tr '\n' ' ')"

for V in "${VERSIONS[@]}"; do
  VM="${PREFIX}${V/./}"
  L="$OUT/logs/$V"
  mkdir -p "$L"
  log "[$V] 建立全新的測試機 $VM"
  lxc delete --force "$VM" >/dev/null 2>&1
  lxc launch "ubuntu:$V" "$VM" ${POOL_ARGS[@]+"${POOL_ARGS[@]}"} > "$L/launch.log" 2>&1 || { log "[$V] 建不了測試機，見 $L/launch.log"; continue; }
  wait_ready "$VM" || { log "[$V] 測試機沒有網路，略過"; continue; }
  lxc exec "$VM" -- cloud-init status --wait </dev/null >/dev/null 2>&1 || true

  log "[$V] 關掉自動更新、apt update"
  lxc exec "$VM" -- sh -c 'systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; systemctl stop apt-daily.service apt-daily-upgrade.service; DEBIAN_FRONTEND=noninteractive dpkg --configure -a' </dev/null > "$L/disable-auto.log" 2>&1
  ok=0
  for _ in 1 2 3; do
    lxc exec "$VM" -- sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q -o DPkg::Lock::Timeout=600' </dev/null > "$L/apt-update.log" 2>&1 && { ok=1; break; }
    sleep 20
  done
  [ $ok = 1 ] || { log "[$V] apt update 失敗三次，略過這個版本，見 $L/apt-update.log"; continue; }

  log "[$V] 把測試用的套件降回發行版本"
  lxc file push "$OUT/logs/downgrade.sh" "$VM/root/downgrade.sh" > /dev/null
  lxc exec "$VM" --env SRC_RE="$SRC_RE" --env APT_OPTS="$APT_OPTS" -- bash /root/downgrade.sh </dev/null > "$L/downgrade.log" 2>&1
  lxc exec "$VM" -- cat /root/downgrade.tsv </dev/null > "$L/downgrade.tsv" 2>/dev/null
  lxc exec "$VM" -- cat /root/downgrade-status.tsv </dev/null > "$L/downgrade-status.tsv" 2>/dev/null
  lxc exec "$VM" -- sh -c 'dpkg-query -W -f "\${Package}\t\${Version}\t\${Source}\n"' </dev/null > "$L/dpkg-before.txt" 2>&1

  log "[$V] 在測試機裡跑 hc local"
  lxc exec "$VM" -- rm -rf /root/hc /root/out </dev/null
  lxc exec "$VM" -- mkdir -p /root/hc/data </dev/null
  tar -czf - -C "$ROOT" hc analyze.py collect.sh update-data.py rules | lxc exec "$VM" -- tar -xzf - -C /root/hc
  tar -czf - -C "$OUT/data" . | lxc exec "$VM" -- tar -xzf - -C /root/hc/data
  lxc exec "$VM" -- sh -c 'cd /root/hc && python3 hc local --update no --tag U'"${V/./}"' --out /root/out' </dev/null > "$L/hc-local.log" 2>&1
  # 0.7.0 起只產生 findings-ai-<日期時間>.json；單台主機，內容與舊的 findings.json 相同（代號改成 H01）
  lxc exec "$VM" -- sh -c 'cat /root/out/findings-ai-*.json' </dev/null > "$L/findings.json" 2>/dev/null
  # 整份報告（report-*.html、findings-ai-*.json 等）也帶出來，方便看報告與測試顧問端的分析
  mkdir -p "$L/report"
  lxc exec "$VM" -- tar -czf - -C /root/out . </dev/null 2>/dev/null | tar -xzf - -C "$L/report" 2>/dev/null

  log "[$V] pro 用戶端資訊"
  {
    echo "== pro version"; lxc exec "$VM" -- pro version </dev/null 2>&1
    echo "== pro fix --help（有沒有 --dry-run）"; lxc exec "$VM" -- pro fix --help </dev/null 2>&1 | grep -i -e "dry" -e "usage" -e "USN"
    echo "== changelog 裡提到 USN 的最早幾筆"
    lxc exec "$VM" -- sh -c 'for f in /usr/share/doc/ubuntu-pro-client/changelog.Debian.gz /usr/share/doc/ubuntu-advantage-tools/changelog.Debian.gz; do [ -f "$f" ] && zcat "$f"; done' </dev/null 2>/dev/null \
      | awk '/^ubuntu-(advantage-tools|pro-client) \(/{ver=$2} /USN/{print ver": "$0}' | tail -n 5
  } > "$L/pro-info.txt" 2>&1

  # 每包原始碼挑一則非核心的重大／高風險公告：先挑重大，再挑免費的
  # 只挑這次降版的那幾包原始碼，免得名額被映像本身落後的其他套件用掉
  python3 - "$L/findings.json" "$MAX_FIXES" "$SRC_RE" > "$L/fixes.tsv" <<'PY'
import json, re, sys
try:
    cap = int(sys.argv[2])
except ValueError:
    cap = 6
rx = re.compile("^(%s)$" % sys.argv[3])
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
cand = []
for h in d.get("hosts", []):
    for f in h.get("crit_high_fixes", []):
        if f.get("kernel") or not f.get("binaries") or not f.get("usn", "").startswith("USN-"):
            continue
        if not any(rx.match(p) for p in f.get("packages", [])):
            continue
        pay = f.get("needs_pro") and not f.get("subscribed")
        cand.append((f["severity"] != "Critical", bool(pay), f["usn"], f, pay))
cand.sort(key=lambda c: c[:3])
seen = set()
n = 0
for _, _, usn, f, pay in cand:
    if n >= cap:
        break
    key = ",".join(f.get("packages", [])) or usn
    if key in seen:
        continue
    seen.add(key)
    print("%s\t%s\t%s\t%s" % (usn, key, " ".join(f["binaries"]), "需訂閱" if pay else "免費"))
    n += 1
PY
  if [ "$MAX_FIXES" = 0 ]; then log "[$V] HC_MAX_FIXES=0，略過公告測試"; after_upgrade; continue; fi
  if [ ! -s "$L/fixes.tsv" ]; then log "[$V] 報告沒有可測的非核心重大／高風險公告，見 $L/hc-local.log"; after_upgrade; continue; fi

  log "[$V] 拍快照 $SNAP"
  lxc snapshot "$VM" "$SNAP" > "$L/snapshot.log" 2>&1 || { log "[$V] 拍不了快照，見 $L/snapshot.log"; after_upgrade; continue; }
  nic=$(lxc exec "$VM" -- sh -c "ip -o route show default | awk '{print \$5; exit}'" </dev/null 2>/dev/null)

  # 從第 3 號檔案描述子讀清單；迴圈裡的 lxc exec 一律接 /dev/null，免得吃掉清單或卡在互動提問
  while IFS=$'\t' read -r -u 3 usn src bins kind; do
    log "[$V] $usn（$src：$bins，$kind）"
    F="$L/$usn"
    restore "$VM"
    lxc exec "$VM" -- sh -c "apt-get -s install --only-upgrade $bins" </dev/null > "$F-apt-sim.txt" 2>&1
    echo "__EXIT__=$?" >> "$F-apt-sim.txt"
    lxc exec "$VM" -- sh -c "timeout 300 pro fix $usn --dry-run" </dev/null > "$F-profix-online.txt" 2>&1
    echo "__EXIT__=$?" >> "$F-profix-online.txt"
    if [ -n "$nic" ]; then
      lxc exec "$VM" -- ip link set "$nic" down </dev/null
      lxc exec "$VM" -- sh -c "timeout 300 pro fix $usn --dry-run" </dev/null > "$F-profix-offline.txt" 2>&1
      echo "__EXIT__=$?" >> "$F-profix-offline.txt"
    fi
    # 斷網後不硬把網路接回來，直接還原快照，保證乾淨
    restore "$VM"
    lxc exec "$VM" -- sh -c "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a; apt-get install -y --only-upgrade $APT_OPTS $bins" </dev/null > "$F-apt-real.txt" 2>&1
    echo "__EXIT__=$?" >> "$F-apt-real.txt"
    lxc exec "$VM" -- sh -c 'dpkg-query -W -f "\${Package}\t\${Version}\t\${Source}\n"' </dev/null > "$F-dpkg-after.txt" 2>&1
    lxc exec "$VM" -- sh -c "timeout 300 pro fix $usn --dry-run" </dev/null > "$F-profix-after.txt" 2>&1
    echo "__EXIT__=$?" >> "$F-profix-after.txt"
  done 3< "$L/fixes.tsv"
  if restore "$VM"; then after_upgrade; else log "[$V] 還原快照失敗，略過更新後的報告"; fi
done

# 三台合成一份多主機報告：更新前、更新後各一份
combine() {  # $1＝report 或 report-after，$2＝輸出資料夾名稱，$3＝報告表頭的執行單位
  local files=()
  for f in "$OUT"/logs/*/"$1"/collected/hc-*.tar.gz; do [ -f "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || { log "沒有 $1 的收集檔，略過 $2"; return 0; }
  python3 hc report "${files[@]}" --data "$OUT/data" --engine builtin --update no \
    --agency "LXD 測試機（虛構）" --assessor "$3" --out "$OUT/$2" </dev/null > "$OUT/logs/$2.log" 2>&1 \
    && log "合成報告：$(ls "$OUT/$2"/report-*.html 2>/dev/null | head -1)" || log "合成 $2 失敗，見 $OUT/logs/$2.log"
}
combine report combined-before "更新前"
[ "$AFTER" = 1 ] && combine report-after combined-after "更新後（apt upgrade 之後）"

# 整理結果
python3 - "$OUT" "${VERSIONS[@]}" > "$OUT/RESULTS.md" <<'PY'
import json, os, re, sys
out, vers = sys.argv[1], sys.argv[2:]
def rd(p):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
def ex(t):
    m = re.search(r"__EXIT__=(\d+)", t)
    return m.group(1) if m else "-"
def brief(t, n=140):
    t = re.sub(r"__EXIT__=\d+", "", t).strip().replace("\n", " ／ ").replace("|", "／")
    return t[-n:] if t else "（沒有輸出）"
def cell(t):
    return (ex(t) + "：" + brief(t)) if t else "未測"
def dpkg(t):
    r = {}
    for l in t.splitlines():
        p = l.split("\t")
        if len(p) >= 2 and p[0]:
            r[p[0]] = p[1]
    return r
def tsv(p):
    return [l.split("\t") for l in rd(p).splitlines() if l.strip()]

print("# lxd-fixcheck 結果\n")
print("每則公告都從同一個快照開始測，彼此不影響。「多出的」指報告沒列、但 apt 實際動到的套件。")
print("真的升級用報告上的指令，只多加等 apt 鎖與保留舊設定檔的選項，沒有加 --no-remove，所以「移除」也會照實記下。")
print("pro fix 都接 /dev/null、限時 300 秒；結束碼 124 表示逾時，沒訂閱時若遇到互動提問會直接以錯誤結束。\n")
for v in vers:
    L = os.path.join(out, "logs", v)
    print("## %s\n" % v)
    print("```\n%s\n```\n" % (rd(os.path.join(L, "pro-info.txt")).strip() or "（沒有 pro 用戶端資訊，測試機可能沒建起來，見 logs/%s/）" % v))

    # 降版情形，以及每包原始碼在報告裡有幾則重大／高風險公告
    down = tsv(os.path.join(L, "downgrade.tsv"))
    status = dict((r[0], r[1]) for r in tsv(os.path.join(L, "downgrade-status.tsv")) if len(r) >= 2)
    try:
        fj = json.load(open(os.path.join(L, "findings.json"), encoding="utf-8"))
    except Exception:
        fj = {}
    per_src = {}
    for h in fj.get("hosts", []):
        for f in h.get("crit_high_fixes", []):
            if f.get("kernel"):
                continue
            for s in f.get("packages", []):
                per_src.setdefault(s, []).append(f.get("usn", ""))
    fx = tsv(os.path.join(L, "fixes.tsv"))
    tested = {}
    for r in fx:
        if len(r) >= 2:
            for s in r[1].split(","):
                tested[s] = r[0]
    srcs = sorted(set(r[0] for r in down if r))
    if srcs:
        print("| 原始碼套件 | 降版的套件數 | 降版結果 | 報告的重大／高風險公告 | 本次測試 |")
        print("|---|---|---|---|---|")
        for s in srcs:
            n = sum(1 for r in down if r and r[0] == s)
            res = {"ok": "成功", "fail": "失敗"}.get(status.get(s, ""), "未知（見 downgrade.log）")
            print("| %s | %d | %s | %d 則 | %s |" % (s, n, res, len(per_src.get(s, [])), tested.get(s, "—")))
        print()
    else:
        print("沒有降版任何套件（見 logs/%s/downgrade.log）\n" % v)

    if not fx:
        print("沒有可測的公告（見 logs/%s/hc-local.log）\n" % v)
        continue
    before = dpkg(rd(os.path.join(L, "dpkg-before.txt")))
    rows1, rows2 = [], []
    for r in fx:
        if len(r) < 4:
            continue
        usn, src, bins, kind = r[:4]
        F = os.path.join(L, usn)
        want = set(bins.split())
        sim = rd(F + "-apt-sim.txt")
        inst = sorted(set(re.findall(r"^Inst (\S+)", sim, re.M)))
        remv = sorted(set(re.findall(r"^Remv (\S+)", sim, re.M)))
        extra = sorted(set(inst) - want) + ["移除 " + x for x in remv]
        if sim:
            rows1.append("| %s | %s（%s） | %s | %s | %s | 結束碼 %s |" % (
                usn, src, kind, bins, " ".join(inst) or "（無）", " ".join(extra) or "無", ex(sim)))
        else:
            rows1.append("| %s | %s（%s） | %s | 未測 | 未測 | 未測 |" % (usn, src, kind, bins))
        real = rd(F + "-apt-real.txt")
        after = dpkg(rd(F + "-dpkg-after.txt"))
        if after:
            changed = sorted(p for p in after if p in before and after[p] != before[p])
            new = sorted(p for p in after if p not in before)
            gone = sorted(p for p in before if p not in after)
            more = sorted(set(changed) - want) + ["新裝 " + x for x in new] + ["移除 " + x for x in gone]
            ch, mo = " ".join(changed) or "（無）", " ".join(more) or "無"
        else:
            ch = mo = "未測"
        rows2.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            usn, ex(real) if real else "未測", ch, mo,
            cell(rd(F + "-profix-online.txt")), cell(rd(F + "-profix-offline.txt")), cell(rd(F + "-profix-after.txt"))))
    print("**apt 模擬執行（`apt-get -s install --only-upgrade`）**\n")
    print("| 公告 | 原始碼（費用） | 報告列的套件 | 模擬會升級 | 多出的 | 模擬結果 |")
    print("|---|---|---|---|---|---|")
    print("\n".join(rows1) + "\n")
    print("**真的升級與 pro fix（`--dry-run`，結束碼：最後幾行輸出）**\n")
    print("| 公告 | 真的升級結束碼 | 實際變動的套件 | 多出的 | pro fix 連網 | pro fix 斷網 | 升級後 pro fix |")
    print("|---|---|---|---|---|---|---|")
    print("\n".join(rows2) + "\n")
PY
log "完成：$OUT/RESULTS.md"
[ "$AFTER" = 1 ] && echo "更新後的報告若還留幾則免費修補：22.04 以後的 apt 會分階段推送（phased updates），apt upgrade 暫緩少數套件屬正常。"
echo "測試機保留著（做過全面更新的停在更新後狀態，快照 $SNAP 是更新前），可以進去看：lxc exec ${PREFIX}2404 -- bash；不用了就執行 tests/lxd-fixcheck.sh --cleanup"
