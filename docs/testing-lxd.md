# 用 LXD 虛擬機測試

用一台 Ubuntu 電腦（例如 Desktop 26.04）當測試主機，以 LXD 建立各版本的 Ubuntu Server 虛擬機，一個指令跑完所有測試。

## 1. 準備（只要做一次）

```bash
sudo snap install lxd
sudo lxd init --minimal
sudo usermod -aG lxd "$USER"
```

做完**登出再登入**，之後才能不用 sudo 執行 `lxc`。

```bash
sudo apt install -y git openscap-scanner
git clone https://github.com/ikusupuroaj/Ubuntu-Server-Audit.git
cd Ubuntu-Server-Audit
```

`openscap-scanner` 不是必要的，裝了才能做「兩個比對引擎互相對照」。

## 2. 跑測試

在 `Ubuntu-Server-Audit` 資料夾裡執行：

```bash
tests/lxd-quicktest.sh
```

預設只測 20.04 和 24.04。要測其他版本，把版本號列在後面，例如連 22.04、26.04 一起測：

```bash
tests/lxd-quicktest.sh 20.04 22.04 24.04 26.04
```

第一次要下載映像檔、建立虛擬機，每個版本約 3 到 5 分鐘。虛擬機會保留下來，之後重跑快很多。

腳本會自動做這些事：

| 步驟 | 對應的測試項目 |
|---|---|
| 下載並核對官方資料 | T13 |
| 建立虛擬機，裝一個 Universe 套件（nginx） | |
| 用 sudo 收集一次（和客戶實際做法相同，健檢報告一台測試機一列） | T1、T12 |
| 檢查收集時有沒有寫入其他檔案 | T2 |
| 關掉網路再收集一次，記錄花多久 | T3 |
| 檢查收集結果裡有沒有主機名稱與 IP | T7 |
| 兩個比對引擎各算一次，比較結果 | T10、T11 |
| 26.04 的維護狀態（有指定 26.04 時） | T15 |

## 3. 看結果

跑完會在畫面上印出結果表，同一份內容存在 `test-results/<日期時間>/RESULTS.md`，可以直接貼進測試紀錄。

```
test-results/<日期時間>/
├── RESULTS.md          測試結果表
├── report/             健檢報告（report-*.html 用瀏覽器打開）與 findings-ai-*.json，一台測試機一列
├── bundles/            用 sudo 收集到的檔案
└── logs/               每個步驟的紀錄（出問題時看這裡）
```

結果表裡標「人工核對」或「記錄」的項目，需要你看一下內容再判斷。

腳本沒辦法自動做的項目：

- **T8**：打開報告，確認每項發現和主機實際狀況相符。
- **T9**：已註冊 Ubuntu Pro 的主機。請自己在一台虛擬機裡執行 `sudo pro attach`，再重跑腳本。註冊用的 token 請自己輸入，不要寫進任何檔案。
- **T4、T5**：對照 `logs/security-status-<版本>.txt` 與收集檔裡的 `pro-api-updates.json`。

## 4. 清理

```bash
tests/lxd-quicktest.sh --cleanup
```

會刪除腳本建立的所有測試機（名稱開頭是 `hc-t-`），不會動到其他虛擬機。

## 5. 舊版本（14.04、16.04）

較舊的版本在新版 LXD 上常常建不了虛擬機，或是虛擬機開起來之後 LXD 連不進去。遇到這種情況，腳本會標示「略過」，然後繼續測其他版本。

真的要測的話，可以改用容器：

```bash
tests/lxd-quicktest.sh --allow-container 16.04
```

容器跟測試主機共用同一個核心，所以**核心版本、待重開機這些項目的結果不準**，結果表會加上註記。容器裡如果沒有網路或沒有 `ubuntu` 帳號，腳本會標示失敗並說明原因。

## 附錄：手動操作

不用腳本也可以手動測，以下指令都在 `Ubuntu-Server-Audit` 資料夾裡執行。

```bash
mkdir -p runs
lxc launch ubuntu:22.04 t-2204 --vm
lxc exec t-2204 -- cloud-init status --wait
```

收集，不必先把腳本傳進虛擬機：

```bash
lxc exec t-2204 -- su - ubuntu -c 'sudo -n bash -s -- --tag T-2204 --stdout' < collect.sh > runs/hc-T-2204.tar.gz
```

這和工具預設一樣用 sudo 收集。要測一般權限（T6）的話，把 `sudo -n bash -s` 換成 `bash -s`。

分析：

```bash
./hc report runs/hc-T-2204.tar.gz --engine both
```

## 附錄：測試使用者流程（./hc scan）

快速測試腳本不走 SSH。要照使用者手冊測 `./hc scan`，需要先讓測試主機能用 SSH 連進測試機：

1. 測試主機沒有金鑰時，先建一把（問題都按 Enter）：`ssh-keygen -t ed25519`
2. 把公鑰放進測試機：

   ```bash
   lxc exec t-2004 -- su - ubuntu -c 'mkdir -p -m 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys' < ~/.ssh/id_ed25519.pub
   ```

3. 查測試機 IP：`lxc list t-2004 -c n4`。`hosts.txt` 要寫 IP，測試主機查不到 LXD 測試機的名稱。
4. 刪掉測試機再重建時，新測試機可能拿到同一個 IP，SSH 會出現「REMOTE HOST IDENTIFICATION HAS CHANGED」。確定是自己剛建的測試機後，執行 `ssh-keygen -R 測試機IP` 刪掉舊紀錄再連。

## 附錄：驗證「只修這一則」的指令（tests/lxd-fixcheck.sh）

報告的「重大與高風險公告」附了 `sudo pro fix USN-…` 與 `apt install --only-upgrade` 兩行指令。這支腳本用容器驗證這兩行是否照預期運作：

```bash
tests/lxd-fixcheck.sh                    # 預設 20.04、22.04、24.04
tests/lxd-fixcheck.sh 24.04              # 只測一個版本
HC_MAX_FIXES=3 tests/lxd-fixcheck.sh     # 每個版本最多測幾則公告（預設 6；0＝只產生報告）
HC_POOL=default tests/lxd-fixcheck.sh    # 指定儲存池
HC_AFTER_UPGRADE=0 tests/lxd-fixcheck.sh # 不產生「更新後」的報告
HC_DATA=git tests/lxd-fixcheck.sh        # 不向 Canonical 下載，改用 git clone 內附的官方資料
tests/lxd-fixcheck.sh --cleanup          # 刪除測試機（名稱開頭 hc-f-）
```

每個版本會建一台全新的測試機（名稱開頭 `hc-f-` 的舊測試機會先刪掉），關掉自動更新，再把幾包不同類型的套件降回發行版本，製造確定存在的缺口：

| 套件 | 為什麼選它 |
|---|---|
| openssl | 最單純的情況，當基準 |
| curl、vim | 一包原始碼拆成好幾個套件，主機通常只裝其中幾個 |
| sudo | 單一套件，很常見 |
| Python 3 | 套件之間的相依最複雜 |
| libxml2、expat | 很多程式共用的函式庫 |

`libc6`、`systemd`、`apt`、`dpkg` 不降版，降這些容易把測試機弄壞。

接著跑 `./hc local`，每包原始碼挑一則報告列出的重大或高風險公告（不含核心），拍快照後逐則從快照重新開始測：apt 模擬執行實際會升級哪些套件、`pro fix --dry-run` 連網與拔掉網路卡的結果、真的用 `--only-upgrade` 升級後前後實際變動的套件（有沒有多帶相依套件、新裝或移除套件），以及升級後 `pro fix` 是否認定已修好。另外記錄 pro 用戶端版本、`pro fix` 有沒有 `--dry-run`、changelog 裡提到 USN 的版本。結果在 `test-results/fixcheck-<日期時間>/RESULTS.md`，原始輸出在同一層的 `logs/`；每台測試機的整份報告（`report-*.html`、`findings-ai-*.json`、收集檔）在 `logs/<版本>/report/`；報告的交件代號欄可以對回 U2004、U2204、U2404，三個收集檔可以再用 `./hc report` 合成一份多主機報告。每個版本大約要 15 到 30 分鐘（估計值）。沒指定儲存池時，腳本會自動挑 btrfs 或 zfs 的儲存池：這兩種的快照與還原幾乎是瞬間完成，`dir` 則是整份複製，慢很多。都沒有才用 LXD 預設，畫面開頭會印出用了哪個。

官方資料預設向 Canonical 下載，遇到暫時錯誤（例如 HTTP 503）會重試 3 次，仍失敗就改用 git clone 內附的資料（data 分支，不需要網路）；資料不齊才中止。

最後，腳本會照報告的建議全面更新（`apt update`、`apt upgrade`）並重開測試機，再產生一次報告，放在 `logs/<版本>/report-after/`；三台的收集檔也會各合成一份多主機報告：`combined-before/`（更新前）與 `combined-after/`（更新後），可以直接比較更新前後，或拿 findings-ai 檔測試顧問端的分析。全面更新失敗時不會產生更新後的報告。22.04 以後的 apt 會分階段推送（phased updates），更新後報告還留幾則免費修補屬正常。

Landscape 離線（air-gapped）環境不在這支腳本的範圍，斷網只是模擬「連不到 Canonical」。

## 注意

- `lxc console --show-log` 只能用在容器，虛擬機不能用。
- 用 cloud-init 放 SSH 公鑰，對 16.04 的虛擬機沒有效果。
