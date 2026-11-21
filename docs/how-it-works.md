# 比對原理與資料來源

## 官方資料

Canonical 的安全團隊為每個仍在支援的 Ubuntu 版本，發布機器可讀的弱點資料：OVAL、OSV、VEX。說明見 <https://documentation.ubuntu.com/security/security-updates/>。

本工具使用 OVAL 的「套件清單版」：

- 網址：`https://security-metadata.canonical.com/oval/oci.com.ubuntu.<代號>.usn.oval.xml.bz2`
- 內容：每則 Ubuntu 安全公告（USN）一筆定義，寫明受影響的套件、修補版本、CVE 編號、嚴重度。
- 原本用途：Canonical 用它來掃描雲端映像的套件清單（manifest），說明見 <https://documentation.ubuntu.com/security/security-updates/oval/>。

套件清單版和一般版的差別：一般版要在受檢主機上直接讀取已安裝的套件，等於受檢主機上要裝掃描工具。套件清單版只需要一份「套件名稱＋版本」的文字清單，所以可以在別台電腦離線比對。

## 比對怎麼做

1. `collect.sh` 在受檢主機用 `dpkg-query` 列出已安裝套件，內容和 `dpkg-query -W` 的輸出相同。用 `./hc scan` 時，腳本經 SSH 送進主機執行，主機上不留下腳本與收集檔。
2. 分析程式把狀態為「已安裝」的套件整理成 `manifest` 檔，格式為每行「套件名稱、Tab、版本」。
3. 依主機版本挑選對應的 OVAL 檔（例如 20.04 用 focal），逐則檢查：
   - OVAL 用正規表示式在 manifest 裡找出受影響的套件與版本；
   - 已安裝版本低於修補版本（依 Debian 版本比較規則），這則公告就算「尚未修補」。
4. 比對引擎：
   - **OpenSCAP**：在暫存資料夾放 `manifest` 和 OVAL 檔，執行 `oscap oval eval --results`，再讀結果檔。這就是 Canonical 文件示範的方式。
   - **內建比對**：用 Python 照同一份 OVAL 的物件、狀態、測試、條件結構計算。用 `--engine both` 可以和 OpenSCAP 的結果逐則比較。

## 「需不需要 Ubuntu Pro」怎麼判斷

OVAL 的每個比對條件都附有說明，例如：

```
sympa source package in esm-apps/focal, is affected and has been fixed (note: '6.2.40~dfsg-4ubuntu0.20.04.1~esm1').
```

`in` 後面就是修補來源：延伸維護寫成 `esm-apps/focal` 這種形式，一般套件庫只寫版本代號，例如 `python3.10 source package in jammy`。

| 修補來源 | 意思 | 歸類 |
|---|---|---|
| `focal`、`jammy` 等版本代號 | 一般套件庫的免費修補 | 沒套用時列為 D 類 |
| `esm-infra` | 延伸維護（Main 套件），需要 Ubuntu Pro | A 類 |
| `esm-apps` | 延伸維護（Universe 套件），需要 Ubuntu Pro | A 類 |
| `esm-infra-legacy`、`esm-apps-legacy` | Legacy 加購期間的修補 | A 類 |

主機如果已註冊 Ubuntu Pro，而且對應服務已啟用，這些修補改列為 D 類「已訂閱但尚未套用」。

## 主機上的 Ubuntu Pro 用戶端

主機上如果有 `pro` 指令，收集腳本也會記錄 `pro api u.pro.packages.updates.v1` 的結果。分析時的用法：

- 有官方 OVAL 時，以 OVAL 為準，Pro 用戶端的數字只附在說明裡當對照。
- 沒有對應版本的 OVAL 檔時，才改用 Pro 用戶端的數字，報告的「資料來源」欄會標明。

兩者單位不同：OVAL 算的是「安全公告則數」，Pro 用戶端算的是「套件個數」。

## 報告可信度的檢查點

| 檢查點 | 在哪裡看 |
|---|---|
| 用的是哪一天的官方資料 | 掃描開始時的畫面；報告的「官方資料檔明細」（HTML 版在最後的「資料來源」） |
| 資料是否在搬運中被改過 | 同一表格的「與下載紀錄」欄（比對 SHA-256） |
| 用哪個比對引擎 | 報告表頭「比對引擎」 |
| 內建比對與 OpenSCAP 是否一致 | 用 `--engine both` 執行，每台主機下方會列出差異 |
| 哪些項目沒檢查到 | 每台主機的「未能檢查的項目」 |
