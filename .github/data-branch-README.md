# offline-ubuntu-healthcheck 官方弱點資料（data 分支）

這個分支由 GitHub Actions 每天自動更新，只保留最新一份，不累積歷史。

- 內容：Canonical 官方的 OVAL 弱點資料（套件清單版，檔名 `oci.com.ubuntu.<代號>.usn.oval.xml.bz2`），從 https://security-metadata.canonical.com/oval/ 下載，**檔案未經修改**。
- `SOURCES.json`：每個檔案的官方網址、官方產生時間、下載時間與 SHA-256。
- `SHA256SUMS`：可用 `sha256sum -c SHA256SUMS` 核對。

用 `git clone` 下載本專案時，這個分支會一起下載下來，`hc` 第一次執行時會自動放進 `data/`，不需要網路。之後執行 `git pull` 就會帶回最新的一份。

## 授權

OVAL 資料的著作權屬於 Canonical Ltd.，授權為 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)。本專案只是原樣轉存，方便離線環境取得；最新與正式的來源仍是 Canonical 官方網站。

本專案不是 Canonical 的官方工具，與 Canonical 沒有隸屬關係。Ubuntu 是 Canonical Ltd. 的商標。
