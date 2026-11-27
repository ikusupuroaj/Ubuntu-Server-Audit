# Ubuntu-Server-Audit

An offline security health check for Ubuntu hosts.

It tells you whether each host's release is still maintained, which security fixes are missing, and which of those gaps an Ubuntu Pro subscription would close. Matching uses **Canonical's official OVAL data**. Nothing is installed on the hosts being checked. Reports and the user guide ([docs/user-guide.pdf](docs/user-guide.pdf)) are written in Traditional Chinese.

> This is not an official Canonical tool. It is not affiliated with or endorsed by Canonical. Ubuntu is a trademark of Canonical Ltd.

## Workflow

1. Download the tool to an analysis machine (Ubuntu or macOS; Windows is untested; Python 3.6+ with no extra packages).
2. Scan your hosts with one command; results are matched against Canonical's official data.
3. Open the HTML report in a browser.
4. (Optional) Send the de-identified result to a health-check consultant through the questionnaire page.
5. Receive a management report that ranks the work by each host's role.

Run every command in a terminal, inside the `Ubuntu-Server-Audit` folder. `./hc -h` shows help and `./hc --version` shows the version.

## Quick start

```bash
git clone https://github.com/ikusupuroaj/Ubuntu-Server-Audit.git
cd Ubuntu-Server-Audit
```

A plain `git clone` also fetches the `data` branch, which GitHub Actions refreshes daily from Canonical. `hc` copies it into `data/` on first run, so the tool works offline right away. Without git, download `Ubuntu-Server-Audit-full.zip` from the `data-latest` release (GitHub's "Download ZIP" and `git clone --depth 1` do not include the data).

Run `./hc` with no arguments for a guided menu (Traditional Chinese): check this machine, scan hosts over SSH (the menu builds `inventory.txt` for you and can test SSH logins and install your key), analyse returned collector files, update or verify the official data. The commands below do the same things directly.

| Situation | Command |
|---|---|
| Check this machine only (Ubuntu) | `./hc local` |
| This machine can SSH to the hosts | `cp inventory.example.txt inventory.txt`, edit it, then `./hc scan` (an older `hosts.txt` still works: `./hc scan hosts.txt`) |
| Host owners run the collector themselves | on the host: `sudo bash collect.sh --tag H01`; then `./hc report hc-H01-*.tar.gz` |

`./hc scan` pipes the collector over SSH and streams the result back, so the collector and its output are never written on the host (the Ubuntu Pro client and sudo still write their own logs). `hc local` and `hc scan` collect with sudo by default, which covers three extra checks (SSH config, ufw, empty passwords); add `--no-sudo` to skip sudo, and those three are listed as not checked. `hc local` tries sudo first (asking for your password) and falls back to a normal user if sudo is unavailable or skipped with Ctrl+C; `hc scan` needs passwordless sudo on the hosts and otherwise falls back to a normal user. A collector file made with `sudo bash collect.sh` is handed back to the account that ran sudo, so it can be copied without changing permissions.

Open `report-<timestamp>.html` in a browser for the full report. Each run writes to `reports/<timestamp>/`: the report, `findings-ai-<timestamp>.json` (de-identified results, only needed if you use the consultant service), `oval-detail.json` (full matching details) and, for `local` and `scan`, `collected/` (raw data from the hosts, including package lists; do not send it out). With `report`, the `hc-*.tar.gz` bundles you copied in hold the same raw data. Keep the report and `collected/` according to your organization's data rules.

## OVAL data

| Task | Command |
|---|---|
| Show data dates | `./hc update --list` |
| Update from Canonical (recommended) | `./hc update` |
| Canonical unreachable, GitHub reachable | `git pull` or `./hc update --from github` |
| Check files after moving them offline | `./hc update --verify` |

## How it decides "needs Ubuntu Pro"

It reads the fix pocket named in the official OVAL criteria (`esm-infra`, `esm-apps`, `esm-infra-legacy`). It does not guess from version strings. Matching uses OpenSCAP (`oscap`) when available, otherwise a built-in evaluator of the same definitions. `--engine both` runs both and lists any differences.

## More

- `docs/user-guide.pdf`: step-by-step user guide, including how to read the report
- `docs/upload/`: a questionnaire page (served by GitHub Pages) for sending `findings-ai-<timestamp>.json` with a short host-context questionnaire to the consultant. The file is read in the browser; host tags are H01, H02… and the mapping stays in the local report only. If you choose to download the answers file instead of uploading, it already contains the results, so email that single file. Check your organization's rules before sending results outside. Data sent to the consultant is deleted 90 days after the case is closed (the case is closed once the consultant has emailed the report and confirmed you received it).
- `tests/lxd-quicktest.sh`: one-command test across Ubuntu releases in LXD VMs
- `rules/default-rules.json`: categories, advice texts and thresholds; override with `--rules`
- Critical and high advisories show an attack vector and the highest CVSS score, taken from the CVSS vectors in Canonical's OVAL data (CVSS 3.x and 4.0 mixed). It shows how an issue could be reached, not that it has been confirmed exploitable.

## Relation to sec-cvescan

The approach (export a package manifest, scan it elsewhere offline) follows Canonical's [sec-cvescan](https://github.com/canonical/sec-cvescan). That project is deprecated and its data feed is no longer updated. This tool uses the maintained official OVAL feed instead. No sec-cvescan code is used.

## License

The code is licensed under the Apache License 2.0. The OVAL data is © Canonical Ltd. and licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The `data` branch and the release archives redistribute the official files unmodified; `SOURCES.json` records where and when each file was downloaded.
