# offline-ubuntu-healthcheck

An offline security health check for Ubuntu hosts.

It tells you whether each host's release is still maintained, which security fixes are missing, and which of those gaps an Ubuntu Pro subscription would close. Matching uses **Canonical's official OVAL data**. Nothing is installed on the hosts being checked. Reports and the user guide ([docs/user-guide.pdf](docs/user-guide.pdf)) are written in Traditional Chinese.

> This is not an official Canonical tool. It is not affiliated with or endorsed by Canonical. Ubuntu is a trademark of Canonical Ltd.

## Quick start

```bash
git clone https://github.com/ikusupuroaj/Ubuntu-Server-Audit.git
cd Ubuntu-Server-Audit
```

A plain `git clone` also fetches the `data` branch, which GitHub Actions refreshes daily from Canonical. `hc` copies it into `data/` on first run, so the tool works offline right away. Without git, download `Ubuntu-Server-Audit-full.zip` from the `data-latest` release (GitHub's "Download ZIP" and `git clone --depth 1` do not include the data).

| Situation | Command |
|---|---|
| Check this machine only (Ubuntu) | `./hc local --sudo` |
| This machine can SSH to the hosts | `cp hosts.example.txt hosts.txt`, edit it, then `./hc scan hosts.txt --sudo` |
| Host owners run the collector themselves | on the host: `sudo bash collect.sh --tag H01`; then `./hc report hc-H01-*.tar.gz` |

`./hc scan` pipes the collector over SSH and streams the result back, so the collector and its output are never written on the host (the Ubuntu Pro client and sudo still write their own logs). `--sudo` is optional in all three cases. It adds three checks (SSH config, ufw, empty passwords); without it they are listed as not checked. `hc local --sudo` asks for your sudo password; `hc scan --sudo` needs passwordless sudo on the hosts and otherwise falls back to a normal user. A collector file made with `sudo bash collect.sh` is owned by root: run `sudo chown $USER hc-H01-*.tar.gz` before copying it.

Open `report-<timestamp>.html` in a browser for the full report. Each run writes three files to `reports/<timestamp>/`: the report, `findings-ai-<timestamp>.json` (de-identified results to send to your consultant) and `oval-detail.json` (full matching details, keep it yourself).

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
- `docs/upload/`: a questionnaire page (served by GitHub Pages) for sending `findings-ai-<timestamp>.json` with a short host-context questionnaire to the consultant. The file is read in the browser; host tags are H01, H02… and the mapping stays in the local report only.
- `tests/lxd-quicktest.sh`: one-command test across Ubuntu releases in LXD VMs
- `rules/default-rules.json`: categories, advice texts and thresholds; override with `--rules`
- Critical and high advisories show an attack vector and the highest CVSS score, taken from the CVSS vectors in Canonical's OVAL data (CVSS 3.x and 4.0 mixed). It shows how an issue could be reached, not that it has been confirmed exploitable.

## Relation to sec-cvescan

The approach (export a package manifest, scan it elsewhere offline) follows Canonical's [sec-cvescan](https://github.com/canonical/sec-cvescan). That project is deprecated and its data feed is no longer updated. This tool uses the maintained official OVAL feed instead. No sec-cvescan code is used.

## License

The code is licensed under the Apache License 2.0. The OVAL data is © Canonical Ltd. and licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The `data` branch and the release archives redistribute the official files unmodified; `SOURCES.json` records where and when each file was downloaded.
