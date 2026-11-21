#!/usr/bin/env python3
"""產生示範用的「虛構」收集結果，供教學示範與分析程式測試。

注意：主機與設定全部是虛構的，不是任何真實單位的主機。
套件版本號採用各版本發行時或早期更新的版本號，目的是讓官方 OVAL 比對有結果可以示範；
Ubuntu Pro 用戶端的更新清單（pro-api-updates.json）是虛構的對照資料。
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def updates(items):
    s = {"num_updates": len(items),
         "num_esm_infra_updates": sum(1 for i in items if i[2] == "esm-infra"),
         "num_esm_apps_updates": sum(1 for i in items if i[2] == "esm-apps"),
         "num_standard_security_updates": sum(1 for i in items if i[2] == "standard-security"),
         "num_standard_updates": 0}
    ups = [{"package": p, "version": v, "provided_by": pb, "status": st,
            "origin": "esm.ubuntu.com" if pb.startswith("esm") else "archive.ubuntu.com",
            "download_size": 100000} for p, v, pb, st in items]
    return json.dumps({"_schema_version": "v1", "result": "success", "errors": [], "warnings": [],
                       "data": {"type": "PackageUpdates", "meta": {"environment_vars": []},
                                "attributes": {"summary": s, "updates": ups}}}, indent=1)


def summary(third):
    return json.dumps({"_schema_version": "v1", "result": "success",
                       "data": {"attributes": {"summary": {"num_installed_packages": 600,
                                "num_third_party_packages": third, "num_unknown_packages": 0}}}})


HOSTS = {
    "demo-ap01": {  # 20.04，標準維護已結束
        "os": 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n',
        "uname": "Linux demo-ap01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux",
        "uptime": "17280000.00 30000000.00",  # 200 天
        "kernels": ["5.4.0-150-generic", "5.4.0-169-generic"],
        "pkgs": [("bash", "5.0-6ubuntu1", "bash"), ("openssl", "1.1.1f-1ubuntu2", "openssl"),
                 ("libssl1.1", "1.1.1f-1ubuntu2", "openssl"), ("sudo", "1.8.31-1ubuntu1", "sudo"),
                 ("nginx-core", "1.18.0-0ubuntu1", "nginx"), ("nginx", "1.18.0-0ubuntu1", "nginx"),
                 ("imagemagick", "8:6.9.10.23+dfsg-2.1ubuntu11", "imagemagick")],
        "updates": [("openssl", "1.1.1f-1ubuntu2.24+esm1", "esm-infra", "pending_attach"),
                    ("libssl1.1", "1.1.1f-1ubuntu2.24+esm1", "esm-infra", "pending_attach"),
                    ("sudo", "1.8.31-1ubuntu1.5+esm1", "esm-infra", "pending_attach"),
                    ("nginx", "1.18.0-0ubuntu1.4+esm1", "esm-apps", "pending_attach"),
                    ("imagemagick", "8:6.9.10.23+dfsg-2.1ubuntu11.9+esm1", "esm-apps", "pending_attach")],
        "sshd": "permitrootlogin yes\npasswordauthentication yes\n",
        "ufw": "Status: inactive", "third": 3, "root": True,
    },
    "demo-db01": {  # 16.04，ESM 也已結束
        "os": 'NAME="Ubuntu"\nVERSION="16.04.7 LTS (Xenial Xerus)"\nVERSION_ID="16.04"\nPRETTY_NAME="Ubuntu 16.04.7 LTS"\n',
        "uname": "Linux demo-db01 4.4.0-210-generic #242-Ubuntu SMP x86_64 GNU/Linux",
        "uptime": "41472000.00 80000000.00",  # 480 天
        "kernels": ["4.4.0-210-generic"],
        "pkgs": [("bash", "4.3-14ubuntu1", "bash"), ("libc6", "2.23-0ubuntu3", "glibc"),
                 ("openssh-server", "1:7.2p2-4ubuntu2.8", "openssh"), ("sudo", "1.8.16-0ubuntu1", "sudo")],
        "updates": [("libc6", "2.23-0ubuntu11.3+esm5", "esm-infra", "pending_attach"),
                    ("openssh-server", "1:7.2p2-4ubuntu2.10+esm6", "esm-infra", "pending_attach")],
        "sshd": "permitrootlogin prohibit-password\npasswordauthentication yes\n",
        "ufw": "Status: active", "third": 0, "root": True,
    },
    "demo-web01": {  # 22.04，標準維護期內
        "os": 'NAME="Ubuntu"\nVERSION="22.04.5 LTS (Jammy Jellyfish)"\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.5 LTS"\n',
        "uname": "Linux demo-web01 5.15.0-125-generic #135-Ubuntu SMP x86_64 GNU/Linux",
        "uptime": "2592000.00 5000000.00",  # 30 天
        "kernels": ["5.15.0-125-generic", "5.15.0-130-generic"],
        "pkgs": [("bash", "5.1-6ubuntu1", "bash"), ("curl", "7.81.0-1ubuntu1.10", "curl"),
                 ("libcurl4", "7.81.0-1ubuntu1.10", "curl"), ("redis-server", "5:6.0.16-1ubuntu1", "redis"),
                 ("openssl", "3.0.2-0ubuntu1.10", "openssl")],
        "updates": [("curl", "7.81.0-1ubuntu1.20", "standard-security", "upgrade_available"),
                    ("libcurl4", "7.81.0-1ubuntu1.20", "standard-security", "upgrade_available"),
                    ("redis-server", "5:6.0.16-1ubuntu1+esm1", "esm-apps", "pending_attach")],
        "sshd": "permitrootlogin no\npasswordauthentication no\n",
        "ufw": "Status: active", "third": 12, "root": False,
    },
}

for tag, h in HOSTS.items():
    d = os.path.join(HERE, tag)
    os.makedirs(d, exist_ok=True)
    w = lambda n, t: open(os.path.join(d, n), "w").write(t + "\n__EXIT__=0\n")
    open(os.path.join(d, "meta.txt"), "w").write(
        "collector_version=0.5\ncollected_at=2026-11-16T02:00:00Z\ntag=%s\nuid=%s\n" % (tag, "0" if h["root"] else "1000"))
    w("os-release.txt", h["os"])
    w("kernel-release.txt", h["uname"].split()[2])
    w("uname.txt", "Linux %s x86_64" % h["uname"].split()[2])
    w("uptime.txt", h["uptime"])
    lines = ["%s\t%s\tinstall ok installed\t%s\tamd64" % p for p in h["pkgs"]]
    # 核心套件版本格式為「ABI.上傳序號」，例如 5.4.0-150.167；序號為虛構
    lines += ["linux-image-%s\t%s.%d\tinstall ok installed\tlinux-signed\tamd64"
              % (k, k.rsplit("-", 1)[0], int(k.split("-")[1]) + 10) for k in h["kernels"]]
    w("dpkg.txt", "\n".join(lines))
    w("pro-status.json", json.dumps({"attached": False, "services": [
        {"name": "esm-infra", "status": "n/a"}, {"name": "livepatch", "status": "n/a"}]}))
    w("pro-api-updates.json", updates(h["updates"]))
    w("pro-api-summary.json", summary(h["third"]))
    if h["root"]:
        w("sshd.txt", h["sshd"])
        open(os.path.join(d, "shadow-summary.txt"), "w").write("empty_password_accounts=0\n")
        w("ufw.txt", h["ufw"])  # 防火牆狀態需要 sudo 才收得到
    w("uid0.txt", "uid0_accounts=1")
    w("unattended-upgrades.txt", 'APT::Periodic::Update-Package-Lists "1";')
print("已產生示範資料：", ", ".join(HOSTS))
