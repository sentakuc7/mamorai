import { describe, it, expect } from "vitest";
import { forbiddenOps, isLongStep } from "./classify.js";

describe("EDR-113 operations MamorAI never runs", () => {
  const always: [string, string][] = [
    ["sudo pkill -9 dnf", "パッケージ管理の処理を強制終了"],
    ["pkill -f dnf", "パッケージ管理の処理を強制終了"],
    ["sudo killall yum", "パッケージ管理の処理を強制終了"],
    ["sudo kill -9 $(pgrep -f dnf)", "パッケージ管理の処理を強制終了"],
    ["pgrep dnf | xargs sudo kill -9", "パッケージ管理の処理を強制終了"],
    ["sudo pkill -9 apt-get", "パッケージ管理の処理を強制終了"],
    ["sudo rm -f /var/lib/rpm/.rpm.lock", "パッケージ管理のロック削除"],
    ["sudo rm /var/lib/dpkg/lock-frontend", "パッケージ管理のロック削除"],
    ["rm -f /var/lib/apt/lists/lock", "パッケージ管理のロック削除"],
  ];
  it.each(always)("%s → %s (lab too)", (cmd, label) => expect(forbiddenOps([cmd], "lab")).toContain(label));
  const prod: string[] = [
    "cd /var/tmp/php-build/php-8.3.15 && make -j2 2>&1 | tail -20",
    "cd /var/tmp/php-build/php-8.3.15 && sudo make install",
    "./configure --prefix=/usr/local/php-8.3.15 --enable-fpm",
    "sudo dnf install -y gcc make autoconf bison re2c libxml2-devel",
    "sudo dnf groupinstall -y 'Development Tools'",
    "sudo apt-get install -y build-essential",
  ];
  it.each(prod)("%s → source build blocked on production", (cmd) => expect(forbiddenOps([cmd], "production")).toContain("本番ホストでのソースビルド"));
  it.each(prod)("%s → allowed (with approval) on lab", (cmd) => expect(forbiddenOps([cmd], "lab")).not.toContain("本番ホストでのソースビルド"));
  it.each([
    "ps aux | grep -E 'make|dnf' | grep -v grep",
    "sudo dnf upgrade --releasever=2023.12.20261021 -y",
    "sudo dnf install -y php8.3-fpm",
    "sudo kill -9 2359555",
    "pkill -f php-build",
    "sudo systemctl restart php-fpm",
    "rm -rf /var/tmp/php-build",
    "sudo dnf -q check",
    "rpm -e --justdb --nodeps --noscripts curl-minimal-8.21.0-5.amzn2023.0.1.x86_64",
  ])("%s → not forbidden", (cmd) => expect(forbiddenOps([cmd], "production")).toEqual([]));
});

describe("EDR-114 long steps", () => {
  it.each([
    "sudo dnf upgrade --releasever=2023.12.20261021 -y",
    "sudo dnf update -y php8.3 php8.3-fpm",
    "dnf -y install php8.3",
    "sudo dnf reinstall -y php8.3-common",
    "sudo dnf history undo 14 -y",
    "sudo apt-get install --only-upgrade -y php8.2",
    "DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade",
  ])("%s → long", (cmd) => expect(isLongStep(cmd)).toBe(true));
  it.each([
    "dnf check-update php8.3",
    "dnf -q repoquery php8.3",
    "rpm -q php8.3",
    "sudo systemctl restart httpd",
    "apt-cache policy php8.2",
    "dnf check-release-update",
  ])("%s → not long", (cmd) => expect(isLongStep(cmd)).toBe(false));
});
