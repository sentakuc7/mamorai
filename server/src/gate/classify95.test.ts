import { describe, it, expect } from "vitest";
import { mustAskOps } from "./classify.js";

describe("EDR-94 operations that always need a human", () => {
  const cases: [string, string][] = [
    ["sudo dnf config-manager --add-repo https://rpms.remirepo.net/x.repo", "外部リポジトリの追加"],
    ["sudo dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm", "外部リポジトリの追加"],
    ["sudo dnf install -y epel-release", "外部リポジトリの追加"],
    ["curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -", "外部リポジトリの追加"],
    ["sudo dnf upgrade --releasever=2023.12.20261021 -y", "OS 全体のアップグレード"],
    ["sudo dnf update -y", "OS 全体のアップグレード"],
    ["sudo apt-get -y dist-upgrade", "OS 全体のアップグレード"],
    ["sudo rpm -e --nodeps php8.3-common", "パッケージの削除"],
    ["sudo dnf remove -y php8.3*", "パッケージの削除"],
    ["sudo pkill -9 dnf", "処理の強制終了"],
    ["kill -9 1234", "処理の強制終了"],
    ["cd /var/tmp/php-build/php-8.3.15 && sudo make install", "ソースからのビルド・システムのプログラム差し替え"],
    ["./configure --prefix=/usr/local/php", "ソースからのビルド・システムのプログラム差し替え"],
    ["sudo ln -sf /usr/local/php-8.3.15/bin/php /usr/bin/php", "ソースからのビルド・システムのプログラム差し替え"],
    ["sudo iptables -P INPUT DROP", "ファイアウォールの方針変更"],
    ["sudo reboot", "再起動・停止"],
  ];
  it.each(cases)("%s → %s", (cmd, label) => expect(mustAskOps([cmd])).toContain(label));
  it.each([
    "sudo dnf update -y php8.3 php8.3-fpm",
    "sudo dnf check-update php8.3",
    "sudo systemctl restart php-fpm",
    "sudo sed -i 's/a/b/' /etc/php.ini",
    "sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak",
    "rm -rf /var/tmp/php-build",
    "ps aux | grep -E 'make|configure' | grep -v grep",
    "sudo /var/ossec/bin/wazuh-analysisd -t",
  ])("not a must-ask: %s", (cmd) => expect(mustAskOps([cmd])).toEqual([]));
});
