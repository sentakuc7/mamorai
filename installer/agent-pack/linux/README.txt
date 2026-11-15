MamorAI エージェントパック（Linux）
===================================

このフォルダは MamorAI の「ホスト管理 › エージェントパック」で作ったものです。
パックの版（rN）と中身は pack.json に、全ファイルのハッシュは SHA256SUMS.txt に書いてあります。
MamorAI 側の設定（manager のアドレス、グループ、Tailscale、auditd、SSH）が変わると、
MamorAI が自動で新しい版を作ります。配る前に、最新の版を DL し直してください。

対応 OS: Debian / Ubuntu（apt）、RHEL / CentOS / Rocky / Alma / Fedora / Amazon Linux（dnf / yum）

■ 1 台ずつ入れる（新規でも更新でも同じ手順）

    scp MamorAI-Agent-Linux-rN.zip user@server:~/
    ssh user@server
    unzip MamorAI-Agent-Linux-rN.zip        # パスワードは MamorAI の DL 画面に出たもの
    cd MamorAI-Agent-Linux-rN
    sudo ./install-edr-agent-linux.sh            # 先に --dry-run で確認だけすることもできます

  - Wazuh エージェントが入っていない → 新規インストールをするか聞かれます
  - すでに入っている → このパックで更新するか聞かれます
    （更新すると、設定・auditd が新しくなり、エージェントがパックより古ければ版を上げます。登録は消えません）
  - 登録パスワードがパックに入っていないときは、新規インストールの途中で入力を求められます
  - ログ: /var/log/mamorai-agent-install.log
  - 終わると、展開したフォルダと同じ場所の zip は自動で消えます（秘密情報が入っているため。残すなら --keep-files）

■ まとめて配る（質問なし）

    sudo ./install-edr-agent-linux.sh --mode update --yes
    sudo ./install-edr-agent-linux.sh --mode install --password '<登録パスワード>' --yes

  Ansible・cron・SSH のループなどから、そのまま呼べます。
  終了コード: 0 = 完了、1 = 失敗、2 = 中止

■ 何をするか

  1. パックが改ざんされていないか確認する（sha256sum -c SHA256SUMS.txt）
  2. Tailscale を入れる（パックで有効にしている場合だけ）
  3. Wazuh エージェントを入れる。パックで決めた版に固定し、自動更新を止める
     manager のアドレス（ossec.conf の <server>）を、パックに書いた順に並べ直す
  4. auditd を入れる。ログインユーザーが実行したコマンドを記録し、MamorAI のプロセスツリーに使う
  5. docker-listener を有効にする（Docker が動いているときだけ）
  6. MamorAI 用の SSH を設定する（選んだ場合だけ。既定は「いいえ」）
       - 専用ユーザー mamorai を作る（パスワードでは入れない）
       - authorized_keys に MamorAI の公開鍵を入れる。MamorAI のアドレスからだけ使える
       - sudo を付ける（設定で "none" にすると sudo なし。その場合は読み取りのスキャンだけできる）
       - 設定し終えたら、MamorAI のホスト画面でこのサーバーを開き、
         「パックで準備した SSH を使う」を押す
       - 取り消すとき: userdel -r mamorai; rm -f /etc/sudoers.d/90-mamorai
  7. 入れたパックの版を /etc/mamorai/pack.json に書く
     MamorAI は SSH でスキャンするときにこれを読み、ホストごとのパックの版として表示する

■ 秘密情報について

  MamorAI に登録してある Tailscale の認証キーと Wazuh の登録パスワードが、自動で config.json に入っています。
  そのため zip は暗号化してあり、インストールが終わると展開したデータは自動で消えます。
  漏れたと思ったら、MamorAI の「設定 › エージェントパック › 秘密情報」でキーを入れ替えてください。
