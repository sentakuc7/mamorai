MamorAI エージェントパック（Windows）
=====================================

このフォルダは MamorAI の「ホスト管理 › エージェントパック」から作られたものです。
版（rN）と中身は pack.json、全ファイルのハッシュは SHA256SUMS.txt にあります。
MamorAI の設定（manager のアドレス・グループ・Sysmon など）や Windows 用アドオンが
変わると、MamorAI 側で自動的に新しい版になります。配る前に最新の版を DL してください。

■ 1 台ずつ入れる（新規・更新どちらも同じ）

  0. zip は暗号化されています。展開するときに、MamorAI の DL 画面に出たパスワードを入れてください
     （エクスプローラーの「すべて展開」でそのまま開けます）
  1. フォルダごと対象の PC にコピーする（USB・共有フォルダなど）
  2. Install-EdrAgent.bat をダブルクリック → 管理者の確認で「はい」
  3. 画面の質問に答える
       - まだ Wazuh エージェントが無い PC  → 新規インストール
       - すでに入っている PC              → [1] 更新 / [2] アドオンだけ を選ぶ
       - 新規のとき: ノート PC（社外に持ち出す）かデスクトップ（LAN だけ）か
       - 登録パスワード（パックに入っていない場合だけ聞かれます）
  4. 「All done」と出れば完了。ログ: C:\ProgramData\MamorAI\agent-install.log
  5. 終わると、展開したフォルダと「ダウンロード」にある zip は自動で消えます
     （Tailscale のキー・登録パスワードが入っているため。残したいときは -KeepFiles）

  アドオンだけ入れたい / 更新したいときは Install-AddonOnly.bat。

■ まとめて配る（GPO が使えない環境でも可）

  共有フォルダに置いて、各 PC で管理者として次を実行します（質問なし・終了コードで判定）。

    powershell -NoProfile -ExecutionPolicy Bypass -File \\server\share\MamorAI-Agent-Windows-rN\Install-EdrAgent.ps1 -Mode update -Unattended

  新規の PC にも無人で入れる場合:

    ... Install-EdrAgent.ps1 -Mode install -DeviceType desktop -RegistrationPassword <登録パスワード> -Unattended

  共有フォルダ（\\server\share）から実行した場合は、ほかの PC でも使うので消しません。
  共有フォルダは読める人を絞り、配り終わったら消してください。

  -Mode   : auto（既定。新規なら install、入っていれば update） / install / update / addon
  終了コード: 0 = 完了、1 = 失敗、2 = 中止
  タスクスケジューラ（SYSTEM で実行）や PDQ・Intune の「スクリプト」からも同じ形で呼べます。

■ 何をするか

  1. パックの改ざん確認（SHA256SUMS.txt と照合）
  2. Tailscale（ノート PC、かつパックに Tailscale のアドレスがある場合だけ）
  3. Wazuh エージェント
       新規: 登録して接続。更新: パックより古ければ上げる（登録はそのまま）
       manager のアドレスの並び（ossec.conf の <server>）をパックに合わせる
  4. Sysmon（パックで有効な場合）と設定ファイルの更新
  5. MamorAI アドオン（MamorAI のホスト画面から、サービス停止・ポート / IP 遮断・隔離をするためのもの）
       署名とハッシュを確認してから置きます
  6. 入れたパックの版を C:\ProgramData\MamorAI\pack.json に記録
     （MamorAI の「アドオンの版を確認」で、ホストごとのパックの版が表示されます）

  インストーラーと Sysmon は、正しい発行元の署名（Wazuh / Microsoft / Tailscale）があるものだけ実行します。

■ 秘密情報について

  MamorAI に登録してある Tailscale の認証キーと Wazuh の登録パスワードが、自動で config.json に入っています。
  そのため zip は暗号化してあり、インストールが終わると展開したデータは自動で消えます。
  - zip やパスワードを、メールやチャットで外部に送らないでください
  - 漏れたと思ったら、MamorAI の「設定 › エージェントパック › 秘密情報」でキーを入れ替えてください
    （Tailscale の管理画面で古いキーを無効にし、Wazuh の登録パスワードも変えます）
