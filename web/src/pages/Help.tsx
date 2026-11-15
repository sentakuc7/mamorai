/* In-app help pages (EDR-140). /help/:topic */
import { Link, useParams } from "react-router-dom";

const H2 = "mt-2 text-[18px] font-bold text-slate-100";
const P = "text-[14px] leading-[1.9] text-slate-300";
const CARD = "rounded-[14px] border border-slate-700 bg-slate-800 px-5 py-4";
const TD = "border-b border-slate-700 px-3 py-2 align-top text-[13.5px] text-slate-300";
const TH = "border-b border-slate-600 px-3 py-2 text-left text-[12px] font-semibold text-slate-400";

function TailscaleKey() {
  return (
    <>
      <h1 className="m-0 text-[24px] font-bold">Tailscale の認証キーを入れ替える</h1>
      <div className={`${CARD} ${P}`}>
        <b className="text-slate-100">要点</b>: Tailscale の認証キーは最長 90 日で期限が切れます。期限の 14 日前になったら、新しいキーを作り、MamorAI に貼り替えてください。作業は 5 分ほどです。
        <br />すでに tailnet に入っている端末やサーバーは、キーの期限が切れても<b className="text-slate-100">つながったまま</b>です。キーが要るのは、エージェントパックで<b className="text-slate-100">新しく</b>端末を入れるときだけです。
      </div>

      <h2 className={H2}>なぜ必要か</h2>
      <ul className={`${P} list-disc pl-6`}>
        <li>エージェントパックには、MamorAI に登録してある Tailscale の認証キーが自動で入ります。ノート PC や社外のサーバーは、このキーを使って tailnet に参加します。</li>
        <li>認証キーの期限は、Tailscale の仕様で最長 90 日です。無期限にはできません。</li>
        <li>期限が切れたキーで作ったパックを新しい端末に入れると、Tailscale のブラウザ承認が必要になります。人がいないサーバーでは、そこで止まってしまいます。</li>
        <li>MamorAI は期限の 14 日前から、エージェントパックの画面に注意を出します。Wazuh のアラートと Discord にも知らせます。</li>
      </ul>

      <h2 className={H2}>手順</h2>
      <ol className={`${P} list-decimal pl-6`}>
        <li>Tailscale の管理画面で <b className="text-slate-100">Settings › Keys</b> を開きます（<a className="text-teal-300 hover:underline" href="https://login.tailscale.com/admin/settings/keys" target="_blank" rel="noreferrer">login.tailscale.com/admin/settings/keys</a>）。</li>
        <li><b className="text-slate-100">Generate auth key…</b> を押し、次のとおりに設定して <b className="text-slate-100">Generate key</b> を押します。
          <table className="my-2 w-full border-collapse">
            <thead><tr><th className={TH}>項目</th><th className={TH}>設定</th><th className={TH}>理由</th></tr></thead>
            <tbody>
              <tr><td className={TD}>Description</td><td className={TD}><code>mamorai agent pack</code></td><td className={TD}>あとで見分けるため</td></tr>
              <tr><td className={TD}>Reusable</td><td className={TD}>オン</td><td className={TD}>多くの端末で同じキーを使うため</td></tr>
              <tr><td className={TD}>Expiration</td><td className={TD}>90 days</td><td className={TD}>選べる最長の期間</td></tr>
              <tr><td className={TD}>Ephemeral</td><td className={TD}>オフ</td><td className={TD}>オンだと、オフラインになった端末が消えてしまう</td></tr>
              <tr><td className={TD}>Tags</td><td className={TD}>オン → <code>tag:mamorai</code></td><td className={TD}>タグ付きの端末は、端末の鍵に期限がなくなる（180 日で外れない）</td></tr>
              <tr><td className={TD}>Pre-approved</td><td className={TD}>表示されていればオン</td><td className={TD}>端末ごとの承認を省くため（端末の承認を有効にしている tailnet だけに出る項目）</td></tr>
            </tbody>
          </table>
        </li>
        <li>表示された <code>tskey-auth-…</code> を<b className="text-slate-100">コピー</b>します。この画面を閉じると二度と表示されません。チャットやメールには貼らないでください。</li>
        <li>MamorAI の <Link className="text-teal-300 hover:underline" to="/settings/agentpack">設定 › エージェントパック › 秘密情報</Link> を開き、「Tailscale の認証キー」に貼り付けます。<b className="text-slate-100">有効期限</b>（今日から 90 日後）も入れて「保存」します。</li>
        <li>エージェントパックが自動で新しい版（rN）になり、変更点に「Tailscale の認証キーを更新」と出ることを確認します。</li>
        <li>Tailscale の Keys の一覧で、<b className="text-slate-100">古いキーを Revoke</b> します。すでにつながっている端末には影響しません。</li>
        <li>前の版のパックを共有フォルダなどに置いている場合は、新しい版に置き換えます。</li>
      </ol>

      <h2 className={H2}>よくある質問</h2>
      <div className="flex flex-col gap-2.5">
        <div className={CARD}><div className="font-semibold text-slate-100">キーを入れ替えたら、今つながっている端末を入れ直す必要はある？</div><div className={P}>ありません。キーは参加するときに 1 回だけ使うものです。</div></div>
        <div className={CARD}><div className="font-semibold text-slate-100">期限を過ぎてしまった</div><div className={P}>上の手順でキーを作り直せば、すぐに元どおりになります。そのあいだに作ったパックで入れた端末は、ブラウザ承認で参加させるか、新しいパックで入れ直してください。</div></div>
        <div className={CARD}><div className="font-semibold text-slate-100">Wazuh の manager（MamorAI のサーバー）が tailnet から外れないか心配</div><div className={P}>manager は Tailscale の管理画面の Machines で、端末の「…」から <b>Disable key expiry</b> にしておいてください。<code>tag:mamorai</code> 付きのキーで参加した端末は、最初から期限がありません。</div></div>
        <div className={CARD}><div className="font-semibold text-slate-100">「キーが漏れたかもしれない」とき</div><div className={P}>Tailscale でそのキーを Revoke し、上の手順で新しいキーに替えてください。tailnet の Machines に、身に覚えのない端末がないかも確認します。</div></div>
      </div>
    </>
  );
}

const TOPICS: Record<string, { title: string; el: () => JSX.Element }> = {
  "tailscale-key": { title: "Tailscale の認証キーを入れ替える", el: TailscaleKey },
};

export default function Help() {
  const { topic = "" } = useParams();
  const t = TOPICS[topic];
  return (
    <div className="mx-auto flex max-w-[900px] flex-col gap-3.5">
      <div className="text-xs text-slate-400"><Link className="hover:underline" to="/hosts">管理ホスト</Link> › ヘルプ</div>
      {t ? <t.el /> : <div className="text-sm text-slate-400">ヘルプが見つかりません。{Object.entries(TOPICS).map(([k, v]) => <Link key={k} className="ml-2 text-teal-300 hover:underline" to={`/help/${k}`}>{v.title}</Link>)}</div>}
    </div>
  );
}
