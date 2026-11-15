/**
 * EDR-146: 「AIエージェントに相談」— the same name and the same friendly first screen on every AI chat in MamorAI.
 * The agent is "the pocket that grants the user's wishes": plain questions, investigations, patching, improvements — anything.
 */
import InfoTip from "./InfoTip";

export const AGENT_NAME = "AIエージェントに相談";

export function AgentMark({ size = 20 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true"><path d="M32 4 L56 13 V31 C56 46 45 56 32 60 C19 56 8 46 8 31 V13 Z" fill="#3A56F0" /><circle cx="32" cy="30" r="7" fill="#FFFFFF" /><path d="M46 8l2.2 4.6L53 14l-4.8 1.4L46 20l-2.2-4.6L39 14l4.8-1.4z" fill="#F5C542" /></svg>;
}

/** title for chat panels: 「AIエージェントに相談」 + what this page is good at + ⓘ */
export function AgentTitle({ context, size = "md" }: { context?: string; size?: "sm" | "md" }) {
  return (
    <span className={`inline-flex items-center gap-2 font-semibold ${size === "sm" ? "text-sm" : "text-[15px]"}`}>
      <AgentMark size={size === "sm" ? 16 : 20} />{AGENT_NAME}
      {context && <span className="rounded-full bg-[#15204A] px-2 py-0.5 text-[11px] font-normal text-teal-200">{context}</span>}
      <span className="text-slate-400"><InfoTip title="AIエージェントとは">
        MamorAI の AI エージェントは「困ったらまず聞く」相手です。ちょっとした質問から、アラートの調査、パッチ当てや設定変更の相談、運用の改善まで、なんでも頼めます。<br />
        調べるのは自分で進め、<b className="text-slate-100">何かを変える操作は必ず承認カードであなたが確認してから</b>実行します。パスワードや鍵はチャットに貼らないでください。
      </InfoTip></span>
    </span>
  );
}

const CAN = [
  { icon: "🔍", t: "調べる", d: "アラート・ログ・脆弱性・端末の状態" },
  { icon: "🛠", t: "直す", d: "パッチ・設定変更・遮断（必ず承認後）" },
  { icon: "📋", t: "段取りする", d: "手順書・Action ボード・定期チェック" },
  { icon: "💡", t: "教わる", d: "用語・仕組み・どうすればいいか" },
];

/** first screen of a chat: what the agent can do + example requests (click → sent as the first message) */
export default function AgentIntro({ lead, examples = [], onPick, note, compact = false }: { lead?: React.ReactNode; examples?: string[]; onPick?: (text: string) => void; note?: React.ReactNode; compact?: boolean }) {
  return (
    <div className={`flex flex-col ${compact ? "gap-2" : "gap-3"} text-slate-300`}>
      <div className={compact ? "text-[13.5px] leading-relaxed" : "text-[15px] leading-[1.8]"}>
        {!compact && <div className="mb-0.5 flex items-center gap-2 text-[17px] font-semibold text-slate-100"><AgentMark size={22} />なんでも相談してください</div>}
        {lead ?? <>質問でも、調査でも、パッチ当てやシステム改善の相談でも大丈夫です。AI エージェントが調べて、やり方を考えて、<b className="text-slate-100">変更はあなたの承認をもらってから</b>実行します。</>}
      </div>
      {!compact && <div className="grid gap-2 [grid-template-columns:repeat(auto-fit,minmax(170px,1fr))]">
        {CAN.map((c) => <div key={c.t} className="rounded-xl border border-slate-700 bg-slate-900/60 px-3 py-2"><div className="text-[13.5px] font-semibold text-slate-100">{c.icon} {c.t}</div><div className="text-[12px] text-slate-400">{c.d}</div></div>)}
      </div>}
      {examples.length > 0 && <div>
        <div className="mb-1 text-[12px] text-slate-400">たとえば（押すとそのまま送ります）</div>
        <div className="flex flex-wrap gap-1.5">{examples.map((q) => <button key={q} type="button" disabled={!onPick} className="rounded-full border border-slate-600 bg-slate-900/40 px-3 py-1 text-left text-[12.5px] text-slate-200 hover:border-teal-400 hover:bg-slate-700 disabled:opacity-60" onClick={() => onPick?.(q)}>{q}</button>)}</div>
      </div>}
      {note && <div className="text-[12px] leading-relaxed text-slate-400">{note}</div>}
    </div>
  );
}
