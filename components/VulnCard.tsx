import type { VulnEntry } from "@/lib/types";
import type { ReadStatus } from "@/lib/useReadStatus";
import {
  BreakingBadge,
  KevBadge,
  PriorityBadge,
  SeverityBadge,
  SourceBadge,
  StackBadge,
  mentionSourceName,
  severityRailClass,
} from "./Badges";
import { RelativeTime } from "./RelativeTime";
import { StatusButton } from "./StatusButton";

export function VulnCard({
  vuln,
  expanded,
  onToggle,
  status,
  onCycleStatus,
}: {
  vuln: VulnEntry;
  expanded: boolean;
  onToggle: () => void;
  status: ReadStatus;
  onCycleStatus: () => void;
}) {
  // トリアージ動線: 要対応度が高いものだけ折りたたみ状態でも推奨対応を見せる
  const showActionPreview =
    !expanded &&
    vuln.recommendedActionJa &&
    (vuln.breaking || vuln.stackMatch || vuln.kev || vuln.priority === "high");
  // 既読装飾はタイトル/本文に限定 (レール・バッジの視認性は維持して深刻度スキャンを壊さない)
  const titleCls =
    status === "done"
      ? "text-zinc-400 line-through dark:text-zinc-500"
      : status === "read"
        ? "opacity-60"
        : "";
  return (
    <div
      id={vuln.id}
      className={`rounded-lg border border-l-4 bg-white transition-colors dark:bg-zinc-900 ${severityRailClass(
        vuln.cvss?.severity,
      )} ${
        vuln.kev
          ? "border-red-300 dark:border-red-800"
          : "border-zinc-200 dark:border-zinc-700"
      }`}
    >
      {/* ヘッダ全体をbuttonにすると状態ボタンが入れ子になるため、展開ボタンと兄弟に分割 */}
      <div className="flex">
        <button
          onClick={onToggle}
          className="block min-w-0 flex-1 p-3 text-left"
          aria-expanded={expanded}
        >
          {/* 1行目: 判断材料 (速報・重大度・KEV・優先度・スタック・話題) | 右端: 経過時間・出典 */}
          <span className="flex flex-wrap items-center gap-2">
            {vuln.breaking && <BreakingBadge />}
            {vuln.cvss && <SeverityBadge severity={vuln.cvss.severity} score={vuln.cvss.score} />}
            <span className="font-mono text-xs text-zinc-500">{vuln.id}</span>
            {vuln.kev && <KevBadge />}
            {vuln.priority && <PriorityBadge priority={vuln.priority} />}
            {vuln.stackMatch && <StackBadge matchType={vuln.stackMatch.matchType} />}
            {vuln.trendMentions.length > 0 && (
              <span className="text-[10px] text-pink-600 dark:text-pink-400">
                🔥 話題 ×{vuln.trendMentions.length}
              </span>
            )}
            <span className="ml-auto flex items-center gap-1.5">
              {vuln.published && <RelativeTime iso={vuln.published} />}
              {vuln.sources.map((s) => (
                <SourceBadge key={s} source={s} />
              ))}
              <span className="text-zinc-400">{expanded ? "▲" : "▼"}</span>
            </span>
          </span>
          {/* 2行目: タイトル全幅 (折り返し位置が安定しスキャンしやすい) */}
          <span className={`mt-1 block text-sm font-medium leading-snug ${titleCls}`}>
            {vuln.titleJa ?? vuln.titleEn}
          </span>
          {/* 3行目 (条件付き): 推奨対応の1行プレビュー */}
          {showActionPreview && (
            <span className="mt-1 block truncate text-xs font-medium text-emerald-700 dark:text-emerald-400">
              → 推奨: {vuln.recommendedActionJa}
            </span>
          )}
        </button>
        <div className="flex items-center border-l border-zinc-100 px-1.5 dark:border-zinc-800">
          <StatusButton status={status} onCycle={onCycleStatus} />
        </div>
      </div>
      {expanded && <VulnDetail vuln={vuln} />}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="mb-0.5 text-xs font-bold text-zinc-500 dark:text-zinc-400">{title}</h4>
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  );
}

export function VulnDetail({ vuln }: { vuln: VulnEntry }) {
  return (
    <div className="space-y-3 border-t border-zinc-100 p-3 dark:border-zinc-800">
      {!vuln.analyzed && (
        <p className="rounded bg-amber-50 p-2 text-xs text-amber-700 dark:bg-amber-950 dark:text-amber-300">
          この項目はAI分析の対象外または分析に失敗したため、元データのみ表示しています。
        </p>
      )}
      {vuln.breaking && (
        <div className="rounded border border-fuchsia-300 bg-fuchsia-50 p-2 dark:border-fuchsia-800 dark:bg-fuchsia-950">
          <h4 className="mb-0.5 text-xs font-bold text-fuchsia-700 dark:text-fuchsia-300">
            🚨 NVD未登録の速報情報
          </h4>
          <p className="text-xs leading-relaxed text-fuchsia-900 dark:text-fuchsia-200">
            公的データベース (NVD/JVN等) に未登録の情報です。CVSS等は暫定値の可能性があります。
            下記の出典 (一次情報) を確認してください。
          </p>
          {vuln.zdi && (
            <p className="mt-1 text-xs text-fuchsia-700 dark:text-fuchsia-400">
              出典: Zero Day Initiative {vuln.zdi.id ?? vuln.zdi.canId}
              {vuln.zdi.status === "upcoming"
                ? ` — ベンダー報告済み・パッチ未提供のゼロデイ${vuln.zdi.dueDate ? ` (修正期限: ${vuln.zdi.dueDate})` : ""}`
                : " — アドバイザリ公開済み"}
            </p>
          )}
          {!vuln.zdi && vuln.trendMentions.length > 0 && (
            <p className="mt-1 text-xs text-fuchsia-700 dark:text-fuchsia-400">
              出典: {[...new Set(vuln.trendMentions.map((m) => mentionSourceName(m.source)))].join(", ")} の報道
            </p>
          )}
        </div>
      )}
      {(vuln.stackImpactJa || vuln.stackMatch) && (
        <div className="rounded border border-teal-300 bg-teal-50 p-2 dark:border-teal-800 dark:bg-teal-950">
          <h4 className="mb-0.5 text-xs font-bold text-teal-700 dark:text-teal-300">
            📌 このプロジェクトへの影響
          </h4>
          <p className="text-sm leading-relaxed">
            {vuln.stackImpactJa ??
              "このプロジェクトの使用技術に関連する可能性があります。"}
          </p>
          {vuln.stackMatch && vuln.stackMatch.matched.length > 0 && (
            <p className="mt-1 text-xs text-teal-700 dark:text-teal-400">
              一致: {vuln.stackMatch.matched.join(", ")}
              {vuln.stackMatch.matchType !== "package" && " (キーワード/製品名ベースの推定)"}
            </p>
          )}
        </div>
      )}
      {vuln.summaryJa && <Section title="概要">{vuln.summaryJa}</Section>}
      {!vuln.summaryJa && vuln.titleEn && <Section title="概要 (原文)">{vuln.titleEn}</Section>}
      {vuln.impactJa && <Section title="想定される影響">{vuln.impactJa}</Section>}
      {vuln.recommendedActionJa && (
        <Section title="推奨対応">
          <span className="font-medium text-emerald-700 dark:text-emerald-400">
            {vuln.recommendedActionJa}
          </span>
        </Section>
      )}
      {vuln.priorityReasonJa && <Section title="優先度の根拠">{vuln.priorityReasonJa}</Section>}
      {vuln.kevInfo && (
        <Section title="CISA KEV (悪用が確認された脆弱性)">
          <ul className="list-inside list-disc text-xs">
            {vuln.kevInfo.dateAdded && <li>KEV追加日: {vuln.kevInfo.dateAdded}</li>}
            {vuln.kevInfo.dueDate && <li>米連邦機関の対応期限: {vuln.kevInfo.dueDate}</li>}
            {vuln.kevInfo.requiredAction && <li>要求される対応: {vuln.kevInfo.requiredAction}</li>}
            {vuln.kevInfo.knownRansomwareCampaignUse === "Known" && (
              <li className="font-bold text-red-600">ランサムウェアでの悪用が既知</li>
            )}
          </ul>
        </Section>
      )}
      {vuln.affectedProducts.length > 0 && (
        <Section title="影響を受ける製品">
          <ul className="list-inside list-disc text-xs">
            {vuln.affectedProducts.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </Section>
      )}
      {vuln.cvss?.vector && (
        <Section title="CVSSベクトル">
          <code className="rounded bg-zinc-100 px-1 py-0.5 font-mono text-xs dark:bg-zinc-800">
            CVSS {vuln.cvss.version}: {vuln.cvss.vector}
          </code>
        </Section>
      )}
      {vuln.trendMentions.length > 0 && (
        <Section title="SNS・コミュニティでの言及">
          <ul className="space-y-0.5 text-xs">
            {vuln.trendMentions.map((m) => (
              <li key={m.url}>
                <span className="mr-1 rounded bg-zinc-100 px-1 text-[10px] dark:bg-zinc-800">
                  {mentionSourceName(m.source)}
                </span>
                <a href={m.url} target="_blank" rel="noopener noreferrer" className="text-sky-600 hover:underline dark:text-sky-400">
                  {m.title || m.url}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}
      {vuln.references.length > 0 && (
        <Section title="参考リンク">
          <ul className="space-y-0.5 text-xs">
            {vuln.references.map((r) => (
              <li key={r.url}>
                <span className="mr-1 text-zinc-400">[{r.label}]</span>
                <a href={r.url} target="_blank" rel="noopener noreferrer" className="break-all text-sky-600 hover:underline dark:text-sky-400">
                  {r.url}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
