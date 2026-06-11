import type { VulnEntry } from "@/lib/types";
import { KevBadge, PriorityBadge, SeverityBadge, SourceBadge } from "./Badges";

export function VulnCard({
  vuln,
  expanded,
  onToggle,
}: {
  vuln: VulnEntry;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      id={vuln.id}
      className={`rounded-lg border bg-white transition-colors dark:bg-zinc-900 ${
        vuln.kev
          ? "border-red-300 dark:border-red-800"
          : "border-zinc-200 dark:border-zinc-700"
      }`}
    >
      <button
        onClick={onToggle}
        className="flex w-full flex-wrap items-center gap-2 p-3 text-left"
        aria-expanded={expanded}
      >
        {vuln.cvss && <SeverityBadge severity={vuln.cvss.severity} score={vuln.cvss.score} />}
        <span className="font-mono text-xs text-zinc-500">{vuln.id}</span>
        {vuln.kev && <KevBadge />}
        {vuln.priority && <PriorityBadge priority={vuln.priority} />}
        <span className="flex gap-1">
          {vuln.sources.map((s) => (
            <SourceBadge key={s} source={s} />
          ))}
        </span>
        {vuln.trendMentions.length > 0 && (
          <span className="text-[10px] text-pink-600 dark:text-pink-400">
            🔥 話題 ×{vuln.trendMentions.length}
          </span>
        )}
        <span className="w-full text-sm font-medium sm:w-auto sm:flex-1">
          {vuln.titleJa ?? vuln.titleEn}
        </span>
        <span className="ml-auto text-zinc-400">{expanded ? "▲" : "▼"}</span>
      </button>
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
                <span className="mr-1 rounded bg-zinc-100 px-1 text-[10px] uppercase dark:bg-zinc-800">
                  {m.source}
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
