import type { Priority, Severity, Source } from "@/lib/types";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-amber-400 text-black",
  LOW: "bg-zinc-400 text-black",
  NONE: "bg-zinc-300 text-black",
  UNKNOWN: "bg-zinc-200 text-zinc-700",
};

// カード/テーブル左端の深刻度カラーレール (border-l-4 と併用)。
// バッジより外周にあるため、縦スキャンで深刻度の分布が一目でわかる
const SEVERITY_RAILS: Record<string, string> = {
  CRITICAL: "border-l-red-600",
  HIGH: "border-l-orange-500",
  MEDIUM: "border-l-amber-400",
  LOW: "border-l-zinc-400",
  NONE: "border-l-zinc-300 dark:border-l-zinc-600",
  UNKNOWN: "border-l-zinc-300 dark:border-l-zinc-600",
};

export function severityRailClass(severity: Severity | undefined): string {
  return SEVERITY_RAILS[severity ?? "UNKNOWN"] ?? SEVERITY_RAILS.UNKNOWN;
}

export function SeverityBadge({ severity, score }: { severity: Severity; score: number | null }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-bold ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.UNKNOWN}`}
    >
      {/* 等幅+右寄せでスコアの小数点が縦に揃い、流し読みで比較できる */}
      <span className="inline-block w-7 text-right font-mono tabular-nums">
        {score != null ? score.toFixed(1) : "—"}
      </span>
      <span className="font-normal">{severity}</span>
    </span>
  );
}

const SOURCE_LABELS: Record<Source, { label: string; cls: string }> = {
  nvd: { label: "NVD", cls: "border-sky-500 text-sky-600 dark:text-sky-400" },
  jvn: { label: "JVN", cls: "border-emerald-500 text-emerald-600 dark:text-emerald-400" },
  kev: { label: "KEV", cls: "border-red-500 text-red-600 dark:text-red-400" },
  ghsa: { label: "GHSA", cls: "border-violet-500 text-violet-600 dark:text-violet-400" },
  zdi: { label: "ZDI", cls: "border-fuchsia-500 text-fuchsia-600 dark:text-fuchsia-400" },
  trend: { label: "NEWS", cls: "border-pink-500 text-pink-600 dark:text-pink-400" },
};

// トレンド言及シグナルのソースキー → 表示名 (速報の出典明示・信頼性判断材料)
const MENTION_SOURCE_NAMES: Record<string, string> = {
  "rss:thn": "The Hacker News",
  "rss:bleeping": "BleepingComputer",
  "rss:jpcert": "JPCERT/CC",
  mastodon: "Mastodon",
  hn: "Hacker News",
};

export function mentionSourceName(source: string): string {
  return MENTION_SOURCE_NAMES[source] ?? source;
}

export function SourceBadge({ source }: { source: Source }) {
  const s = SOURCE_LABELS[source];
  if (!s) return null;
  return (
    <span className={`inline-block rounded border px-1 py-px text-[10px] font-medium ${s.cls}`}>
      {s.label}
    </span>
  );
}

/** NVD/JVN/GHSA/KEV 未登録の速報 (トレンド昇格・ZDI由来)。KEVの赤と区別できる系統色 */
export function BreakingBadge() {
  return (
    <span
      className="inline-block rounded bg-fuchsia-600 px-1.5 py-0.5 text-[10px] font-bold text-white"
      title="NVD未登録の速報情報 (報道/ZDI由来)。詳細は未確定の可能性があります"
    >
      🚨 速報
    </span>
  );
}

export function KevBadge() {
  return (
    <span className="inline-block animate-pulse rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">
      悪用確認済み
    </span>
  );
}

/** マッチした技術名の表示整形: エコシステムプレフィックスを除去 (npm:axios → axios) */
export function stackLabel(matched: string): string {
  return matched.replace(/^(npm|composer):/, "");
}

/** 自プロジェクトの技術スタックに関連する脆弱性の印。どの技術かを名前で示す */
export function StackBadge({
  matchType,
  matched,
}: {
  matchType: "package" | "cpe" | "keyword";
  matched: string[];
}) {
  const certain = matchType === "package";
  const names = matched.map(stackLabel);
  const shown = names.slice(0, 3).join(", ") + (names.length > 3 ? ` +${names.length - 3}` : "");
  return (
    <span
      className="inline-block rounded border border-teal-500 bg-teal-50 px-1.5 py-0.5 text-[10px] font-bold text-teal-700 dark:bg-teal-950 dark:text-teal-300"
      title={`${certain ? "依存パッケージに完全一致" : "使用技術に関連する可能性"}: ${names.join(", ")}`}
    >
      📌 {shown || "使用技術"}
      {certain ? "" : "?"}
    </span>
  );
}

const PRIORITY_STYLES: Record<Priority, { label: string; cls: string }> = {
  high: { label: "優先度: 高", cls: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300" },
  medium: { label: "優先度: 中", cls: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300" },
  low: { label: "優先度: 低", cls: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300" },
};

export function PriorityBadge({ priority }: { priority: Priority }) {
  const p = PRIORITY_STYLES[priority];
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold ${p.cls}`}>
      {p.label}
    </span>
  );
}
