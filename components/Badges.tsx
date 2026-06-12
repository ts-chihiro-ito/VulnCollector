import type { Priority, Severity, Source } from "@/lib/types";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-amber-400 text-black",
  LOW: "bg-zinc-400 text-black",
  NONE: "bg-zinc-300 text-black",
  UNKNOWN: "bg-zinc-200 text-zinc-700",
};

export function SeverityBadge({ severity, score }: { severity: Severity; score: number | null }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-bold ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.UNKNOWN}`}
    >
      {score != null ? score.toFixed(1) : "—"}
      <span className="font-normal">{severity}</span>
    </span>
  );
}

const SOURCE_LABELS: Record<Source, { label: string; cls: string }> = {
  nvd: { label: "NVD", cls: "border-sky-500 text-sky-600 dark:text-sky-400" },
  jvn: { label: "JVN", cls: "border-emerald-500 text-emerald-600 dark:text-emerald-400" },
  kev: { label: "KEV", cls: "border-red-500 text-red-600 dark:text-red-400" },
  ghsa: { label: "GHSA", cls: "border-violet-500 text-violet-600 dark:text-violet-400" },
};

export function SourceBadge({ source }: { source: Source }) {
  const s = SOURCE_LABELS[source];
  if (!s) return null;
  return (
    <span className={`inline-block rounded border px-1 py-px text-[10px] font-medium ${s.cls}`}>
      {s.label}
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

/** 自プロジェクトの技術スタックに関連する脆弱性の印 */
export function StackBadge({ matchType }: { matchType: "package" | "cpe" | "keyword" }) {
  const certain = matchType === "package";
  return (
    <span
      className="inline-block rounded border border-teal-500 bg-teal-50 px-1.5 py-0.5 text-[10px] font-bold text-teal-700 dark:bg-teal-950 dark:text-teal-300"
      title={certain ? "依存パッケージに完全一致" : "使用技術に関連する可能性"}
    >
      📌 使用技術{certain ? "" : "?"}
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
