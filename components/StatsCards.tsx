import type { DailyStats } from "@/lib/types";

/**
 * コンパクトな統計ストリップ。主役は「使用技術に関連」の件数 (メイン一覧と一致するよう
 * Dashboard 側で day.vulns から計算して渡す)。全体の収集規模はミュート色の脇役
 */
export function StatsCards({
  stats,
  relevantTotal,
  relevantBreaking,
  relevantKev,
}: {
  stats: DailyStats;
  relevantTotal: number;
  relevantBreaking: number;
  relevantKev: number;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-baseline gap-x-4 gap-y-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 dark:border-zinc-700 dark:bg-zinc-900">
      <span className="text-sm">
        📌 使用技術に関連{" "}
        <span className={`text-xl font-bold ${relevantTotal > 0 ? "text-teal-700 dark:text-teal-300" : ""}`}>
          {relevantTotal}
        </span>{" "}
        件
      </span>
      {relevantBreaking > 0 && (
        <span className="text-xs font-medium text-fuchsia-600 dark:text-fuchsia-400">
          🚨 速報 {relevantBreaking}
        </span>
      )}
      {relevantKev > 0 && (
        <span className="text-xs font-medium text-red-600 dark:text-red-400">
          ⚠ 悪用確認済み {relevantKev}
        </span>
      )}
      <span className="ml-auto text-xs text-zinc-400 dark:text-zinc-500">
        収集 {stats.collectedTotal} ・ AI分析 {stats.analyzed} ・ Critical{" "}
        {stats.bySeverity.CRITICAL ?? 0} / High {stats.bySeverity.HIGH ?? 0}
      </span>
    </div>
  );
}
