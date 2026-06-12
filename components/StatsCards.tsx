import type { DailyStats } from "@/lib/types";

function Card({
  label,
  value,
  valueCls = "",
  children,
}: {
  label: string;
  value: React.ReactNode;
  valueCls?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-zinc-200 bg-white p-3 dark:border-zinc-700 dark:bg-zinc-900">
      <p className="text-xs text-zinc-500 dark:text-zinc-400">{label}</p>
      <p className={`text-2xl font-bold ${valueCls}`}>{value}</p>
      {children}
    </div>
  );
}

export function StatsCards({ stats }: { stats: DailyStats }) {
  const analyzedRate =
    stats.collectedTotal > 0 ? Math.round((stats.analyzed / stats.collectedTotal) * 1000) / 10 : 0;
  return (
    <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
      <Card label="収集" value={stats.collectedTotal}>
        {(stats.breakingCount ?? 0) > 0 ? (
          <p className="text-xs font-medium text-fuchsia-600 dark:text-fuchsia-400">
            🚨 速報 (NVD未登録) {stats.breakingCount}件
          </p>
        ) : (
          <p className="text-xs text-zinc-400">全ソース計</p>
        )}
      </Card>
      <Card label="AI分析" value={stats.analyzed}>
        <div className="mt-1 flex items-center gap-1">
          <div className="h-1 flex-1 rounded-full bg-zinc-200 dark:bg-zinc-700">
            <div
              className="h-1 rounded-full bg-sky-500"
              style={{ width: `${Math.min(analyzedRate, 100)}%` }}
            />
          </div>
          <span className="text-[10px] text-zinc-400">{analyzedRate}%</span>
        </div>
      </Card>
      <Card label="KEV (悪用確認済み)" value={stats.kevCount} valueCls="text-red-600 dark:text-red-400">
        {(stats.stackMatched ?? 0) > 0 && (
          <p className="text-xs text-teal-600 dark:text-teal-400">📌 使用技術に関連 {stats.stackMatched}件</p>
        )}
      </Card>
      <Card
        label="Critical / High"
        value={
          <>
            <span className="text-red-600 dark:text-red-400">{stats.bySeverity.CRITICAL ?? 0}</span>
            <span className="mx-1 text-base font-normal text-zinc-400">/</span>
            <span className="text-orange-500">{stats.bySeverity.HIGH ?? 0}</span>
          </>
        }
      >
        <p className="text-xs text-zinc-400">重大度内訳</p>
      </Card>
    </div>
  );
}
