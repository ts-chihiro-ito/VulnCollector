"use client";

// 速報 (NVD未登録) 専用セクション: ページ上部の一等地でゼロデイ・未登録情報を強調表示。
// 出典 (ZDI / 報道媒体名) を明示し、閲覧者が情報の信頼性を判断できるようにする

import type { VulnEntry } from "@/lib/types";
import { SourceBadge, mentionSourceName } from "./Badges";
import { RelativeTime } from "./RelativeTime";

function provenance(v: VulnEntry): string {
  if (v.zdi) {
    return v.zdi.status === "upcoming"
      ? `ZDI ${v.zdi.canId} (パッチ前ゼロデイ報告)`
      : `ZDI ${v.zdi.id ?? v.zdi.canId}`;
  }
  const outlets = [...new Set(v.trendMentions.map((m) => mentionSourceName(m.source)))];
  return outlets.length > 0 ? `報道: ${outlets.join(", ")}` : "";
}

export function BreakingSection({
  vulns,
  onCveClick,
}: {
  vulns: VulnEntry[];
  onCveClick: (id: string) => void;
}) {
  if (vulns.length === 0) return null;
  return (
    <section className="mb-4 rounded-lg border border-fuchsia-400 bg-fuchsia-50 dark:border-fuchsia-700 dark:bg-fuchsia-950/40">
      <h2 className="border-b border-fuchsia-200 px-3 py-2 text-sm font-bold text-fuchsia-800 dark:border-fuchsia-800 dark:text-fuchsia-300">
        🚨 速報 — NVD未登録の脆弱性情報 ({vulns.length}件)
      </h2>
      <ul className="divide-y divide-fuchsia-100 dark:divide-fuchsia-900">
        {vulns.map((v) => (
          <li key={v.id}>
            <button
              onClick={() => onCveClick(v.id)}
              className="block w-full px-3 py-2 text-left transition-colors hover:bg-fuchsia-100/60 dark:hover:bg-fuchsia-900/30"
              title="クリックで一覧の該当エントリへ移動"
            >
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-bold">{v.id}</span>
                {v.cvss?.score != null && (
                  <span className="font-mono text-xs tabular-nums text-fuchsia-700 dark:text-fuchsia-300">
                    CVSS {v.cvss.score.toFixed(1)}
                  </span>
                )}
                {v.sources.map((s) => (
                  <SourceBadge key={s} source={s} />
                ))}
                <span className="text-[10px] text-fuchsia-600 dark:text-fuchsia-400">
                  {provenance(v)}
                </span>
                <span className="ml-auto">
                  {v.published && <RelativeTime iso={v.published} />}
                </span>
              </span>
              <span className="mt-0.5 block truncate text-xs text-zinc-700 dark:text-zinc-300">
                {v.titleJa ?? v.titleEn}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
