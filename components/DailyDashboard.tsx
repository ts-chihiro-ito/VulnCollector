"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DailyData, IndexEntry, Severity } from "@/lib/types";
import {
  DEFAULT_FILTERS,
  serializeFilterParams,
  type FilterState,
} from "@/lib/filterParams";
import { DateNav } from "./DateNav";
import { FilterBar } from "./FilterBar";
import { FilterParamsSync } from "./FilterParamsSync";
import { StatsCards } from "./StatsCards";
import { TrendSection } from "./TrendSection";
import { VulnCard } from "./VulnCard";

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
  UNKNOWN: 0,
};

const MIN_RANK = { all: 0, critical: 4, high: 3, medium: 2 } as const;

export function DailyDashboard({ day, dates }: { day: DailyData; dates: IndexEntry[] }) {
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showLowPriority, setShowLowPriority] = useState(false);
  const queryDebounce = useRef<number | null>(null);

  // #CVE-XXXX-YYYY ハッシュでのディープリンク (初期表示 + hashchange)
  useEffect(() => {
    const applyHash = () => {
      const id = decodeURIComponent(window.location.hash.slice(1));
      if (!id) return;
      setExpandedId(id);
      requestAnimationFrame(() => {
        document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    };
    const timer = setTimeout(applyHash, 0);
    window.addEventListener("hashchange", applyHash);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("hashchange", applyHash);
    };
  }, []);

  const focusCve = (id: string) => {
    setExpandedId(id);
    history.replaceState(null, "", `#${id}`);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  // URL クエリ → state (初期表示・リロード・ブラウザ戻る/進む)。
  // 自分の replaceState のエコーやデフォルト一致は no-op にして再レンダーを防ぐ
  const handleParams = useCallback((incoming: FilterState) => {
    setFilters((current) =>
      serializeFilterParams(incoming) === serializeFilterParams(current) ? current : incoming,
    );
  }, []);

  // state → URL (replaceState は Next ルーターと同期し、履歴を汚さない)。
  // 相対 "?..." はハッシュを落とすため location.hash の明示付加が必須
  const writeUrl = (f: FilterState) => {
    const qs = serializeFilterParams(f);
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${qs ? `?${qs}` : ""}${window.location.hash}`,
    );
  };

  const updateFilters = (next: FilterState) => {
    const onlyQueryChanged =
      next.query !== filters.query &&
      serializeFilterParams({ ...next, query: filters.query }) === serializeFilterParams(filters);
    setFilters(next);
    if (queryDebounce.current) window.clearTimeout(queryDebounce.current);
    if (onlyQueryChanged) {
      // キーストロークごとの URL 書き換えを抑制 (フィルタ自体は即時反映)
      queryDebounce.current = window.setTimeout(() => writeUrl(next), 300);
    } else {
      writeUrl(next);
    }
  };

  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    const base = day.vulns.filter((v) => {
      const sev: Severity = v.cvss?.severity ?? "UNKNOWN";
      if (SEVERITY_RANK[sev] < MIN_RANK[filters.severity]) return false;
      if (filters.kevOnly && !v.kev) return false;
      if (!v.sources.some((s) => filters.sources.includes(s))) return false;
      if (q) {
        const haystack = [
          v.id,
          v.titleJa,
          v.titleEn,
          v.summaryJa,
          v.jvnId,
          v.ghsaId,
          ...v.affectedProducts,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
    if (filters.sort === "cvss") {
      return base.sort((a, b) => (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1));
    }
    if (filters.sort === "published") {
      return base.sort((a, b) => (b.published ?? "").localeCompare(a.published ?? ""));
    }
    return base; // default: データ順 (優先度順で生成済み)
  }, [day.vulns, filters]);

  const filteredLow = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    if (!q) return day.lowPriority;
    return day.lowPriority.filter(
      (v) => v.id.toLowerCase().includes(q) || v.titleEn.toLowerCase().includes(q),
    );
  }, [day.lowPriority, filters.query]);

  const filterQuery = serializeFilterParams(filters);

  return (
    <div>
      {/* useSearchParams はこのブリッジのみで使用。Suspense でCSR降格を局所化し
          ダッシュボード本体のプリレンダーと本番ビルドを守る */}
      <Suspense fallback={null}>
        <FilterParamsSync onParams={handleParams} />
      </Suspense>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <DateNav current={day.date} dates={dates} query={filterQuery} />
        <span className="text-xs text-zinc-500 dark:text-zinc-400">更新 {day.generatedAt}</span>
      </div>

      <StatsCards stats={day.stats} />

      {day.stats.sourceErrors.length > 0 && (
        <p className="mb-4 rounded border border-amber-300 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-300">
          ⚠ 一部ソースの取得に失敗しています: {day.stats.sourceErrors.join(" / ")}
        </p>
      )}

      <TrendSection trends={day.trends} onCveClick={focusCve} />

      <FilterBar filters={filters} onChange={updateFilters} />

      <p className="mb-2 text-xs text-zinc-500">
        {filtered.length} / {day.vulns.length} 件を表示
      </p>
      <div className="space-y-2">
        {filtered.map((v) => (
          <VulnCard
            key={v.id}
            vuln={v}
            expanded={expandedId === v.id}
            onToggle={() => setExpandedId(expandedId === v.id ? null : v.id)}
          />
        ))}
        {filtered.length === 0 && (
          <p className="rounded border border-zinc-200 p-6 text-center text-sm text-zinc-500 dark:border-zinc-700">
            条件に一致する脆弱性はありません
          </p>
        )}
      </div>

      {day.lowPriority.length > 0 && (
        <section className="mt-6">
          <button
            onClick={() => setShowLowPriority(!showLowPriority)}
            className="mb-2 text-sm font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"
          >
            {showLowPriority ? "▼" : "▶"} その他の収集済みCVE ({filteredLow.length}件)
          </button>
          {showLowPriority && (
            <div className="max-h-96 overflow-y-auto rounded border border-zinc-200 dark:border-zinc-700">
              <table className="w-full text-xs">
                <tbody>
                  {filteredLow.slice(0, 500).map((v) => (
                    <tr key={v.id} className="border-b border-zinc-100 last:border-0 dark:border-zinc-800">
                      <td className="whitespace-nowrap px-2 py-1 font-mono">{v.id}</td>
                      <td className="whitespace-nowrap px-2 py-1">{v.score ?? "—"}</td>
                      <td className="px-2 py-1 text-zinc-500">{v.titleEn}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredLow.length > 500 && (
                <p className="p-2 text-center text-[10px] text-zinc-400">
                  表示は500件まで。検索で絞り込んでください。
                </p>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
