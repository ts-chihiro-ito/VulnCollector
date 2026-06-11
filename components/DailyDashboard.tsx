"use client";

import { useEffect, useMemo, useState } from "react";
import type { DailyData, IndexEntry, Severity } from "@/lib/types";
import { DateNav } from "./DateNav";
import { FilterBar, type Filters } from "./FilterBar";
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
  const [filters, setFilters] = useState<Filters>({
    severity: "all",
    sources: ["nvd", "jvn", "kev", "ghsa"],
    kevOnly: false,
    query: "",
  });
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showLowPriority, setShowLowPriority] = useState(false);

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

  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    return day.vulns.filter((v) => {
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
  }, [day.vulns, filters]);

  const filteredLow = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    if (!q) return day.lowPriority;
    return day.lowPriority.filter(
      (v) => v.id.toLowerCase().includes(q) || v.titleEn.toLowerCase().includes(q),
    );
  }, [day.lowPriority, filters.query]);

  const sev = day.stats.bySeverity;

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <DateNav current={day.date} dates={dates} />
        <div className="flex flex-wrap gap-3 text-xs text-zinc-500 dark:text-zinc-400">
          <span>収集 {day.stats.collectedTotal}件</span>
          <span>分析 {day.stats.analyzed}件</span>
          <span className="text-red-600 dark:text-red-400">KEV {day.stats.kevCount}件</span>
          <span>Critical {sev.CRITICAL ?? 0} / High {sev.HIGH ?? 0}</span>
          <span>更新 {day.generatedAt}</span>
        </div>
      </div>

      {day.stats.sourceErrors.length > 0 && (
        <p className="mb-4 rounded border border-amber-300 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-300">
          ⚠ 一部ソースの取得に失敗しています: {day.stats.sourceErrors.join(" / ")}
        </p>
      )}

      <TrendSection trends={day.trends} onCveClick={focusCve} />

      <FilterBar filters={filters} onChange={setFilters} />

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
