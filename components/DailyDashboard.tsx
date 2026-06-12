"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DailyData, IndexEntry, Severity, VulnEntry } from "@/lib/types";
import {
  DEFAULT_FILTERS,
  serializeFilterParams,
  type FilterState,
  type SortDir,
  type SortKey,
} from "@/lib/filterParams";
import { useLocalStorageValue, writeLocalStorage } from "@/lib/localStore";
import { useReadStatus } from "@/lib/useReadStatus";
import { BreakingSection } from "./BreakingSection";
import { DateNav } from "./DateNav";
import { FilterBar } from "./FilterBar";
import { FilterParamsSync } from "./FilterParamsSync";
import { StatsCards } from "./StatsCards";
import { TrendSection } from "./TrendSection";
import { VulnCard } from "./VulnCard";
import { VulnTable } from "./VulnTable";

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
  UNKNOWN: 0,
};

const MIN_RANK = { all: 0, critical: 4, high: 3, medium: 2 } as const;

// GitHub Pages は *.github.io のオリジンを共有するためキーを名前空間化
const VIEW_STORAGE_KEY = "vulncollector:view";
const HIDE_DONE_STORAGE_KEY = "vulncollector:hideDone";

export function DailyDashboard({ day, dates }: { day: DailyData; dates: IndexEntry[] }) {
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showOthers, setShowOthers] = useState(false);
  const [showLowPriority, setShowLowPriority] = useState(false);
  const queryDebounce = useRef<number | null>(null);
  const storedViewApplied = useRef(false);
  const { statusOf, cycle } = useReadStatus();
  // hideDone は個人のローカル状態なので URL に載せず localStorage のみ
  // (SSR/hydration 中は null = 無効として描画が一致する)
  const hideDone = useLocalStorageValue(HIDE_DONE_STORAGE_KEY) === "1";

  // メイン表示 = 使用技術に関連するもの。それ以外は「その他」セクション (デフォルト閉)
  const relevantIds = useMemo(
    () => new Set(day.vulns.filter((v) => v.stackMatch).map((v) => v.id)),
    [day.vulns],
  );

  // ディープリンク/CVEクリックの対象が「その他」内ならセクションを開いてからスクロール
  const revealCve = useCallback(
    (id: string) => {
      setExpandedId(id);
      if (!relevantIds.has(id)) setShowOthers(true);
      // setState と同一バッチで対象がマウントされるため、rAF 時点でDOMに存在する
      requestAnimationFrame(() => {
        document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    },
    [relevantIds],
  );

  // #CVE-XXXX-YYYY ハッシュでのディープリンク (初期表示 + hashchange)
  useEffect(() => {
    const applyHash = () => {
      const id = decodeURIComponent(window.location.hash.slice(1));
      if (id) revealCve(id);
    };
    const timer = setTimeout(applyHash, 0);
    window.addEventListener("hashchange", applyHash);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("hashchange", applyHash);
    };
  }, [revealCve]);

  const focusCve = (id: string) => {
    history.replaceState(null, "", `#${id}`);
    revealCve(id);
  };

  // URL クエリ → state (初期表示・リロード・ブラウザ戻る/進む)。
  // 自分の replaceState のエコーやデフォルト一致は no-op にして再レンダーを防ぐ。
  // 初回のみ: URL に view 指定が無ければ localStorage のデフォルトを適用し、
  // 即 URL へ昇格させて以降のパース結果と矛盾しないようにする (URL が常に source of truth)
  const handleParams = useCallback((incoming: FilterState) => {
    if (!storedViewApplied.current) {
      storedViewApplied.current = true;
      try {
        if (!new URLSearchParams(window.location.search).has("view")) {
          const stored = localStorage.getItem(VIEW_STORAGE_KEY);
          if (stored === "table") {
            incoming = { ...incoming, view: "table" };
            const qs = serializeFilterParams(incoming);
            window.history.replaceState(
              null,
              "",
              `${window.location.pathname}${qs ? `?${qs}` : ""}${window.location.hash}`,
            );
          }
        }
      } catch {
        // localStorage 不可環境は無視
      }
    }
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
    if (next.view !== filters.view) {
      // 表示モードは次回訪問のデフォルトとして記憶 (card はキー削除でクリーンに)
      try {
        if (next.view === "table") localStorage.setItem(VIEW_STORAGE_KEY, "table");
        else localStorage.removeItem(VIEW_STORAGE_KEY);
      } catch {
        // localStorage 不可環境は無視
      }
    }
    setFilters(next);
    if (queryDebounce.current) window.clearTimeout(queryDebounce.current);
    if (onlyQueryChanged) {
      // キーストロークごとの URL 書き換えを抑制 (フィルタ自体は即時反映)
      queryDebounce.current = window.setTimeout(() => writeUrl(next), 300);
    } else {
      writeUrl(next);
    }
  };

  const updateHideDone = (v: boolean) => writeLocalStorage(HIDE_DONE_STORAGE_KEY, v ? "1" : null);

  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    const base = day.vulns.filter((v) => {
      const sev: Severity = v.cvss?.severity ?? "UNKNOWN";
      if (SEVERITY_RANK[sev] < MIN_RANK[filters.severity]) return false;
      if (filters.kevOnly && !v.kev) return false;
      if (!v.sources.some((s) => filters.sources.includes(s))) return false;
      if (hideDone && statusOf(v.id) === "done") return false;
      if (q) {
        const haystack = [
          v.id,
          v.titleJa,
          v.titleEn,
          v.summaryJa,
          v.jvnId,
          v.ghsaId,
          ...v.affectedProducts,
          ...(v.stackMatch?.matched ?? []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
    const mul = filters.dir === "asc" ? -1 : 1;
    if (filters.sort === "cvss") {
      return base.sort((a, b) => mul * ((b.cvss?.score ?? -1) - (a.cvss?.score ?? -1)));
    }
    if (filters.sort === "published") {
      return base.sort((a, b) => mul * (b.published ?? "").localeCompare(a.published ?? ""));
    }
    return base; // default: データ順 (優先度順で生成済み)
  }, [day.vulns, filters, hideDone, statusOf]);

  // メイン = スタック関連のみ。その他はKEVを先頭に (悪用確認済みは関連が無くても上位で気付けるように)
  const relevant = useMemo(() => filtered.filter((v) => v.stackMatch), [filtered]);
  const others = useMemo(() => {
    const rest = filtered.filter((v) => !v.stackMatch);
    return [...rest.filter((v) => v.kev), ...rest.filter((v) => !v.kev)];
  }, [filtered]);

  // 統計はフィルタに依存しない日次の実数 (メイン一覧の母数と一致)
  const relevantAll = useMemo(() => day.vulns.filter((v) => v.stackMatch), [day.vulns]);
  const breakingRelevant = useMemo(() => relevantAll.filter((v) => v.breaking), [relevantAll]);

  const filteredLow = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    if (!q) return day.lowPriority;
    return day.lowPriority.filter(
      (v) => v.id.toLowerCase().includes(q) || v.titleEn.toLowerCase().includes(q),
    );
  }, [day.lowPriority, filters.query]);

  const filterQuery = serializeFilterParams(filters);
  const queryActive = filters.query.trim() !== "";
  // 検索で「その他」にだけヒットがある場合は自動展開 (0件に見える混乱を防ぐ)
  const othersOpen = showOthers || (queryActive && others.length > 0);

  const handleSortChange = (sort: SortKey, dir: SortDir) =>
    updateFilters({ ...filters, sort, dir });

  // カード/テーブルの一覧描画 (メインと「その他」で共用)
  const renderList = (items: VulnEntry[]) =>
    filters.view === "table" ? (
      <VulnTable
        items={items}
        sort={filters.sort}
        dir={filters.dir}
        onSortChange={handleSortChange}
        expandedId={expandedId}
        onToggle={(id) => setExpandedId(expandedId === id ? null : id)}
        statusOf={statusOf}
        onCycleStatus={cycle}
      />
    ) : (
      <div className="space-y-1.5">
        {items.map((v) => (
          <VulnCard
            key={v.id}
            vuln={v}
            expanded={expandedId === v.id}
            onToggle={() => setExpandedId(expandedId === v.id ? null : v.id)}
            status={statusOf(v.id)}
            onCycleStatus={() => cycle(v.id)}
          />
        ))}
      </div>
    );

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

      <StatsCards
        stats={day.stats}
        relevantTotal={relevantAll.length}
        relevantBreaking={breakingRelevant.length}
        relevantKev={relevantAll.filter((v) => v.kev).length}
      />

      {day.stats.sourceErrors.length > 0 && (
        <p className="mb-4 rounded border border-amber-300 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-300">
          ⚠ 一部ソースの取得に失敗しています: {day.stats.sourceErrors.join(" / ")}
        </p>
      )}

      <BreakingSection vulns={breakingRelevant} onCveClick={focusCve} />

      <FilterBar
        filters={filters}
        onChange={updateFilters}
        hideDone={hideDone}
        onHideDoneChange={updateHideDone}
      />

      {/* メイン: 使用技術に関連する脆弱性のみ */}
      <h2 className="mb-2 text-sm font-bold">
        📌 使用技術に関連する脆弱性{" "}
        <span className="font-normal text-zinc-400">
          ({relevant.length !== relevantAll.length ? `${relevant.length}/` : ""}
          {relevantAll.length}件)
        </span>
      </h2>
      {relevant.length > 0 ? (
        renderList(relevant)
      ) : (
        <p className="rounded border border-zinc-200 p-6 text-center text-sm text-zinc-500 dark:border-zinc-700">
          {relevantAll.length === 0
            ? "本日、使用技術に関連する脆弱性はありません"
            : "条件に一致する脆弱性はありません"}
        </p>
      )}

      {/* 使用技術に関連しないもの (デフォルト閉) */}
      {others.length > 0 && (
        <section className="mt-6">
          <button
            onClick={() => setShowOthers(!othersOpen)}
            aria-expanded={othersOpen}
            className="mb-2 text-sm font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"
          >
            {othersOpen ? "▼" : "▶"} その他の脆弱性 — 使用技術に関連しない ({others.length}件)
            {others.some((v) => v.kev) && (
              <span className="ml-2 text-xs font-normal text-red-500">
                ⚠ 悪用確認済み {others.filter((v) => v.kev).length}件を含む
              </span>
            )}
          </button>
          {othersOpen && renderList(others)}
        </section>
      )}

      <TrendSection trends={day.trends} onCveClick={focusCve} />

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
