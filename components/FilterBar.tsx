"use client";

import { useState } from "react";
import type { Source } from "@/lib/types";
import {
  ALL_SOURCES,
  DEFAULT_FILTERS,
  type FilterState,
  type SeverityFilter,
  type SortKey,
  type ViewMode,
} from "@/lib/filterParams";

const VIEW_OPTIONS: { value: ViewMode; label: string }[] = [
  { value: "card", label: "▦ カード" },
  { value: "table", label: "☰ テーブル" },
];

export function FilterBar({
  filters,
  onChange,
  hideDone,
  onHideDoneChange,
}: {
  filters: FilterState;
  onChange: (f: FilterState) => void;
  hideDone: boolean;
  onHideDoneChange: (v: boolean) => void;
}) {
  const [showDetail, setShowDetail] = useState(false);

  const toggleSource = (s: Source) => {
    const sources = filters.sources.includes(s)
      ? filters.sources.filter((x) => x !== s)
      : [...filters.sources, s];
    onChange({ ...filters, sources });
  };

  // 詳細フィルタに非デフォルト値があるか (URL共有で開いた人が気付けるよう ● を出す)
  const detailActive =
    filters.severity !== DEFAULT_FILTERS.severity ||
    filters.sources.length !== ALL_SOURCES.length ||
    filters.kevOnly ||
    filters.sort !== DEFAULT_FILTERS.sort ||
    hideDone;

  return (
    <div className="mb-4 rounded-lg border border-zinc-200 bg-white p-3 text-sm dark:border-zinc-700 dark:bg-zinc-900">
      {/* 常時表示: 検索 + 詳細フィルタトグル + 表示切替 */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={filters.query}
          onChange={(e) => onChange({ ...filters, query: e.target.value })}
          placeholder="CVE ID・製品名・キーワードで検索"
          className="w-64 rounded border border-zinc-300 bg-transparent px-2 py-1 outline-none focus:border-sky-500 dark:border-zinc-600"
        />
        <button
          onClick={() => setShowDetail(!showDetail)}
          aria-expanded={showDetail}
          className="rounded border border-zinc-300 px-2 py-1 text-xs text-zinc-500 hover:bg-zinc-100 dark:border-zinc-600 dark:hover:bg-zinc-800"
        >
          {showDetail ? "▼" : "▶"} 詳細フィルタ
          {detailActive && <span className="ml-1 text-sky-500">●</span>}
        </button>
        <div
          className="ml-auto flex overflow-hidden rounded border border-zinc-300 dark:border-zinc-600"
          role="group"
          aria-label="表示モード"
        >
          {VIEW_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => onChange({ ...filters, view: opt.value })}
              aria-pressed={filters.view === opt.value}
              className={`px-2 py-1 text-xs transition-colors ${
                filters.view === opt.value
                  ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                  : "text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* 詳細フィルタ (デフォルト閉) */}
      {showDetail && (
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-zinc-100 pt-3 dark:border-zinc-800">
          <label className="flex items-center gap-1">
            <span className="text-zinc-500">重大度:</span>
            <select
              value={filters.severity}
              onChange={(e) => onChange({ ...filters, severity: e.target.value as SeverityFilter })}
              className="rounded border border-zinc-300 bg-transparent px-1 py-1 dark:border-zinc-600 dark:bg-zinc-900"
            >
              <option value="all">すべて</option>
              <option value="critical">Critical のみ</option>
              <option value="high">High 以上</option>
              <option value="medium">Medium 以上</option>
            </select>
          </label>
          <label className="flex items-center gap-1">
            <span className="text-zinc-500">並び順:</span>
            <select
              value={filters.sort}
              onChange={(e) => onChange({ ...filters, sort: e.target.value as SortKey, dir: "desc" })}
              className="rounded border border-zinc-300 bg-transparent px-1 py-1 dark:border-zinc-600 dark:bg-zinc-900"
            >
              <option value="default">優先度順</option>
              <option value="cvss">CVSSスコア順</option>
              <option value="published">公開日が新しい順</option>
            </select>
          </label>
          <div className="flex items-center gap-2">
            <span className="text-zinc-500">ソース:</span>
            {ALL_SOURCES.map((s) => (
              <label key={s} className="flex cursor-pointer items-center gap-1">
                <input
                  type="checkbox"
                  checked={filters.sources.includes(s)}
                  onChange={() => toggleSource(s)}
                />
                <span className="uppercase">{s === "trend" ? "news" : s}</span>
              </label>
            ))}
          </div>
          <label className="flex cursor-pointer items-center gap-1">
            <input
              type="checkbox"
              checked={filters.kevOnly}
              onChange={(e) => onChange({ ...filters, kevOnly: e.target.checked })}
            />
            <span className="font-medium text-red-600 dark:text-red-400">悪用確認済みのみ</span>
          </label>
          <label className="flex cursor-pointer items-center gap-1">
            <input
              type="checkbox"
              checked={hideDone}
              onChange={(e) => onHideDoneChange(e.target.checked)}
            />
            <span className="text-zinc-500">✅ 対応済みを隠す</span>
          </label>
        </div>
      )}
    </div>
  );
}
