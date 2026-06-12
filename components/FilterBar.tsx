import type { Source } from "@/lib/types";
import { ALL_SOURCES, type FilterState, type SeverityFilter, type SortKey } from "@/lib/filterParams";

export function FilterBar({
  filters,
  onChange,
}: {
  filters: FilterState;
  onChange: (f: FilterState) => void;
}) {
  const toggleSource = (s: Source) => {
    const sources = filters.sources.includes(s)
      ? filters.sources.filter((x) => x !== s)
      : [...filters.sources, s];
    onChange({ ...filters, sources });
  };

  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-zinc-200 bg-white p-3 text-sm dark:border-zinc-700 dark:bg-zinc-900">
      <input
        type="search"
        value={filters.query}
        onChange={(e) => onChange({ ...filters, query: e.target.value })}
        placeholder="CVE ID・製品名・キーワードで検索"
        className="w-64 rounded border border-zinc-300 bg-transparent px-2 py-1 outline-none focus:border-sky-500 dark:border-zinc-600"
      />
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
          onChange={(e) => onChange({ ...filters, sort: e.target.value as SortKey })}
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
            <span className="uppercase">{s}</span>
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
    </div>
  );
}
