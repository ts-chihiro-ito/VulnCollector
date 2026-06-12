"use client";

// 高密度テーブルビュー: 1画面に多くのCVEを表示し列ソート可能。
// 行に id 属性を付けるため、既存の #CVE-ID ディープリンク (focusCve) がビュー不問で機能する。

import type { VulnEntry } from "@/lib/types";
import type { SortDir, SortKey } from "@/lib/filterParams";
import type { ReadStatus } from "@/lib/useReadStatus";
import type { VulnGroup } from "@/lib/grouping";
import { SourceBadge, severityRailClass } from "./Badges";
import { RelativeTime } from "./RelativeTime";
import { StatusButton } from "./StatusButton";
import { VulnDetail } from "./VulnCard";

const PRIORITY_CELL: Record<string, { label: string; cls: string }> = {
  high: { label: "高", cls: "font-bold text-red-600 dark:text-red-400" },
  medium: { label: "中", cls: "text-amber-600 dark:text-amber-400" },
  low: { label: "低", cls: "text-zinc-400" },
};

function SortableHeader({
  label,
  sortKey,
  current,
  dir,
  onSort,
  className = "",
}: {
  label: string;
  sortKey: SortKey;
  current: SortKey;
  dir: SortDir;
  onSort: (key: SortKey) => void;
  className?: string;
}) {
  const active = current === sortKey;
  return (
    <th
      scope="col"
      aria-sort={active ? (dir === "desc" ? "descending" : "ascending") : undefined}
      className={`px-2 py-1.5 text-left font-medium ${className}`}
    >
      <button
        onClick={() => onSort(sortKey)}
        className={`hover:text-zinc-900 dark:hover:text-zinc-100 ${active ? "text-zinc-900 dark:text-zinc-100" : ""}`}
        title="クリックでソート切替 (降順 → 昇順 → 優先度順)"
      >
        {label}
        {active && <span className="ml-0.5">{dir === "desc" ? "▼" : "▲"}</span>}
      </button>
    </th>
  );
}

export function VulnTable({
  groups,
  showGroupHeaders,
  sort,
  dir,
  onSortChange,
  expandedId,
  onToggle,
  statusOf,
  onCycleStatus,
}: {
  groups: VulnGroup[];
  showGroupHeaders: boolean;
  sort: SortKey;
  dir: SortDir;
  onSortChange: (sort: SortKey, dir: SortDir) => void;
  expandedId: string | null;
  onToggle: (id: string) => void;
  statusOf: (id: string) => ReadStatus;
  onCycleStatus: (id: string) => void;
}) {
  // 同一キー再クリックで desc → asc → 優先度順(default) のサイクル
  const handleSort = (key: SortKey) => {
    if (sort !== key) onSortChange(key, "desc");
    else if (dir === "desc") onSortChange(key, "asc");
    else onSortChange("default", "desc");
  };

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-700">
      <table className="w-full table-fixed text-xs">
        <thead className="sticky top-0 z-10 bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
          <tr>
            <th scope="col" className="w-8 px-1 py-1.5" title="既読状態" />
            <SortableHeader label="CVSS" sortKey="cvss" current={sort} dir={dir} onSort={handleSort} className="w-16" />
            <th scope="col" className="w-44 px-2 py-1.5 text-left font-medium">
              <button
                onClick={() => onSortChange("default", "desc")}
                className={`hover:text-zinc-900 dark:hover:text-zinc-100 ${sort === "default" ? "text-zinc-900 dark:text-zinc-100" : ""}`}
                title="優先度順 (デフォルト) に戻す"
              >
                ID{sort === "default" && <span className="ml-0.5">★</span>}
              </button>
            </th>
            <th scope="col" className="px-2 py-1.5 text-left font-medium">タイトル</th>
            <th scope="col" className="w-10 px-2 py-1.5 text-left font-medium">優先</th>
            <th scope="col" className="w-28 px-2 py-1.5 text-left font-medium">ソース</th>
            <SortableHeader label="公開" sortKey="published" current={sort} dir={dir} onSort={handleSort} className="w-36" />
          </tr>
        </thead>
        {groups.map((group) => (
          <tbody key={group.key}>
            {showGroupHeaders && (
              <tr>
                <th
                  colSpan={7}
                  scope="colgroup"
                  className="border-y border-zinc-200 bg-zinc-50 px-2 py-1 text-left text-[11px] font-bold text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/70 dark:text-zinc-300"
                >
                  {group.label} ({group.items.length}件)
                </th>
              </tr>
            )}
            {group.items.map((v) => {
              const status = statusOf(v.id);
              const expanded = expandedId === v.id;
              const prio = v.priority ? PRIORITY_CELL[v.priority] : null;
              return (
                <Row key={v.id} vuln={v} status={status} expanded={expanded} onToggle={onToggle} onCycleStatus={onCycleStatus} prio={prio} />
              );
            })}
          </tbody>
        ))}
      </table>
    </div>
  );
}

function Row({
  vuln,
  status,
  expanded,
  onToggle,
  onCycleStatus,
  prio,
}: {
  vuln: VulnEntry;
  status: ReadStatus;
  expanded: boolean;
  onToggle: (id: string) => void;
  onCycleStatus: (id: string) => void;
  prio: { label: string; cls: string } | null;
}) {
  const titleCls =
    status === "done"
      ? "text-zinc-400 line-through dark:text-zinc-500"
      : status === "read"
        ? "opacity-60"
        : "";
  return (
    <>
      <tr
        id={vuln.id}
        tabIndex={0}
        onClick={() => onToggle(vuln.id)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle(vuln.id);
          }
        }}
        aria-expanded={expanded}
        className="cursor-pointer border-b border-zinc-100 last:border-0 hover:bg-sky-50 dark:border-zinc-800 dark:hover:bg-sky-950/40"
      >
        <td className="px-1 py-1 text-center">
          <StatusButton status={status} onCycle={() => onCycleStatus(vuln.id)} />
        </td>
        <td className={`border-l-4 px-2 py-1 text-right font-mono tabular-nums ${severityRailClass(vuln.cvss?.severity)}`}>
          {vuln.cvss?.score != null ? vuln.cvss.score.toFixed(1) : "—"}
        </td>
        <td className="whitespace-nowrap px-2 py-1 font-mono">
          {vuln.id}
          {vuln.breaking && <span title="NVD未登録の速報"> 🚨</span>}
          {vuln.stackMatch && <span title="使用技術に関連"> 📌</span>}
          {vuln.kev && <span title="悪用確認済み (KEV)"> ⚠</span>}
        </td>
        <td className={`truncate px-2 py-1 ${titleCls}`} title={vuln.titleJa ?? vuln.titleEn}>
          {vuln.titleJa ?? vuln.titleEn}
        </td>
        <td className={`px-2 py-1 ${prio?.cls ?? "text-zinc-300 dark:text-zinc-600"}`}>
          {prio?.label ?? "—"}
        </td>
        <td className="space-x-0.5 whitespace-nowrap px-2 py-1">
          {vuln.sources.map((s) => (
            <SourceBadge key={s} source={s} />
          ))}
        </td>
        <td className="whitespace-nowrap px-2 py-1">
          {vuln.published ? <RelativeTime iso={vuln.published} /> : "—"}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="bg-white dark:bg-zinc-900">
            <VulnDetail vuln={vuln} />
          </td>
        </tr>
      )}
    </>
  );
}
