// フィルタ・ソート状態と URL クエリパラメータの相互変換 (純関数)
//   デフォルト値はクエリから省略してクリーンな URL を保つ。
//   パース時は不正値をデフォルトへフォールバック (URL は信頼しない)。

import type { Source } from "./types";

export type SeverityFilter = "all" | "critical" | "high" | "medium";
export type SortKey = "default" | "cvss" | "published";
export type SortDir = "desc" | "asc";
export type ViewMode = "card" | "table";

export const ALL_SOURCES: Source[] = ["nvd", "jvn", "kev", "ghsa", "zdi", "trend"];

export interface FilterState {
  severity: SeverityFilter;
  sources: Source[];
  kevOnly: boolean;
  query: string;
  sort: SortKey;
  dir: SortDir; // sort が cvss/published のときのみ意味を持つ
  view: ViewMode;
}

export const DEFAULT_FILTERS: FilterState = {
  severity: "all",
  sources: ALL_SOURCES,
  kevOnly: false,
  query: "",
  sort: "default",
  dir: "desc",
  view: "card",
};

const SEVERITIES: SeverityFilter[] = ["all", "critical", "high", "medium"];
const SORTS: SortKey[] = ["default", "cvss", "published"];

export function parseFilterParams(sp: URLSearchParams): FilterState {
  const sev = sp.get("sev");
  const sort = sp.get("sort");
  // "?src=" (空文字) は全解除、パラメータ無しは全選択
  const src = sp.get("src");
  const sources =
    src == null
      ? ALL_SOURCES
      : (src.split(",").filter((s): s is Source => (ALL_SOURCES as string[]).includes(s)) as Source[]);
  return {
    severity: SEVERITIES.includes(sev as SeverityFilter) ? (sev as SeverityFilter) : "all",
    sources,
    kevOnly: sp.get("kev") === "1",
    query: sp.get("q") ?? "",
    sort: SORTS.includes(sort as SortKey) ? (sort as SortKey) : "default",
    dir: sp.get("dir") === "asc" ? "asc" : "desc",
    view: sp.get("view") === "table" ? "table" : "card",
  };
}

export function serializeFilterParams(f: FilterState): string {
  const sp = new URLSearchParams();
  if (f.query.trim()) sp.set("q", f.query.trim());
  if (f.severity !== "all") sp.set("sev", f.severity);
  if (f.sources.length !== ALL_SOURCES.length) sp.set("src", f.sources.join(","));
  if (f.kevOnly) sp.set("kev", "1");
  if (f.sort !== "default") {
    sp.set("sort", f.sort);
    if (f.dir !== "desc") sp.set("dir", f.dir); // dirはソート指定時のみ意味を持つ
  }
  if (f.view !== "card") sp.set("view", f.view);
  return sp.toString();
}
