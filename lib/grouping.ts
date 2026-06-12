// 優先度順表示でのセクション分割 (速報 → スタック関連 → KEV → その他)
// 最初に該当したグループへ入れる。グループ内は入力順 (= 優先度順) を維持

import type { VulnEntry } from "./types";

export type GroupKey = "breaking" | "stack" | "kev" | "rest";

export interface VulnGroup {
  key: GroupKey;
  label: string;
  items: VulnEntry[];
}

const GROUP_DEFS: { key: GroupKey; label: string; match: (v: VulnEntry) => boolean }[] = [
  { key: "breaking", label: "🚨 速報 (NVD未登録)", match: (v) => v.breaking === true },
  { key: "stack", label: "📌 使用技術に関連", match: (v) => v.stackMatch != null },
  { key: "kev", label: "⚠ 悪用確認済み (KEV)", match: (v) => v.kev },
  { key: "rest", label: "その他 (優先度順)", match: () => true },
];

export function groupVulns(vulns: VulnEntry[]): VulnGroup[] {
  const groups = GROUP_DEFS.map((d) => ({ key: d.key, label: d.label, items: [] as VulnEntry[] }));
  for (const v of vulns) {
    const i = GROUP_DEFS.findIndex((d) => d.match(v));
    groups[i].items.push(v);
  }
  return groups.filter((g) => g.items.length > 0);
}
