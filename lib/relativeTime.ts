// 経過時間表示の純関数 (コンポーネントから分離してテスト可能に)

/** published はタイムゾーン指定なしのUTC ("2026-06-09T16:16:35.700") のため Z を補完してパース */
export function parseUtcIso(iso: string): number {
  const normalized = /[Zz]|[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + "Z";
  return Date.parse(normalized);
}

/** 「N分前/N時間前/N日前」。14日超は null (絶対日付だけで十分)。不正値も null */
export function formatRelativeJa(iso: string, now: number): string | null {
  const t = parseUtcIso(iso);
  if (Number.isNaN(t)) return null;
  const diffMs = Math.max(0, now - t); // 未来時刻 (時計ずれ) は「たった今」に丸める
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return "たった今";
  if (minutes < 60) return `${minutes}分前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}時間前`;
  const days = Math.floor(hours / 24);
  if (days <= 14) return `${days}日前`;
  return null;
}
