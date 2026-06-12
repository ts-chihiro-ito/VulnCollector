"use client";

import type { ReadStatus } from "@/lib/useReadStatus";

const STATUS_UI: Record<ReadStatus, { icon: string; label: string; cls: string }> = {
  unread: { icon: "◯", label: "未読", cls: "text-zinc-300 hover:text-zinc-500 dark:text-zinc-600" },
  read: { icon: "👁", label: "既読", cls: "opacity-70 hover:opacity-100" },
  done: { icon: "✅", label: "対応済み", cls: "hover:opacity-70" },
};

/** 既読状態の循環ボタン (◯ 未読 → 👁 既読 → ✅ 対応済み)。カード/テーブル共用 */
export function StatusButton({ status, onCycle }: { status: ReadStatus; onCycle: () => void }) {
  const ui = STATUS_UI[status];
  return (
    <button
      onClick={(e) => {
        e.stopPropagation(); // 行クリックでの展開と干渉させない
        onCycle();
      }}
      className={`rounded px-1 py-0.5 text-sm leading-none transition-opacity ${ui.cls}`}
      title={`クリックで切り替え (現在: ${ui.label})`}
      aria-label={`既読状態を切り替え (現在: ${ui.label})`}
    >
      {ui.icon}
    </button>
  );
}
