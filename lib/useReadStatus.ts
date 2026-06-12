"use client";

// 既読/対応済みのローカル管理 (CVE ID単位・日付に依存しないグローバル)。
// SSR/初回クライアント描画は常に「全件未読」(localStore のサーバースナップショットが null) で一致し、
// マウント後の再描画で既読装飾が適用される。

import { useCallback, useMemo } from "react";
import { readLocalStorage, useLocalStorageValue, writeLocalStorage } from "./localStore";

export type ReadStatus = "unread" | "read" | "done";

const STORAGE_KEY = "vulncollector:status";
const MAX_ENTRIES = 2000; // 無制限肥大の防止 (超過時は更新が古い順に間引く)

type StatusMap = Record<string, { s: Exclude<ReadStatus, "unread">; t: number }>;

function parse(raw: string | null): StatusMap {
  try {
    return raw ? (JSON.parse(raw) as StatusMap) : {};
  } catch {
    return {};
  }
}

function prune(map: StatusMap): StatusMap {
  const entries = Object.entries(map);
  if (entries.length <= MAX_ENTRIES) return map;
  entries.sort((a, b) => b[1].t - a[1].t);
  return Object.fromEntries(entries.slice(0, MAX_ENTRIES));
}

const CYCLE: Record<ReadStatus, ReadStatus> = { unread: "read", read: "done", done: "unread" };

export function useReadStatus() {
  const raw = useLocalStorageValue(STORAGE_KEY);
  const map = useMemo(() => parse(raw), [raw]);

  const statusOf = useCallback(
    (id: string): ReadStatus => map[id]?.s ?? "unread",
    [map],
  );

  const cycle = useCallback((id: string) => {
    const current = parse(readLocalStorage(STORAGE_KEY));
    const next = CYCLE[current[id]?.s ?? "unread"];
    const updated: StatusMap = { ...current };
    if (next === "unread") delete updated[id];
    else updated[id] = { s: next, t: Date.now() };
    writeLocalStorage(STORAGE_KEY, JSON.stringify(prune(updated)));
  }, []);

  return { statusOf, cycle };
}
