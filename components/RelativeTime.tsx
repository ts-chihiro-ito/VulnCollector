"use client";

import { useSyncExternalStore } from "react";
import { formatRelativeJa } from "@/lib/relativeTime";

// 「現在時刻 (分解像度)」を外部ストアとして購読する。
// SSR/hydration 中はサーバースナップショット (null) なので日付部分のみ描画され、
// マウント後に相対時間が付き、開きっぱなしでも毎分更新される — effect での setState 不要
function subscribeMinute(cb: () => void) {
  const timer = setInterval(cb, 60_000);
  return () => clearInterval(timer);
}
const getMinute = () => Math.floor(Date.now() / 60_000);
const getServerMinute = () => null;

/** 「YYYY-MM-DD (18時間前)」表示。日付部分はロケール非依存の文字列スライスで hydration 安全 */
export function RelativeTime({ iso }: { iso: string }) {
  const minute = useSyncExternalStore(subscribeMinute, getMinute, getServerMinute);
  const rel = minute == null ? null : formatRelativeJa(iso, minute * 60_000);
  return (
    <time dateTime={iso} className="whitespace-nowrap text-[10px] text-zinc-400 tabular-nums">
      {iso.slice(0, 10)}
      {rel ? ` (${rel})` : ""}
    </time>
  );
}
