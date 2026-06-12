"use client";

// localStorage を React の外部ストアとして購読する基盤。
// useSyncExternalStore により SSR/hydration 中はサーバースナップショット (null) を返し、
// マウント後に実値で再描画される — effect での setState を使わない hydration 安全パターン。
// GitHub Pages は *.github.io のオリジンを共有するため、キーは "vulncollector:" で名前空間化すること。

import { useCallback, useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  // 別タブでの変更も反映 (storage イベントは他タブでのみ発火する)
  window.addEventListener("storage", cb);
  return () => {
    listeners.delete(cb);
    window.removeEventListener("storage", cb);
  };
}

export function readLocalStorage(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null; // プライベートモード等は黙ってメモリのみ動作
  }
}

/** 書き込み (null で削除) + 同一タブ内の購読者へ通知 */
export function writeLocalStorage(key: string, value: string | null) {
  try {
    if (value == null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // 保存失敗は無視
  }
  emit();
}

/** localStorage の単一キーを購読する。SSR/hydration 中は常に null */
export function useLocalStorageValue(key: string): string | null {
  const getSnapshot = useCallback(() => readLocalStorage(key), [key]);
  return useSyncExternalStore(subscribe, getSnapshot, () => null);
}
