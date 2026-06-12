"use client";

import { useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { parseFilterParams, type FilterState } from "@/lib/filterParams";

/**
 * URL クエリ → フィルタ state の同期ブリッジ (描画なし)。
 * useSearchParams を呼ぶ唯一のコンポーネント。静的エクスポートでは
 * useSearchParams 利用ツリーが最寄りの Suspense 境界まで CSR に降格するため、
 * このコンポーネントだけを <Suspense> に包んで隔離する
 * (DailyDashboard 本体のプリレンダーを守る + ビルドエラー回避)。
 * 初回マウントとブラウザ戻る/進む (Next ルーターが popstate を同期) の両方で発火する。
 */
export function FilterParamsSync({ onParams }: { onParams: (f: FilterState) => void }) {
  const searchParams = useSearchParams();
  useEffect(() => {
    onParams(parseFilterParams(new URLSearchParams(searchParams.toString())));
    // onParams は親で useCallback 安定化済み
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);
  return null;
}
