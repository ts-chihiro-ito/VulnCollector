import Link from "next/link";
import type { IndexEntry } from "@/lib/types";

export function DateNav({ current, dates }: { current: string; dates: IndexEntry[] }) {
  // dates は新しい順
  const idx = dates.findIndex((d) => d.date === current);
  const newer = idx > 0 ? dates[idx - 1] : null;
  const older = idx >= 0 && idx < dates.length - 1 ? dates[idx + 1] : null;

  const href = (date: string) => `/date/${date}/`;

  return (
    <nav className="flex items-center gap-2 text-sm">
      {older ? (
        <Link href={href(older.date)} className="rounded border border-zinc-300 px-2 py-1 hover:bg-zinc-100 dark:border-zinc-600 dark:hover:bg-zinc-800">
          ← {older.date}
        </Link>
      ) : (
        <span className="rounded border border-zinc-200 px-2 py-1 text-zinc-400 dark:border-zinc-700">←</span>
      )}
      <span className="rounded bg-zinc-900 px-3 py-1 font-bold text-white dark:bg-zinc-100 dark:text-zinc-900">
        {current}
      </span>
      {newer ? (
        <Link href={href(newer.date)} className="rounded border border-zinc-300 px-2 py-1 hover:bg-zinc-100 dark:border-zinc-600 dark:hover:bg-zinc-800">
          {newer.date} →
        </Link>
      ) : (
        <span className="rounded border border-zinc-200 px-2 py-1 text-zinc-400 dark:border-zinc-700">→</span>
      )}
    </nav>
  );
}
