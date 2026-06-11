import type { TrendTopic } from "@/lib/types";

export function TrendSection({
  trends,
  onCveClick,
}: {
  trends: TrendTopic[];
  onCveClick: (id: string) => void;
}) {
  if (trends.length === 0) return null;
  return (
    <section className="mb-6">
      <h2 className="mb-2 text-lg font-bold">📈 本日の話題</h2>
      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
        {trends.map((t) => (
          <div
            key={t.topic}
            className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-700 dark:bg-zinc-900"
          >
            <h3 className="mb-1 text-sm font-semibold">{t.topic}</h3>
            <p className="mb-2 text-xs leading-relaxed text-zinc-600 dark:text-zinc-300">
              {t.summaryJa}
            </p>
            {t.relatedCveIds.length > 0 && (
              <div className="mb-1 flex flex-wrap gap-1">
                {t.relatedCveIds.map((id) => (
                  <button
                    key={id}
                    onClick={() => onCveClick(id)}
                    className="rounded bg-zinc-200 px-1.5 py-0.5 font-mono text-[10px] hover:bg-zinc-300 dark:bg-zinc-700 dark:hover:bg-zinc-600"
                  >
                    {id}
                  </button>
                ))}
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {t.sourceUrls.slice(0, 3).map((url, i) => (
                <a
                  key={url}
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] text-sky-600 hover:underline dark:text-sky-400"
                >
                  ソース{i + 1} ↗
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
