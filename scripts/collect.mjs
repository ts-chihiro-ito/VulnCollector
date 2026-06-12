#!/usr/bin/env node
// 収集オーケストレータ:
//   4ソース + トレンドシグナルを取得し、AI入力バッチを tmp/ に書き出す。
//   1ソースの失敗ではrunを止めない (stats.sourceErrors に記録)。

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { jstDateString, jstTimestamp, runSource, truncate } from "./lib/util.mjs";
import { fetchNvdWindow, fetchNvdById, severityFromScore } from "./lib/nvd.mjs";
import { fetchJvnWindow } from "./lib/jvn.mjs";
import { fetchKev } from "./lib/kev.mjs";
import { fetchGhsaWindow } from "./lib/ghsa.mjs";
import { fetchTrendSignals } from "./lib/trends.mjs";
import {
  mergeSources,
  selectForAnalysis,
  loadRecentlyAnalyzedIds,
  loadTodayAnalyzed,
  buildBatches,
} from "./lib/filter.mjs";
import { loadStack, matchStack } from "./lib/stack.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TMP = path.join(ROOT, "tmp");
const DATA_DIR = path.join(ROOT, "data");
const WINDOW_HOURS = 48;

const watchlist = JSON.parse(fs.readFileSync(path.join(ROOT, "scripts", "watchlist.json"), "utf8"));

async function main() {
  const now = new Date();
  const windowStart = new Date(now.getTime() - WINDOW_HOURS * 3600_000);
  const todayJst = jstDateString(now);
  console.log(`収集開始: ${jstTimestamp(now)} (窓: ${WINDOW_HOURS}h, 日付: ${todayJst})`);

  fs.mkdirSync(path.join(TMP, "ai"), { recursive: true });
  // 前回実行の残骸を除去 (バッチ数が減った場合の取り違え防止)
  for (const f of fs.readdirSync(path.join(TMP, "ai"))) {
    fs.rmSync(path.join(TMP, "ai", f));
  }

  // NVDはレート制限が厳しいので直列、他は並列
  const ghToken = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? "";
  const [nvdRes, jvnRes, kevRes, ghsaRes, trendRes] = await Promise.all([
    runSource("nvd", () => fetchNvdWindow(windowStart, now)),
    runSource("jvn", () => fetchJvnWindow(windowStart, now)),
    runSource("kev", () => fetchKev(windowStart)),
    runSource("ghsa", () => fetchGhsaWindow(windowStart, ghToken)),
    fetchTrendSignals(windowStart),
  ]);

  const kev = kevRes.ok ? kevRes.items : { all: new Map(), newlyAdded: [] };
  const sourceErrors = [
    ...[nvdRes, jvnRes, kevRes, ghsaRes].filter((r) => !r.ok).map((r) => `${r.name}: ${r.error}`),
    ...trendRes.errors,
  ];

  const nvdItems = nvdRes.ok ? nvdRes.items : [];
  const nvdIds = new Set(nvdItems.map((i) => i.id));

  // KEV新規追加でNVD窓に無い古いCVEをバックフィル (≤10件)
  for (const entry of kev.newlyAdded.slice(0, 10)) {
    if (nvdIds.has(entry.cveId)) continue;
    try {
      const item = await fetchNvdById(entry.cveId);
      if (item) {
        nvdItems.push(item);
        nvdIds.add(item.id);
        console.log(`[kev-backfill] ${entry.cveId} をNVDから補完`);
      }
    } catch (err) {
      console.warn(`[kev-backfill] ${entry.cveId} 取得失敗: ${err.message}`);
    }
  }

  const records = mergeSources({
    nvdItems,
    jvnItems: jvnRes.ok ? jvnRes.items : [],
    ghsaItems: ghsaRes.ok ? ghsaRes.items : [],
    kev,
    mentions: trendRes.mentions,
  });
  console.log(`統合レコード数: ${records.size}`);

  // 自プロジェクトの技術スタックと照合
  const stack = loadStack(ROOT, watchlist);
  let stackMatched = 0;
  for (const r of records.values()) {
    r.stackMatch = matchStack(r, stack);
    if (r.stackMatch) stackMatched++;
  }
  console.log(`スタックマッチ: ${stackMatched}件`);

  const excludeIds = loadRecentlyAnalyzedIds(DATA_DIR, todayJst);
  const alreadyAnalyzed = loadTodayAnalyzed(DATA_DIR, todayJst);
  const { selected, lowPriority } = selectForAnalysis(records, watchlist, {
    excludeIds,
    alreadyAnalyzed,
  });
  console.log(
    `分析対象: ${selected.length}件 (うち本日分析済み再利用: ${selected.filter((r) => alreadyAnalyzed.has(r.id)).length}件) / 低優先: ${lowPriority.length}件`,
  );

  // AIバッチ書き出し
  const batches = buildBatches(selected, watchlist, alreadyAnalyzed);
  batches.forEach((batch, i) => {
    fs.writeFileSync(
      path.join(TMP, "ai", `batch-${i + 1}.json`),
      JSON.stringify({ items: batch }, null, 2),
    );
  });
  console.log(`AIバッチ: ${batches.length}個 (${batches.reduce((n, b) => n + b.length, 0)}件)`);

  // トレンド統合用ダイジェスト (上位N件 + 当日の分析対象CVE一覧)
  const topSignals = [...trendRes.signals]
    .sort((a, b) => (b.engagement ?? 0) - (a.engagement ?? 0) || (b.date ?? "").localeCompare(a.date ?? ""))
    .slice(0, watchlist.maxTrendSignals)
    .map((s) => ({
      source: s.source,
      title: truncate(s.title, 150),
      url: s.url,
      cveIds: s.cveIds,
      summary: s.summary ? truncate(s.summary, 200) : undefined,
    }));
  if (topSignals.length > 0) {
    fs.writeFileSync(
      path.join(TMP, "ai", "trend-input.json"),
      JSON.stringify({ signals: topSignals, todaysCveIds: selected.map((r) => r.id) }, null, 2),
    );
  }

  // merge.mjs 用の全収集結果
  const collected = {
    date: todayJst,
    generatedAt: jstTimestamp(now),
    windowHours: WINDOW_HOURS,
    stats: {
      collectedTotal: records.size,
      nvd: nvdItems.length,
      jvn: jvnRes.ok ? jvnRes.items.length : 0,
      ghsa: ghsaRes.ok ? ghsaRes.items.length : 0,
      kevNewlyAdded: kev.newlyAdded.length,
      trendSignals: trendRes.signals.length,
      stackMatched,
      sourceErrors,
    },
    selected: selected.map((r) => ({ ...r })),
    lowPriority: lowPriority.map((r) => ({
      id: r.id,
      score: r.cvss?.score ?? null,
      severity: r.cvss?.severity ?? severityFromScore(r.cvss?.score),
      titleEn: truncate(r.titleEn, 100),
      sources: r.sources,
    })),
  };
  fs.writeFileSync(path.join(TMP, "collected.json"), JSON.stringify(collected, null, 2));
  console.log(`tmp/collected.json 書き出し完了`);

  if (sourceErrors.length > 0) {
    console.warn(`ソースエラー (${sourceErrors.length}件):`);
    for (const e of sourceErrors) console.warn(`  - ${e}`);
  }
  // 全ソース失敗時のみ異常終了
  const coreOk = [nvdRes, jvnRes, kevRes, ghsaRes].some((r) => r.ok);
  if (!coreOk) {
    console.error("全コアソースの取得に失敗しました");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
