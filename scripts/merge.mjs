#!/usr/bin/env node
// AI出力マージ:
//   tmp/collected.json + AI出力(環境変数 AI_OUT_1..N / AI_OUT_TRENDS が response-file のパス)
//   → data/vulns/YYYY-MM-DD.json + data/index.json
//
//   - MOCK_AI=1 でAI出力をスキーマ準拠のダミーに置換 (ローカルE2E用)
//   - AIバッチのパース失敗は該当件を「未分析」に降格してrunを継続
//   - 同日再実行: 既存ファイルの分析済みエントリを引き継ぎ (冪等)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { jstTimestamp } from "./lib/util.mjs";
import { isRealAnalysis } from "./lib/filter.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TMP = path.join(ROOT, "tmp");
const DATA_DIR = path.join(ROOT, "data");
const MAX_BATCHES = 6;

function readJsonSafe(file, label) {
  if (!file || !fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    console.warn(`[merge] ${label} のパースに失敗: ${err.message}`);
    return null;
  }
}

function mockAnalysis(input) {
  return {
    id: input.id,
    titleJa: `[MOCK] ${input.title || input.id}`.slice(0, 60),
    summaryJa: `[MOCK] ${String(input.description ?? "").slice(0, 120)}`,
    impactJa: "[MOCK] 影響のプレースホルダ",
    recommendedActionJa: "[MOCK] ベンダーのアドバイザリを確認し、修正版へ更新してください。",
    priority: input.kev ? "high" : "medium",
    priorityReasonJa: "[MOCK] モック生成のため参考値",
    affectedProducts: input.products ?? [],
  };
}

/** AIバッチ出力を集める。返り値: Map<cveId, analysis> */
function collectAiResults() {
  const results = new Map();
  for (let i = 1; i <= MAX_BATCHES; i++) {
    const batchFile = path.join(TMP, "ai", `batch-${i}.json`);
    if (!fs.existsSync(batchFile)) continue;
    const batch = readJsonSafe(batchFile, `batch-${i}.json`);
    const inputIds = new Set((batch?.items ?? []).map((it) => it.id));

    let output;
    if (process.env.MOCK_AI === "1") {
      output = { items: (batch?.items ?? []).map(mockAnalysis) };
    } else {
      output = readJsonSafe(process.env[`AI_OUT_${i}`], `AI_OUT_${i}`);
    }
    if (!output?.items) {
      console.warn(`[merge] バッチ${i}: AI出力なし → ${inputIds.size}件を未分析に降格`);
      continue;
    }
    let accepted = 0;
    for (const item of output.items) {
      const id = String(item.id ?? "").toUpperCase();
      // ハルシネーション対策: 入力に存在するIDのみ受理
      if (!inputIds.has(id) && !inputIds.has(item.id)) continue;
      results.set(inputIds.has(id) ? id : item.id, item);
      accepted++;
    }
    console.log(`[merge] バッチ${i}: ${accepted}/${inputIds.size}件受理`);
  }
  return results;
}

function collectTrends(collected) {
  if (process.env.MOCK_AI === "1") {
    const input = readJsonSafe(path.join(TMP, "ai", "trend-input.json"), "trend-input.json");
    if (!input) return [];
    return (input.signals ?? []).slice(0, 3).map((s, i) => ({
      topic: `[MOCK] トピック${i + 1}: ${s.title.slice(0, 40)}`,
      summaryJa: "[MOCK] トレンド要約のプレースホルダ",
      relatedCveIds: s.cveIds ?? [],
      sourceUrls: [s.url].filter(Boolean),
    }));
  }
  const output = readJsonSafe(process.env.AI_OUT_TRENDS, "AI_OUT_TRENDS");
  if (output?.topics) return output.topics;
  // AI失敗時は当日既存のトレンドを引き継ぐ
  const existing = readJsonSafe(path.join(DATA_DIR, "vulns", `${collected.date}.json`), "today existing");
  return existing?.trends ?? [];
}

function main() {
  const collected = readJsonSafe(path.join(TMP, "collected.json"), "collected.json");
  if (!collected) {
    console.error("tmp/collected.json がありません。先に collect.mjs を実行してください。");
    process.exit(1);
  }

  const todayFile = path.join(DATA_DIR, "vulns", `${collected.date}.json`);
  const existing = readJsonSafe(todayFile, "today existing");
  const existingAnalyzed = new Map(
    (existing?.vulns ?? []).filter(isRealAnalysis).map((v) => [v.id, v]),
  );

  const aiResults = collectAiResults();

  const vulns = collected.selected.map((r) => {
    const ai = aiResults.get(r.id);
    const prev = existingAnalyzed.get(r.id);
    const base = {
      id: r.id,
      sources: r.sources,
      kev: r.kev,
      kevInfo: r.kevInfo,
      cvss: r.cvss,
      titleEn: r.titleEn,
      published: r.published,
      jvnId: r.jvnId,
      ghsaId: r.ghsaId,
      references: r.references,
      trendMentions: r.trendMentions,
    };
    if (ai) {
      return {
        ...base,
        analyzed: true,
        titleJa: ai.titleJa,
        summaryJa: ai.summaryJa,
        impactJa: ai.impactJa,
        recommendedActionJa: ai.recommendedActionJa,
        priority: ai.priority,
        priorityReasonJa: ai.priorityReasonJa,
        affectedProducts: ai.affectedProducts,
      };
    }
    if (prev) {
      // 同日再実行: 既存のAI分析を引き継ぎ (収集メタは最新に更新)
      return {
        ...base,
        analyzed: true,
        titleJa: prev.titleJa,
        summaryJa: prev.summaryJa,
        impactJa: prev.impactJa,
        recommendedActionJa: prev.recommendedActionJa,
        priority: prev.priority,
        priorityReasonJa: prev.priorityReasonJa,
        affectedProducts: prev.affectedProducts,
      };
    }
    return {
      ...base,
      analyzed: false,
      titleJa: r.jvnTitleJa ?? null,
      summaryJa: null,
      impactJa: null,
      recommendedActionJa: null,
      priority: null,
      priorityReasonJa: null,
      affectedProducts: [...new Set([...(r.packages ?? []), ...(r.cpes ?? [])])].slice(0, 5),
    };
  });

  // 優先度(high→medium→low→未分析)、次いでCVSS降順
  const prioRank = { high: 0, medium: 1, low: 2 };
  vulns.sort((a, b) => {
    const pa = a.priority != null ? prioRank[a.priority] : 3;
    const pb = b.priority != null ? prioRank[b.priority] : 3;
    if (pa !== pb) return pa - pb;
    return (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0);
  });

  const bySeverity = {};
  for (const v of vulns) {
    const sev = v.cvss?.severity ?? "UNKNOWN";
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
  }

  const day = {
    date: collected.date,
    generatedAt: jstTimestamp(),
    stats: {
      collectedTotal: collected.stats.collectedTotal,
      analyzed: vulns.filter((v) => v.analyzed).length,
      kevCount: vulns.filter((v) => v.kev).length,
      bySeverity,
      sourceErrors: collected.stats.sourceErrors,
    },
    vulns,
    lowPriority: collected.lowPriority,
    trends: collectTrends(collected),
  };

  fs.mkdirSync(path.join(DATA_DIR, "vulns"), { recursive: true });
  fs.writeFileSync(todayFile, JSON.stringify(day, null, 1) + "\n");
  console.log(`[merge] ${path.relative(ROOT, todayFile)} 書き出し (分析済み ${day.stats.analyzed}/${vulns.length}件)`);

  // index.json は data/vulns/*.json から再構築 (自己修復)
  const dates = fs
    .readdirSync(path.join(DATA_DIR, "vulns"))
    .filter((f) => /^\d{4}-\d{2}-\d{2}\.json$/.test(f))
    .sort()
    .reverse()
    .map((f) => {
      const d = readJsonSafe(path.join(DATA_DIR, "vulns", f), f);
      return d
        ? {
            date: d.date,
            analyzed: d.stats?.analyzed ?? 0,
            collectedTotal: d.stats?.collectedTotal ?? 0,
            kevCount: d.stats?.kevCount ?? 0,
            criticalCount: d.stats?.bySeverity?.CRITICAL ?? 0,
          }
        : null;
    })
    .filter(Boolean);
  fs.writeFileSync(
    path.join(DATA_DIR, "index.json"),
    JSON.stringify({ updatedAt: jstTimestamp(), dates }, null, 1) + "\n",
  );
  console.log(`[merge] data/index.json 更新 (${dates.length}日分)`);
}

main();
