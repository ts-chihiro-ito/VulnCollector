// ソース横断マージ(CVE IDキー)、事前フィルタ、ランキング、AIバッチ生成

import fs from "node:fs";
import path from "node:path";
import { truncate, isRecentCveId } from "./util.mjs";
import { severityFromScore } from "./nvd.mjs";

/**
 * 全ソースをCVE ID(無ければGHSA/ZDI-CAN ID)でマージした統合レコードを作る。
 * @returns {Map<string, object>}
 */
export function mergeSources({
  nvdItems,
  jvnItems,
  ghsaItems,
  zdiItems = [],
  kev,
  mentions,
  trustedTrendSources = [],
  maxTrendPromoted = 10,
}) {
  const records = new Map();

  const ensure = (id) => {
    if (!records.has(id)) {
      records.set(id, {
        id,
        sources: [],
        kev: false,
        kevInfo: null,
        cvss: null,
        titleEn: "",
        description: "",
        jvnId: null,
        jvnTitleJa: null,
        ghsaId: null,
        packages: [],
        packageRefs: [],
        cpes: [],
        stackMatch: null,
        zdi: null,
        breaking: false,
        published: null,
        references: [],
        trendMentions: [],
      });
    }
    return records.get(id);
  };

  for (const item of nvdItems) {
    const r = ensure(item.id);
    r.sources.push("nvd");
    r.description = item.description;
    r.titleEn = truncate(item.description, 120);
    r.cvss = item.cvss ?? r.cvss;
    r.cpes.push(...(item.cpes ?? []));
    r.published = item.published ?? r.published;
    r.references.push(...item.references.slice(0, 5).map((url) => ({ url, label: "参考情報" })));
    r.references.push({ url: `https://nvd.nist.gov/vuln/detail/${item.id}`, label: "NVD" });
  }

  for (const item of jvnItems) {
    const id = item.cveId ?? item.jvnId;
    if (!id) continue;
    const r = ensure(id);
    r.sources.push("jvn");
    r.jvnId = item.jvnId;
    r.jvnTitleJa = item.titleJa;
    if (!r.description) r.description = item.description;
    if (!r.titleEn) r.titleEn = truncate(item.titleJa, 120);
    // NVDのCVSSを優先、無ければJVN
    if (!r.cvss && item.cvss?.score != null) {
      r.cvss = {
        score: item.cvss.score,
        severity: item.cvss.severity ?? severityFromScore(item.cvss.score),
        vector: item.cvss.vector,
        version: item.cvss.version,
      };
    }
    r.cpes.push(...item.cpes);
    if (item.link) r.references.push({ url: item.link, label: "JVN" });
    if (!r.published && item.issued) r.published = item.issued;
  }

  for (const item of ghsaItems) {
    const id = item.cveId ?? item.ghsaId;
    const r = ensure(id);
    r.sources.push("ghsa");
    r.ghsaId = item.ghsaId;
    if (!r.description) r.description = item.summary;
    if (!r.titleEn) r.titleEn = truncate(item.summary, 120);
    if (!r.cvss && item.cvss?.score != null) {
      r.cvss = {
        score: item.cvss.score,
        severity: severityFromScore(item.cvss.score),
        vector: item.cvss.vector,
        version: item.cvss.version,
      };
    }
    r.packages.push(...item.packages);
    r.packageRefs.push(...(item.packageRefs ?? []));
    if (item.permalink) r.references.push({ url: item.permalink, label: "GHSA" });
    if (!r.published && item.publishedAt) r.published = item.publishedAt;
  }

  for (const item of zdiItems) {
    // CVE採番済みなら各CVEキー、無ければZDI-CAN IDキー (GHSAフォールバックと同型)
    const ids = item.cveIds.length > 0 ? item.cveIds : [item.zdiCanId];
    for (const id of ids) {
      const r = ensure(id);
      r.sources.push("zdi");
      r.zdi = { id: item.zdiId, canId: item.zdiCanId, status: item.status, dueDate: item.dueDate };
      if (!r.description) r.description = item.description;
      if (!r.titleEn) r.titleEn = truncate(item.title, 120);
      if (!r.cvss && item.cvss?.score != null) r.cvss = item.cvss;
      if (item.link) r.references.push({ url: item.link, label: "ZDI" });
      if (!r.published && item.published) r.published = item.published;
    }
  }

  // KEVフラグ (全カタログ照合)
  for (const r of records.values()) {
    const kevEntry = kev.all.get(r.id);
    if (kevEntry) {
      r.kev = true;
      r.kevInfo = kevEntry;
      if (!r.sources.includes("kev")) r.sources.push("kev");
      if (!r.titleEn) r.titleEn = kevEntry.vulnerabilityName ?? "";
    }
  }

  // トレンド言及: 既存レコードへは注釈、未存在CVEは「速報」レコードへ昇格
  // 昇格の信頼性ガード: 直近年のCVE かつ 信頼フィード(キュレート済み報道/CERT)の言及が必須。
  // Mastodon/HN単独では昇格させない(裏付けシグナルとしてのみ扱う)
  const trusted = new Set(trustedTrendSources);
  const unmatched = [];
  for (const [cveId, list] of mentions) {
    if (records.has(cveId)) {
      records.get(cveId).trendMentions = list.slice(0, 5);
    } else {
      unmatched.push([cveId, list]);
    }
  }
  unmatched.sort((a, b) => b[1].length - a[1].length); // Map挿入順でなく言及数順で上限適用
  let promoted = 0;
  for (const [cveId, list] of unmatched) {
    if (promoted >= maxTrendPromoted) break;
    if (!isRecentCveId(cveId)) continue;
    const trustedMentions = list.filter((m) => trusted.has(m.source));
    if (trustedMentions.length === 0) continue;
    const r = ensure(cveId);
    r.sources.push("trend");
    r.trendMentions = list.slice(0, 5);
    r.titleEn = truncate(trustedMentions[0].title, 120);
    r.description = [...new Set(list.map((m) => m.title))].slice(0, 3).join(" / ");
    r.references = trustedMentions.slice(0, 3).map((m) => ({ url: m.url, label: "報道" }));
    promoted++;
  }

  // 整理: severity補完・参照重複排除・速報判定
  for (const r of records.values()) {
    if (r.cvss && !r.cvss.severity) r.cvss.severity = severityFromScore(r.cvss.score);
    const seen = new Set();
    r.references = r.references.filter((ref) => ref.url && !seen.has(ref.url) && seen.add(ref.url)).slice(0, 8);
    r.sources = [...new Set(r.sources)];
    // 速報: 確立DB (NVD/JVN/GHSA/KEV) のいずれにも未登録 (バックフィル成功分はnvdが付くのでfalseになる)
    r.breaking = !r.sources.some((s) => s !== "zdi" && s !== "trend");
  }

  return records;
}

/** 過去N日の日次ファイルから分析済みCVE IDを収集 (クロスデイ重複排除用) */
export function loadRecentlyAnalyzedIds(dataDir, todayJst, days = 3) {
  const ids = new Set();
  const today = new Date(todayJst + "T00:00:00+09:00");
  for (let i = 1; i <= days; i++) {
    const d = new Date(today.getTime() - i * 86400_000);
    const file = path.join(dataDir, "vulns", d.toLocaleDateString("sv-SE", { timeZone: "Asia/Tokyo" }) + ".json");
    if (!fs.existsSync(file)) continue;
    try {
      const day = JSON.parse(fs.readFileSync(file, "utf8"));
      for (const v of day.vulns ?? []) if (isRealAnalysis(v)) ids.add(v.id);
    } catch {
      // 壊れたファイルは無視
    }
  }
  return ids;
}

/** 本物のAI分析かどうか (MOCK_AI生成分は再利用しない) */
export function isRealAnalysis(v) {
  return v.analyzed && !String(v.titleJa ?? "").startsWith("[MOCK]");
}

/** 当日ファイルの分析済みエントリ (同日再実行でAI消費を抑える) */
export function loadTodayAnalyzed(dataDir, todayJst) {
  const file = path.join(dataDir, "vulns", todayJst + ".json");
  if (!fs.existsSync(file)) return new Map();
  try {
    const day = JSON.parse(fs.readFileSync(file, "utf8"));
    return new Map((day.vulns ?? []).filter(isRealAnalysis).map((v) => [v.id, v]));
  } catch {
    return new Map();
  }
}

/**
 * 採用条件: KEV / スタックマッチ / CVSS>=minCvss / JVN掲載 / トレンド言及 / キーワード一致
 * ランキング: KEV → スタックマッチ(package > cpe/keyword) → トレンド言及数 → CVSS → JVN有無
 */
export function selectForAnalysis(records, watchlist, { excludeIds = new Set(), alreadyAnalyzed = new Map() } = {}) {
  const keywords = watchlist.keywords.map((k) => k.toLowerCase());
  // スタックマッチのみで採用される件数の上限 (依存が多い日に分析枠を食い潰さないため)
  const maxStackMatched = watchlist.stack?.maxMatched ?? 16;

  const qualifiesGeneral = (r) => {
    if (r.kev) return true;
    if ((r.cvss?.score ?? 0) >= watchlist.minCvss) return true;
    if (r.sources.includes("jvn")) return true;
    if (r.trendMentions.length > 0) return true;
    const haystack = `${r.titleEn} ${r.description} ${r.packages.join(" ")} ${r.cpes.join(" ")}`.toLowerCase();
    return keywords.some((k) => haystack.includes(k));
  };

  const candidates = [];
  const lowPriority = [];
  let stackOnly = 0;
  for (const r of records.values()) {
    if (excludeIds.has(r.id) && !alreadyAnalyzed.has(r.id)) continue; // 過去日に分析済み
    if (qualifiesGeneral(r)) {
      candidates.push(r);
    } else if (r.stackMatch && stackOnly < maxStackMatched) {
      stackOnly++;
      candidates.push(r);
    } else {
      lowPriority.push(r);
    }
  }

  const stackRank = (r) => (r.stackMatch ? (r.stackMatch.matchType === "package" ? 2 : 1) : 0);

  candidates.sort((a, b) => {
    if (a.kev !== b.kev) return a.kev ? -1 : 1;
    if (a.breaking !== b.breaking) return a.breaking ? -1 : 1; // 速報/ゼロデイはKEVに次ぐ優先
    const sr = stackRank(b) - stackRank(a);
    if (sr !== 0) return sr;
    const tm = b.trendMentions.length - a.trendMentions.length;
    if (tm !== 0) return tm;
    const cs = (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0);
    if (cs !== 0) return cs;
    return (b.sources.includes("jvn") ? 1 : 0) - (a.sources.includes("jvn") ? 1 : 0);
  });

  const selected = candidates.slice(0, watchlist.maxAnalyzed);
  lowPriority.push(...candidates.slice(watchlist.maxAnalyzed));
  return { selected, lowPriority };
}

/** AI入力用に1件を軽量化 (入力トークン節約) */
export function toAiInput(r) {
  return {
    id: r.id,
    title: r.jvnTitleJa ?? r.titleEn,
    description: truncate(r.description, 500),
    cvss: r.cvss ? `${r.cvss.score} (${r.cvss.severity}) ${r.cvss.vector ?? ""}`.trim() : "不明",
    kev: r.kev
      ? {
          shortDescription: r.kevInfo?.shortDescription ?? null,
          requiredAction: r.kevInfo?.requiredAction ?? null,
          knownRansomwareCampaignUse: r.kevInfo?.knownRansomwareCampaignUse ?? null,
        }
      : null,
    products: [...new Set([...r.packages, ...r.cpes])].slice(0, 5),
    breaking: r.breaking || undefined, // 公的DB未登録の速報
    zdi: r.zdi ? { status: r.zdi.status, canId: r.zdi.canId, dueDate: r.zdi.dueDate } : undefined,
    stack: r.stackMatch ? { via: r.stackMatch.matchType, matched: r.stackMatch.matched } : null,
    trendMentions: r.trendMentions.slice(0, 3).map((m) => m.title),
    references: r.references.slice(0, 3).map((ref) => ref.url),
  };
}

/** 選定済みレコードをAIバッチに分割。既分析IDはスキップ */
export function buildBatches(selected, watchlist, alreadyAnalyzed) {
  const toAnalyze = selected.filter((r) => !alreadyAnalyzed.has(r.id));
  const batches = [];
  const limit = watchlist.maxBatches * watchlist.batchSize;
  const target = toAnalyze.slice(0, limit);
  for (let i = 0; i < target.length; i += watchlist.batchSize) {
    batches.push(target.slice(i, i + watchlist.batchSize).map(toAiInput));
  }
  return batches;
}
