// SNS・コミュニティの話題シグナル収集
//   - Mastodon (mastodon.social) 公開ハッシュタグタイムライン (認証不要)
//   - Hacker News Algolia search_by_date
//   - セキュリティニュースRSS (The Hacker News / BleepingComputer / JPCERT)
//   - X (Twitter) ウェブ経由 (x.mjs)

import { XMLParser } from "fast-xml-parser";
import { fetchJson, fetchText, extractCveIds, stripHtml, truncate, runSource } from "./util.mjs";
import { fetchXSignals } from "./x.mjs";

const MASTODON_TAGS = ["cve", "vulnerability", "infosec"];
const HN_QUERIES = ["CVE", "vulnerability", "exploit"];
const RSS_FEEDS = [
  { key: "rss:thn", name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { key: "rss:bleeping", name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { key: "rss:jpcert", name: "JPCERT/CC", url: "https://www.jpcert.or.jp/rss/jpcert.rdf" },
];

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@_" });

function asArray(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

async function fetchMastodon(windowStart) {
  const signals = [];
  for (const tag of MASTODON_TAGS) {
    const statuses = await fetchJson(
      `https://mastodon.social/api/v1/timelines/tag/${tag}?limit=40`,
    );
    for (const s of statuses) {
      if (new Date(s.created_at) < windowStart) continue;
      const text = stripHtml(s.content);
      signals.push({
        source: "mastodon",
        title: truncate(text, 200),
        url: s.url,
        date: s.created_at,
        engagement: (s.reblogs_count ?? 0) + (s.favourites_count ?? 0),
        cveIds: extractCveIds(text),
      });
    }
  }
  // タグ重複を URL で排除
  const seen = new Set();
  return signals.filter((s) => !seen.has(s.url) && seen.add(s.url));
}

async function fetchHackerNews(windowStart) {
  const since = Math.floor(windowStart.getTime() / 1000);
  const signals = [];
  const seen = new Set();
  for (const query of HN_QUERIES) {
    const params = new URLSearchParams({
      tags: "story",
      query,
      hitsPerPage: "100",
      numericFilters: `created_at_i>${since}`,
    });
    const data = await fetchJson(`https://hn.algolia.com/api/v1/search_by_date?${params}`);
    for (const hit of data.hits ?? []) {
      if (seen.has(hit.objectID)) continue;
      seen.add(hit.objectID);
      const text = `${hit.title ?? ""} ${hit.url ?? ""}`;
      signals.push({
        source: "hn",
        title: hit.title ?? "",
        url: `https://news.ycombinator.com/item?id=${hit.objectID}`,
        date: hit.created_at,
        engagement: (hit.points ?? 0) + (hit.num_comments ?? 0),
        cveIds: extractCveIds(text),
      });
    }
  }
  return signals;
}

/** RSS 2.0 (channel>item) と RDF/RSS 1.0 (rdf:RDF>item) の両対応 */
export function parseFeedItems(xml) {
  const doc = parser.parse(xml);
  if (doc.rss?.channel) return asArray(doc.rss.channel.item);
  if (doc["rdf:RDF"]) return asArray(doc["rdf:RDF"].item);
  return [];
}

async function fetchRssFeed(feed, windowStart) {
  const xml = await fetchText(feed.url);
  const signals = [];
  for (const item of parseFeedItems(xml)) {
    const dateStr = item.pubDate ?? item["dc:date"] ?? item["dcterms:issued"] ?? null;
    const date = dateStr ? new Date(dateStr) : null;
    if (date && date < windowStart) continue;
    const title = typeof item.title === "object" ? (item.title["#text"] ?? "") : (item.title ?? "");
    const desc = stripHtml(
      typeof item.description === "object" ? (item.description["#text"] ?? "") : (item.description ?? ""),
    );
    signals.push({
      source: feed.key,
      title,
      url: item.link ?? "",
      date: date ? date.toISOString() : null,
      engagement: 0,
      cveIds: extractCveIds(`${title} ${desc}`),
      summary: truncate(desc, 300),
    });
  }
  return signals;
}

/**
 * 全トレンドソースを収集。
 * @returns {{ signals: object[], mentions: Map<string, object[]>, errors: string[] }}
 */
export async function fetchTrendSignals(windowStart) {
  const results = await Promise.all([
    runSource("mastodon", () => fetchMastodon(windowStart)),
    runSource("hackernews", () => fetchHackerNews(windowStart)),
    runSource("x", () => fetchXSignals(windowStart)),
    ...RSS_FEEDS.map((feed) => runSource(feed.key, () => fetchRssFeed(feed, windowStart))),
  ]);

  const signals = results.flatMap((r) => r.items);
  const errors = results.filter((r) => !r.ok).map((r) => `${r.name}: ${r.error}`);

  // CVE ID → 言及シグナル一覧
  const mentions = new Map();
  for (const s of signals) {
    for (const cveId of s.cveIds ?? []) {
      if (!mentions.has(cveId)) mentions.set(cveId, []);
      mentions.get(cveId).push({ source: s.source, title: s.title, url: s.url });
    }
  }
  return { signals, mentions, errors };
}
