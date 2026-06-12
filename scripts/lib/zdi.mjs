// Zero Day Initiative (Trend Micro) アドバイザリRSS
//   - published: 公開済みアドバイザリ (description末尾にCVE ID + CVSSスコア)
//   - upcoming: ベンダー報告済み・パッチ前のゼロデイ (CVE無し、ZDI-CAN IDのみ。
//               pubDate=ベンダー報告日なので窓フィルタで新規報告分だけ拾える)

import { fetchText, extractCveIds, stripHtml, truncate } from "./util.mjs";
import { severityFromScore } from "./nvd.mjs";
import { parseFeedItems } from "./trends.mjs";

const PUBLISHED_URL = "https://www.zerodayinitiative.com/rss/published/";
const UPCOMING_URL = "https://www.zerodayinitiative.com/rss/upcoming/";

const ZDI_ID_RE = /^(ZDI-\d{2}-\d+)/;
const ZDI_CAN_RE = /ZDI-CAN-\d+/;
// published: "The ZDI has assigned a CVSS rating of 7.8" / upcoming: "A CVSS score 8.8"
const CVSS_SCORE_RE = /CVSS (?:rating of|score) (\d+(?:\.\d+)?)/;
const CVSS_VECTOR_RE = /AV:[A-Z](?:\/[A-Z]{1,3}:[A-Z]+)+/;
const DUE_DATE_RE = /given until (\d{4}-\d{2}-\d{2})/;

/** fast-xml-parser は属性付きノードをオブジェクト化するため #text を剥がす */
function textOf(node) {
  if (node == null) return "";
  return typeof node === "object" ? String(node["#text"] ?? "") : String(node);
}

function parseZdiFeed(xml, status, windowStart) {
  const items = [];
  for (const item of parseFeedItems(xml)) {
    const pubDate = item.pubDate ? new Date(item.pubDate) : null;
    if (!pubDate || Number.isNaN(pubDate.getTime()) || pubDate < windowStart) continue;

    const rawTitle = textOf(item.title);
    const description = stripHtml(textOf(item.description));
    const guid = textOf(item.guid);

    const zdiId = rawTitle.match(ZDI_ID_RE)?.[1] ?? null;
    const zdiCanId = guid.match(ZDI_CAN_RE)?.[0] ?? rawTitle.match(ZDI_CAN_RE)?.[0] ?? null;
    if (!zdiId && !zdiCanId) continue; // ID不明のものはレコード化できない

    // CVSS抽出失敗は許容 (タイトル+IDだけでレコード成立)
    const score = Number(description.match(CVSS_SCORE_RE)?.[1] ?? NaN);
    const vector = description.match(CVSS_VECTOR_RE)?.[0] ?? null;
    const cvss = Number.isFinite(score)
      ? { score, severity: severityFromScore(score), vector, version: null }
      : null;

    const link = textOf(item.link);
    items.push({
      zdiId,
      zdiCanId: zdiCanId ?? zdiId,
      status,
      cveIds: extractCveIds(description),
      title: truncate(rawTitle.replace(/^ZDI(?:-CAN)?-[\d-]+:\s*/, ""), 200),
      description,
      cvss,
      published: pubDate.toISOString(),
      dueDate: status === "upcoming" ? (description.match(DUE_DATE_RE)?.[1] ?? null) : null,
      // upcomingのlinkは一覧ページ固定なので個別URLとしては使わない
      link: status === "published" && link ? link : null,
    });
  }
  return items;
}

/** 窓内に公開されたZDIアドバイザリ (CVE採番済みが多い) */
export async function fetchZdiPublished(windowStart) {
  const xml = await fetchText(PUBLISHED_URL);
  return parseZdiFeed(xml, "published", windowStart);
}

/** 窓内にベンダー報告されたパッチ前ゼロデイ (CVE無し) */
export async function fetchZdiUpcoming(windowStart) {
  const xml = await fetchText(UPCOMING_URL);
  return parseZdiFeed(xml, "upcoming", windowStart);
}
