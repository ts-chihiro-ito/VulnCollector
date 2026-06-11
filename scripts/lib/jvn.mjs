// JVN iPedia — MyJVN API (getVulnOverviewList, JVNRSS 3.2 / RDF XML)

import { XMLParser } from "fast-xml-parser";
import { fetchText, sleep } from "./util.mjs";

const BASE = "https://jvndb.jvn.jp/myjvn";
const PAGE_SIZE = 50;
const MAX_PAGES = 12; // 安全弁: 最大600件

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: false,
});

function asArray(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

/** JST基準のY/M/D (MyJVNはゼロ埋め不可の数値指定) */
function jstParts(date) {
  const s = date.toLocaleDateString("sv-SE", { timeZone: "Asia/Tokyo" }); // YYYY-MM-DD
  const [y, m, d] = s.split("-").map(Number);
  return { y, m, d };
}

function buildUrl(start, end, startItem) {
  const s = jstParts(start);
  const e = jstParts(end);
  const params = new URLSearchParams({
    method: "getVulnOverviewList",
    feed: "hnd",
    lang: "ja",
    rangeDatePublic: "n",
    rangeDatePublished: "n",
    rangeDateFirstPublished: "n",
    dateFirstPublishedStartY: String(s.y),
    dateFirstPublishedStartM: String(s.m),
    dateFirstPublishedStartD: String(s.d),
    dateFirstPublishedEndY: String(e.y),
    dateFirstPublishedEndM: String(e.m),
    dateFirstPublishedEndD: String(e.d),
    startItem: String(startItem),
    maxCountItem: String(PAGE_SIZE),
  });
  return `${BASE}?${params}`;
}

function parseItem(item) {
  const refs = asArray(item["sec:references"]).map((r) => ({
    id: typeof r === "object" ? (r["#text"] ?? r["@_id"] ?? "") : String(r),
    source: typeof r === "object" ? (r["@_source"] ?? "") : "",
  }));
  const cveRef = refs.find(
    (r) => r.source === "CVE" || /^CVE-\d{4}-\d{4,7}$/i.test(r.id),
  );
  const cvssRaw = asArray(item["sec:cvss"])[0];
  const cvss = cvssRaw
    ? {
        score: cvssRaw["@_score"] ? Number(cvssRaw["@_score"]) : null,
        severity: (cvssRaw["@_severity"] ?? "").toUpperCase() || null,
        vector: cvssRaw["@_vector"] ?? null,
        version: cvssRaw["@_version"] ?? null,
      }
    : null;
  const cpes = asArray(item["sec:cpe"])
    .map((c) => (typeof c === "object" ? (c["#text"] ?? c["@_vendor"] ?? "") : String(c)))
    .filter(Boolean);
  return {
    jvnId: item["sec:identifier"] ?? null,
    titleJa: item.title ?? "",
    link: item.link ?? "",
    description: item.description ?? "",
    issued: item["dcterms:issued"] ?? item["dc:date"] ?? null,
    cveId: cveRef ? cveRef.id.toUpperCase() : null,
    cvss,
    cpes,
  };
}

/** 期間内のJVN脆弱性対策情報を全ページ取得 */
export async function fetchJvnWindow(startDate, endDate) {
  const items = [];
  let startItem = 1;
  for (let page = 0; page < MAX_PAGES; page++) {
    const xml = await fetchText(buildUrl(startDate, endDate, startItem));
    const doc = parser.parse(xml);
    const rdf = doc["rdf:RDF"];
    if (!rdf) throw new Error("MyJVN: unexpected XML (no rdf:RDF root)");
    const status = rdf["status:Status"] ?? {};
    const errCd = status["@_errCd"];
    if (errCd) {
      throw new Error(`MyJVN error ${errCd}: ${status["@_errMsg"] ?? ""}`);
    }
    const pageItems = asArray(rdf.item).map(parseItem);
    items.push(...pageItems);
    const totalRes = Number(status["@_totalRes"] ?? pageItems.length);
    const totalResRet = Number(status["@_totalResRet"] ?? pageItems.length);
    const firstRes = Number(status["@_firstRes"] ?? startItem);
    if (firstRes + totalResRet - 1 >= totalRes || totalResRet === 0) break;
    startItem = firstRes + totalResRet;
    await sleep(1000); // 行儀よく
  }
  return items;
}
