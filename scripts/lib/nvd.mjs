// NVD API 2.0 クライアント
// レート制限: APIキー無し 5req/30s → リクエスト間6秒スリープ

import { fetchJson, sleep, nvdDateTime } from "./util.mjs";

const BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/";
const RESULTS_PER_PAGE = 2000;
const SLEEP_MS = 6000;

function apiHeaders() {
  const key = process.env.NVD_API_KEY;
  return key ? { apiKey: key } : {};
}

/** CVSSメトリクスを v4.0 → v3.1 → v3.0 → v2 の優先順で選ぶ。同版ではPrimary優先 */
export function pickCvss(metrics) {
  if (!metrics) return null;
  const order = [
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV30", "3.0"],
    ["cvssMetricV2", "2.0"],
  ];
  for (const [key, version] of order) {
    const list = metrics[key];
    if (!list?.length) continue;
    const entry = list.find((m) => m.type === "Primary") ?? list[0];
    const d = entry.cvssData ?? {};
    return {
      score: d.baseScore ?? null,
      severity: (d.baseSeverity ?? entry.baseSeverity ?? severityFromScore(d.baseScore)) || "UNKNOWN",
      vector: d.vectorString ?? null,
      version,
    };
  }
  return null;
}

export function severityFromScore(score) {
  if (score == null) return "UNKNOWN";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

function normalize(cve) {
  const en = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";
  return {
    id: cve.id,
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    vulnStatus: cve.vulnStatus ?? null,
    description: en,
    cvss: pickCvss(cve.metrics),
    references: (cve.references ?? []).map((r) => r.url),
  };
}

/** 期間内に公開されたCVE一覧を全ページ取得 */
export async function fetchNvdWindow(startDate, endDate) {
  const items = [];
  let startIndex = 0;
  let totalResults = Infinity;
  while (startIndex < totalResults) {
    const params = new URLSearchParams({
      pubStartDate: nvdDateTime(startDate),
      pubEndDate: nvdDateTime(endDate),
      resultsPerPage: String(RESULTS_PER_PAGE),
      startIndex: String(startIndex),
    });
    const data = await fetchJson(`${BASE}?${params}`, { headers: apiHeaders() });
    totalResults = data.totalResults ?? 0;
    for (const v of data.vulnerabilities ?? []) items.push(normalize(v.cve));
    startIndex += data.resultsPerPage ?? RESULTS_PER_PAGE;
    if (startIndex < totalResults) await sleep(SLEEP_MS);
  }
  return items;
}

/** CVE ID指定の個別取得 (KEV追加分のバックフィル用)。見つからなければnull */
export async function fetchNvdById(cveId) {
  const data = await fetchJson(`${BASE}?cveId=${encodeURIComponent(cveId)}`, {
    headers: apiHeaders(),
  });
  const cve = data.vulnerabilities?.[0]?.cve;
  return cve ? normalize(cve) : null;
}

export { SLEEP_MS as NVD_SLEEP_MS };
