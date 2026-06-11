// CISA Known Exploited Vulnerabilities カタログ

import { fetchJson } from "./util.mjs";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/**
 * @returns {{ all: Map<string, object>, newlyAdded: object[] }}
 *   all: cveID → KEVエントリ(掲載フラグ用), newlyAdded: dateAddedが窓内のもの
 */
export async function fetchKev(windowStart) {
  const data = await fetchJson(KEV_URL);
  const all = new Map();
  const newlyAdded = [];
  for (const v of data.vulnerabilities ?? []) {
    const entry = {
      cveId: v.cveID,
      vendorProject: v.vendorProject,
      product: v.product,
      vulnerabilityName: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      shortDescription: v.shortDescription,
      requiredAction: v.requiredAction,
      dueDate: v.dueDate,
      knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
    };
    all.set(v.cveID, entry);
    if (v.dateAdded && new Date(v.dateAdded + "T00:00:00Z") >= windowStart) {
      newlyAdded.push(entry);
    }
  }
  return { all, newlyAdded };
}
