// GitHub Security Advisories — GraphQL API

import { fetchJson } from "./util.mjs";

const ENDPOINT = "https://api.github.com/graphql";
const MAX_PAGES = 3; // 100件×3 = 日次量に対して十分

const QUERY = /* GraphQL */ `
  query ($since: DateTime!, $after: String) {
    securityAdvisories(
      first: 100
      publishedSince: $since
      orderBy: { field: PUBLISHED_AT, direction: DESC }
      classifications: [GENERAL]
      after: $after
    ) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        ghsaId
        summary
        severity
        publishedAt
        withdrawnAt
        permalink
        identifiers {
          type
          value
        }
        references {
          url
        }
        cvssSeverities {
          cvssV3 {
            score
            vectorString
          }
          cvssV4 {
            score
            vectorString
          }
        }
        vulnerabilities(first: 10) {
          nodes {
            package {
              ecosystem
              name
            }
            vulnerableVersionRange
            firstPatchedVersion {
              identifier
            }
          }
        }
      }
    }
  }
`;

function normalize(node) {
  const cve = node.identifiers?.find((i) => i.type === "CVE")?.value ?? null;
  const v4 = node.cvssSeverities?.cvssV4;
  const v3 = node.cvssSeverities?.cvssV3;
  const cvssSrc = v4?.score ? { ...v4, version: "4.0" } : v3?.score ? { ...v3, version: "3.1" } : null;
  const packages = (node.vulnerabilities?.nodes ?? []).map((p) => {
    const range = p.vulnerableVersionRange ?? "";
    const patched = p.firstPatchedVersion?.identifier;
    const eco = p.package?.ecosystem ? `${p.package.ecosystem.toLowerCase()}: ` : "";
    return `${eco}${p.package?.name ?? "?"} ${range}${patched ? ` (修正: ${patched})` : ""}`.trim();
  });
  // 構造化版 (スタックマッチ用)。packages は表示用文字列なのでそのまま残す
  const packageRefs = (node.vulnerabilities?.nodes ?? [])
    .filter((p) => p.package?.name)
    .map((p) => ({
      ecosystem: (p.package.ecosystem ?? "").toLowerCase(),
      name: p.package.name,
      range: p.vulnerableVersionRange ?? null,
      patched: p.firstPatchedVersion?.identifier ?? null,
    }));
  return {
    ghsaId: node.ghsaId,
    cveId: cve ? cve.toUpperCase() : null,
    summary: node.summary ?? "",
    severity: node.severity ?? null,
    publishedAt: node.publishedAt ?? null,
    permalink: node.permalink ?? null,
    references: (node.references ?? []).map((r) => r.url),
    cvss: cvssSrc
      ? { score: cvssSrc.score, severity: null, vector: cvssSrc.vectorString ?? null, version: cvssSrc.version }
      : null,
    packages,
    packageRefs,
  };
}

/** 期間内に公開されたGeneral Advisoriesを取得 (withdrawn除外) */
export async function fetchGhsaWindow(since, token) {
  if (!token) throw new Error("GITHUB_TOKEN is required for GHSA GraphQL");
  const items = [];
  let after = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const body = JSON.stringify({
      query: QUERY,
      variables: { since: since.toISOString(), after },
    });
    const data = await fetchJson(ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body,
    });
    if (data.errors?.length) {
      throw new Error(`GHSA GraphQL: ${data.errors[0].message}`);
    }
    const conn = data.data?.securityAdvisories;
    if (!conn) throw new Error("GHSA GraphQL: empty response");
    for (const node of conn.nodes ?? []) {
      if (node.withdrawnAt) continue;
      items.push(normalize(node));
    }
    if (!conn.pageInfo?.hasNextPage) break;
    after = conn.pageInfo.endCursor;
  }
  return items;
}
