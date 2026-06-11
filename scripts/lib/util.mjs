// 共通ユーティリティ: HTTP取得(タイムアウト+リトライ)、日付、CVE抽出

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 3;
const USER_AGENT =
  "VulnCollector/1.0 (+https://github.com/; vulnerability intelligence bot)";

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * fetch with timeout + exponential backoff retry (403/429/5xx/network).
 * @returns {Promise<Response>}
 */
export async function fetchWithRetry(url, options = {}) {
  const { retries = MAX_RETRIES, timeoutMs = DEFAULT_TIMEOUT_MS, ...rest } = options;
  const headers = { "User-Agent": USER_AGENT, ...(rest.headers ?? {}) };
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        ...rest,
        headers,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) return res;
      // リトライ対象: レート制限・一時障害
      if ([403, 429, 500, 502, 503, 504].includes(res.status) && attempt < retries) {
        lastError = new Error(`HTTP ${res.status} for ${url}`);
      } else {
        throw new Error(`HTTP ${res.status} for ${url}`);
      }
    } catch (err) {
      if (attempt >= retries) throw err;
      lastError = err;
    }
    await sleep(2 ** attempt * 2000);
  }
  throw lastError ?? new Error(`fetch failed: ${url}`);
}

export async function fetchJson(url, options = {}) {
  const res = await fetchWithRetry(url, options);
  return res.json();
}

export async function fetchText(url, options = {}) {
  const res = await fetchWithRetry(url, options);
  return res.text();
}

/** JSTの YYYY-MM-DD (sv-SE ロケールはISO形式を返す) */
export function jstDateString(date = new Date()) {
  return date.toLocaleDateString("sv-SE", { timeZone: "Asia/Tokyo" });
}

/** JSTのISO風タイムスタンプ (+09:00固定) */
export function jstTimestamp(date = new Date()) {
  const s = date.toLocaleString("sv-SE", { timeZone: "Asia/Tokyo" });
  return s.replace(" ", "T") + "+09:00";
}

/** NVD API用のISO日時 (+09:00オフセット付き) */
export function nvdDateTime(date) {
  const s = date.toLocaleString("sv-SE", { timeZone: "Asia/Tokyo" });
  return s.replace(" ", "T") + ".000+09:00";
}

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

/** テキストからCVE IDを重複なしで抽出(大文字正規化) */
export function extractCveIds(text) {
  if (!text) return [];
  const found = text.match(CVE_RE) ?? [];
  return [...new Set(found.map((id) => id.toUpperCase()))];
}

/** HTMLタグ除去 + エンティティの簡易デコード */
export function stripHtml(html) {
  if (!html) return "";
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

export function truncate(text, maxChars) {
  if (!text) return "";
  return text.length <= maxChars ? text : text.slice(0, maxChars) + "…";
}

/** ソースモジュール実行ラッパー: 失敗してもrunを止めない */
export async function runSource(name, fn) {
  try {
    const items = await fn();
    console.log(`[${name}] ok: ${Array.isArray(items) ? items.length : "?"} items`);
    return { ok: true, name, items, error: null };
  } catch (err) {
    console.warn(`[${name}] FAILED: ${err.message}`);
    return { ok: false, name, items: [], error: err.message };
  }
}
