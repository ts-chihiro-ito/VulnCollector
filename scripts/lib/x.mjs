// X (Twitter) ウェブ経由収集 — 公式APIは使わない
//   経路1: syndication.twitter.com の埋め込みウィジェット基盤 (__NEXT_DATA__ JSON)
//   経路2: Nitter インスタンスの RSS (インスタンスプールでフォールバック)
//   X は未ログインアクセスを強くブロックするためベストエフォート。
//   全経路失敗時は throw し、呼び出し側の runSource が sourceErrors に記録して他ソースで継続する。

import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractCveIds, stripHtml, truncate, sleep } from "./util.mjs";
import { parseFeedItems } from "./trends.mjs";

const CONFIG_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "x.json");

const BROWSER_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
};

function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) return null;
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

/**
 * node:https ベースの取得。
 * undici (fetch) はTLS/ヘッダ指紋でNitter系のボット対策に空応答を返されるため使わない。
 * @returns {Promise<string>} レスポンス本文 (200のみ。それ以外は throw)
 */
function httpGetText(url, headers, { timeoutMs = 20_000, redirects = 3 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers, timeout: timeoutMs }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume();
        resolve(httpGetText(new URL(res.headers.location, url).href, headers, { timeoutMs, redirects: redirects - 1 }));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("timeout", () => req.destroy(new Error(`timeout for ${url}`)));
    req.on("error", reject);
  });
}

function toSignal({ text, url, date, engagement }) {
  return {
    source: "x",
    title: truncate(text, 200),
    url,
    date,
    engagement,
    cveIds: extractCveIds(text),
  };
}

/** 経路1: syndication timeline-profile。__NEXT_DATA__ 不在 (ログイン壁等) は即 throw */
async function fetchViaSyndication(account, windowStart) {
  const html = await httpGetText(
    `https://syndication.twitter.com/srv/timeline-profile/screen-name/${account}`,
    BROWSER_HEADERS,
  );
  const m = html.match(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s);
  if (!m) throw new Error("__NEXT_DATA__ not found (blocked?)");
  const entries = JSON.parse(m[1])?.props?.pageProps?.timeline?.entries ?? [];
  const signals = [];
  for (const entry of entries) {
    const tweet = entry?.content?.tweet;
    if (!tweet?.created_at) continue;
    if (tweet.retweeted_status || tweet.retweeted) continue; // RTはノイズが多いので除外
    const date = new Date(tweet.created_at);
    if (Number.isNaN(date.getTime()) || date < windowStart) continue;
    const permalink = tweet.permalink ?? `/${account}/status/${tweet.id_str ?? ""}`;
    signals.push(
      toSignal({
        text: stripHtml(tweet.full_text ?? tweet.text ?? ""),
        url: `https://x.com${permalink}`,
        date: date.toISOString(),
        engagement:
          (tweet.favorite_count ?? 0) +
          (tweet.retweet_count ?? 0) +
          (tweet.quote_count ?? 0) +
          (tweet.reply_count ?? 0),
      }),
    );
  }
  return signals;
}

/** 経路2: Nitter RSS。Anubis等のボット対策はHTTP 200でHTMLを返すため本文のXML検証が必須 */
async function fetchViaNitter(account, windowStart, instance, userAgent) {
  const xml = await httpGetText(`${instance}/${account}/rss`, {
    "User-Agent": userAgent,
    Accept: "application/rss+xml, application/xml, text/xml, */*",
  });
  if (!xml.trimStart().startsWith("<?xml") || !xml.includes("<item>")) {
    throw new Error("not a valid RSS response (bot challenge?)");
  }
  const signals = [];
  for (const item of parseFeedItems(xml)) {
    const date = item.pubDate ? new Date(item.pubDate) : null;
    if (!date || Number.isNaN(date.getTime()) || date < windowStart) continue;
    const title = typeof item.title === "object" ? (item.title["#text"] ?? "") : (item.title ?? "");
    const desc = stripHtml(
      typeof item.description === "object" ? (item.description["#text"] ?? "") : (item.description ?? ""),
    );
    // RTを除外 (Nitter RSS は "RT by @xxx:" がタイトルに付く)
    if (/^RT by @/i.test(title)) continue;
    // Nitter URL を x.com に書き換え (フラグメント #m 除去)
    const nitterUrl = String(item.link ?? "");
    const xUrl = nitterUrl.replace(/^https?:\/\/[^/]+/, "https://x.com").replace(/#m$/, "");
    signals.push(
      toSignal({
        text: desc || title,
        url: xUrl,
        date: date.toISOString(),
        engagement: 0,
      }),
    );
  }
  return signals;
}

/**
 * 全アカウントのシグナルを収集。
 * ルートプローブ方式: 先頭アカウントで各経路を試し、最初に成功した経路を全アカウントに使う。
 */
export async function fetchXSignals(windowStart) {
  if (process.env.X_DISABLED === "1") {
    console.log("[x] X_DISABLED=1 のためスキップ");
    return [];
  }
  const config = loadConfig();
  if (!config?.accounts?.length) {
    console.log("[x] scripts/x.json なし/空のためスキップ");
    return [];
  }

  const accounts = config.accounts.slice(0, config.maxAccounts ?? 12);
  const delayMs = config.perAccountDelayMs ?? 1500;
  const userAgent = config.nitterUserAgent ?? BROWSER_HEADERS["User-Agent"];
  const routes = [
    { name: "syndication", fn: (a) => fetchViaSyndication(a, windowStart) },
    ...(config.nitterInstances ?? []).map((instance) => ({
      name: `nitter(${new URL(instance).host})`,
      fn: (a) => fetchViaNitter(a, windowStart, instance, userAgent),
    })),
  ];

  const routeErrors = [];
  for (const route of routes) {
    // プローブ: 先頭アカウントで経路の生死を確認
    let probeSignals;
    try {
      probeSignals = await route.fn(accounts[0]);
    } catch (err) {
      routeErrors.push(`${route.name}: ${err.message}`);
      continue;
    }
    const signals = [...probeSignals];
    for (const account of accounts.slice(1)) {
      await sleep(delayMs);
      try {
        signals.push(...(await route.fn(account)));
      } catch (err) {
        console.warn(`[x] ${account} via ${route.name}: ${err.message}`);
      }
    }
    console.log(`[x] route=${route.name}: ${signals.length} signals`);
    return signals;
  }
  throw new Error(`全経路失敗 (${routeErrors.join(" / ")})`);
}
