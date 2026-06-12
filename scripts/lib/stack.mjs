// 自プロジェクト(このリポジトリ)の技術スタック解析とマッチング
//   - リポジトリ直下の package.json / composer.json から依存パッケージを抽出
//   - watchlist.json の stack.keywords (MySQL等ミドルウェア) と合わせて脆弱性レコードと照合
//   - マッチ確度: package (GHSA完全一致) > cpe > keyword

import fs from "node:fs";
import path from "node:path";

function readJsonSafe(file) {
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

/** ignorePackages の簡易glob (末尾 * の前方一致のみ対応) */
function isIgnored(name, patterns) {
  return patterns.some((p) =>
    p.endsWith("*") ? name.startsWith(p.slice(0, -1)) : name === p,
  );
}

/**
 * ルートのマニフェスト + watchlist.stack からスタック定義を構築。
 * @returns {{ packages: {ecosystem: string, name: string}[], keywords: string[] }}
 */
export function loadStack(rootDir, watchlist) {
  const conf = watchlist.stack ?? {};
  const ignore = conf.ignorePackages ?? [];
  const packages = [];
  const projectDir = path.join(rootDir, "scripts", "project");

  const pkg = readJsonSafe(path.join(projectDir, "package.json"));
  if (pkg) {
    const deps = {
      ...(pkg.dependencies ?? {}),
      ...(conf.includeDevDependencies ? (pkg.devDependencies ?? {}) : {}),
    };
    for (const name of Object.keys(deps)) {
      if (!isIgnored(name, ignore)) packages.push({ ecosystem: "npm", name });
    }
  }

  const composer = readJsonSafe(path.join(projectDir, "composer.json"));
  if (composer) {
    const deps = {
      ...(composer.require ?? {}),
      ...(conf.includeDevDependencies ? (composer["require-dev"] ?? {}) : {}),
    };
    for (const name of Object.keys(deps)) {
      // php本体・拡張・ライブラリ指定はパッケージではないので除外
      if (name === "php" || name.startsWith("ext-") || name.startsWith("lib-")) continue;
      if (!isIgnored(name, ignore)) packages.push({ ecosystem: "composer", name });
    }
  }

  const keywords = (conf.keywords ?? []).map((k) => String(k).toLowerCase()).filter(Boolean);
  console.log(`[stack] パッケージ ${packages.length}件 + キーワード ${keywords.length}件`);
  return { packages, keywords };
}

/** "cpe:2.3:a:oracle:mysql:8.0:..." → { vendor: "oracle", product: "mysql" } */
function cpeProduct(cpe) {
  const parts = String(cpe).split(":");
  return parts.length >= 5 ? { vendor: parts[3], product: parts[4] } : null;
}

/** npmスコープ除去: "@scope/name" → "name" */
function stripScope(name) {
  return name.includes("/") ? name.split("/").pop() : name;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 統合レコード1件をスタックと照合。
 * Tier 1 package: GHSAのecosystem+name完全一致 (確実)
 * Tier 2 cpe:     CPEのproduct部がキーワード or パッケージ名と一致
 * Tier 3 keyword: キーワードの単語境界一致 (titleEn + description)
 * 依存パッケージ名の説明文テキストマッチは誤検知が多いため行わない。
 * @returns {{ matchType: "package"|"cpe"|"keyword", matched: string[] } | null}
 */
export function matchStack(record, stack) {
  if (stack.packages.length === 0 && stack.keywords.length === 0) return null;

  const pkgHits = [];
  for (const ref of record.packageRefs ?? []) {
    if (
      stack.packages.some(
        (p) => p.ecosystem === ref.ecosystem && p.name.toLowerCase() === ref.name.toLowerCase(),
      )
    ) {
      pkgHits.push(`${ref.ecosystem}:${ref.name}`);
    }
  }
  if (pkgHits.length > 0) {
    return { matchType: "package", matched: [...new Set(pkgHits)].slice(0, 5) };
  }

  const cpeHits = [];
  for (const cpe of record.cpes ?? []) {
    const p = cpeProduct(cpe);
    if (!p?.product || p.product === "*") continue;
    if (stack.keywords.includes(p.product)) {
      cpeHits.push(p.product);
    } else if (
      // 4文字未満は一般語と衝突しやすいので除外
      p.product.length >= 4 &&
      stack.packages.some((pk) => stripScope(pk.name).toLowerCase() === p.product)
    ) {
      cpeHits.push(p.product);
    }
  }
  if (cpeHits.length > 0) {
    return { matchType: "cpe", matched: [...new Set(cpeHits)].slice(0, 5) };
  }

  if (stack.keywords.length > 0) {
    const haystack = `${record.titleEn} ${record.description}`.toLowerCase();
    const kwHits = stack.keywords.filter((kw) =>
      new RegExp(`\\b${escapeRegExp(kw)}\\b`).test(haystack),
    );
    if (kwHits.length > 0) {
      return { matchType: "keyword", matched: kwHits.slice(0, 5) };
    }
  }

  return null;
}
