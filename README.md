# 🛡 VulnCollector — 脆弱性インテリジェンスダッシュボード

GitHub Actions が毎日、信頼性の高い複数ソースから脆弱性情報を収集し、AI(GitHub Models)が日本語で要約・トリアージ。結果は JSON としてリポジトリにコミットされ、GitHub Pages のダッシュボードで閲覧できます。

## アーキテクチャ

```
[毎日 06:00 JST] collect.yml
  ├─ scripts/collect.mjs   NVD / JVN / CISA KEV / GHSA + SNSシグナル収集 → AI入力バッチ生成
  ├─ actions/ai-inference  ×7回 (要約バッチ最大6 + 話題統合1, openai/gpt-4.1, JSON Schema出力)
  ├─ scripts/merge.mjs     → data/vulns/YYYY-MM-DD.json + data/index.json
  └─ git commit & push
        └─ workflow_run → deploy.yml → Next.js 静的エクスポート → GitHub Pages
```

### 情報源

| 種別 | ソース |
|---|---|
| 脆弱性DB | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) / [JVN iPedia (MyJVN API)](https://jvndb.jvn.jp/apis/) / [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [GitHub Security Advisories](https://docs.github.com/graphql) |
| SNS・話題 | Mastodon (mastodon.social タグTL) / Hacker News (Algolia API) / The Hacker News・BleepingComputer・JPCERT/CC の RSS |

### 自プロジェクトの技術スタックフォーカス

このリポジトリ自身をプロジェクトとみなし、リポジトリ直下の `package.json`(存在すれば `composer.json` も)の依存パッケージと、`scripts/watchlist.json` の `stack.keywords`(MySQL 等のミドルウェア)を脆弱性と自動照合します。

- マッチ確度: GHSA パッケージ完全一致 (`package`) > CPE 製品名一致 (`cpe`) > キーワード一致 (`keyword`)
- マッチした脆弱性は AI 分析の選定で KEV に次ぐ優先度に引き上げられ、AI が「このプロジェクトへの影響」(`stackImpactJa`) を生成
- ダッシュボードでは「📌 使用技術」バッジと専用セクションで表示

### AI処理

`actions/ai-inference@v1`(GitHub Models プロバイダ)。`GITHUB_TOKEN` の `models: read` 権限のみで動作し、**追加のAPIキー・課金は不要**(無料枠: gpt-4.1 は 50リクエスト/日・8K入力/4K出力トークン — 本ワークフローは1日最大7リクエスト)。

- 事前フィルタ: KEV掲載 / 技術スタック一致 / CVSS≥7.0 / JVN掲載 / SNS言及 / `scripts/watchlist.json` のキーワード一致 → 上位48件をAI分析
- 出力: 日本語の要約・影響・推奨対応・優先度(根拠付き)+「本日の話題」3〜6トピック

## 使い方

### ダッシュボードの操作

| 操作 | 説明 |
|---|---|
| 日付ナビ (← →) | 過去の収集日に移動。フィルタ状態はそのまま引き継がれます |
| 重大度フィルタ | Critical / High / Medium 以上に絞り込み |
| KEVのみ | CISA の既知悪用脆弱性カタログに掲載されたものだけ表示 |
| 並び順 | 優先度順(デフォルト) / CVSS スコア降順 / 公開日が新しい順 |
| テキスト検索 | CVE ID・タイトル・製品名・要約を横断検索 |
| URL 共有 | フィルタ・ソートの状態が URL クエリに自動保存されるため、そのままコピーして共有できます |
| CVE ディープリンク | `https://<Pages URL>/date/<日付>/#CVE-XXXX-YYYYY` で特定脆弱性に直接リンクできます。フィルタ付き `?sev=high#CVE-...` も有効です |

### カードの読み方

```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 CRITICAL 9.8  CVE-2026-XXXXX  ⚠KEV  🔴P1  📌使用技術  🔥×3 │  NVD ▼
│ SQL インジェクションにより認証なしで RCE が可能                          │
└─────────────────────────────────────────────────────────────┘
```

| バッジ | 意味 |
|---|---|
| 🔴 CRITICAL / 🟠 HIGH … | CVSS 重大度とスコア |
| ⚠ KEV | CISA の既知悪用脆弱性カタログ掲載済み(最優先対応) |
| 🔴 P1 / 🟠 P2 … | AI による優先度判定(P1 = 即時対応推奨) |
| 📌 使用技術 | このリポジトリの依存パッケージ・ミドルウェアに一致(? 付きは推定) |
| 🔥 ×n | SNS・コミュニティでの言及数 |

カードをクリックすると「概要・影響・推奨対応・優先度の根拠・参考リンク」が展開されます。`📌 使用技術` バッジがある場合は先頭に「このプロジェクトへの影響」セクションが表示されます。

### 収集対象のカスタマイズ

**監視キーワードの追加** (`scripts/watchlist.json`):
```json
{
  "keywords": ["log4j", "openssl", "apache"],
  "stack": {
    "keywords": ["mysql", "redis", "nginx"]
  }
}
```
- `keywords`: 全件収集で常に注目する技術名・製品名
- `stack.keywords`: このリポジトリの `package.json` に現れないミドルウェア・インフラ名(CPE/タイトルマッチで使用技術バッジが付く)

---

## セットアップ(初回のみ)

1. リポジトリの **Settings → Pages → Build and deployment → Source** を **GitHub Actions** に設定
2. Actions タブから **Collect vulnerabilities** を手動実行(`workflow_dispatch`)→ データコミット後、自動で Pages にデプロイされます
3. (任意) NVD のレート制限緩和: [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) を取得し、Secrets に `NVD_API_KEY` として登録

## ローカル開発

```bash
npm install
npm run dev            # http://localhost:3000 (data/ のJSONを表示)

# 収集をローカル実行 (GHSAにはGITHUB_TOKENが必要。無くても他ソースで続行)
GITHUB_TOKEN=<PAT> node scripts/collect.mjs

# AIの代わりにモック分析でマージ (ai-inferenceはActions専用のため)
MOCK_AI=1 node scripts/merge.mjs

# 静的エクスポートの確認 (GitHub Pages相当)
NEXT_PUBLIC_BASE_PATH=/VulnCollector npm run build
```

※ モック分析(`[MOCK]`付き)は同日の実AI実行時に自動で上書きされます。

## 設定ファイル

- `scripts/watchlist.json` — 監視キーワード / CVSSしきい値 / 分析件数上限 / バッチサイズ / 技術スタック設定(`stack.keywords` にミドルウェア名、`stack.includeDevDependencies` で devDependencies も対象化、`stack.maxMatched` でスタックマッチのみの採用上限)
- `scripts/x.json` — X の監視アカウント / Nitter インスタンスリスト / リクエスト間隔
- `.github/prompts/*.prompt.yml` — AIプロンプトと出力JSONスキーマ(モデル変更もここで: 例 `openai/gpt-4.1-mini`)

## 注意

要約・優先度はAI生成です。対応判断の前に必ず参考リンクの一次情報を確認してください。
