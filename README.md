# 🛡 VulnCollector — 脆弱性インテリジェンスダッシュボード

GitHub Actions が毎日、信頼性の高い複数ソースから脆弱性情報を収集し、AI(GitHub Models)が日本語で要約・トリアージ。結果は JSON としてリポジトリにコミットされ、GitHub Pages のダッシュボードで閲覧できます。

## アーキテクチャ

```
[毎日 06:00 JST] collect.yml
  ├─ scripts/collect.mjs   NVD / JVN / CISA KEV / GHSA / ZDI + 報道・SNSシグナル収集 → AI入力バッチ生成
  ├─ actions/ai-inference  ×7回 (要約バッチ最大6 + 話題統合1, openai/gpt-4.1, JSON Schema出力)
  ├─ scripts/merge.mjs     → data/vulns/YYYY-MM-DD.json + data/index.json
  └─ git commit & push
        └─ workflow_run → deploy.yml → Next.js 静的エクスポート → GitHub Pages
```

### 情報源

| 種別 | ソース |
|---|---|
| 脆弱性DB | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) / [JVN iPedia (MyJVN API)](https://jvndb.jvn.jp/apis/) / [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [GitHub Security Advisories](https://docs.github.com/graphql) |
| ゼロデイ・速報 | [Zero Day Initiative](https://www.zerodayinitiative.com/advisories/) RSS (公開済み + パッチ前のベンダー報告分) |
| SNS・話題 | Mastodon (mastodon.social タグTL) / Hacker News (Algolia API) / The Hacker News・BleepingComputer・JPCERT/CC の RSS |

### 速報 (NVD未登録) の扱い

NVD は CVE 公開から登録・分析まで数日〜数週間遅延することがあるため、NVD/JVN/GHSA/KEV のいずれにも未登録の情報を「🚨 速報」としてレコード化し、ダッシュボード上部の専用セクションとバッジで表示します。

- **ZDI由来**: 公開済みアドバイザリに加え、ベンダー報告済み・パッチ前のゼロデイ (ZDI-CAN-xxxxx, CVE未採番) も収集
- **報道由来 (トレンド昇格)**: ニュースで言及された CVE がどのDBにも無い場合、まず NVD に個別照会でバックフィルし (≤5件)、それでも見つからないものだけを速報として昇格
- **信頼性ガード**: 昇格はキュレート済みフィード (`watchlist.trustedTrendSources`: The Hacker News / BleepingComputer / JPCERT/CC) での言及が必須。Mastodon / Hacker News 単独の言及では昇格しない (裏付けシグナルとしてのみ利用)。加えて CVE 年が直近 (今年-1以降) であること、上限 `maxTrendPromoted` (デフォルト10件)
- 速報は AI 分析の選定で KEV に次ぐ優先度。カード詳細に出典 (ZDI ID / 報道媒体名) を明示

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

ダッシュボードは**使用技術(技術スタック)に関連する脆弱性だけをメイン表示**します。関連しないものは「その他の脆弱性」(デフォルト閉、KEVを先頭に)、一般ニュースは「本日の話題」(デフォルト閉) に折りたたまれます。

| 操作 | 説明 |
|---|---|
| 日付ナビ (← →) | 過去の収集日に移動。フィルタ状態はそのまま引き継がれます |
| テキスト検索 | CVE ID・タイトル・製品名・技術名・要約を横断検索。「その他」にだけヒットがある場合は自動で開きます |
| 表示モード | ▦ カード / ☰ テーブル (高密度・列ソート可能)。選択は記憶され次回も適用 |
| 詳細フィルタ | 重大度 / 並び順 / ソース / 悪用確認済みのみ / 対応済みを隠す (非デフォルト時は ● 表示) |
| 既読管理 | 各行の ◯ → 👁 既読 → ✅ 対応済み をクリックで循環 (ブラウザローカル保存) |
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
| 🔴 CRITICAL / 🟠 HIGH … | CVSS 重大度とスコア (カード/行の左端カラーレールも同じ色分け) |
| 🚨 速報 | NVD/JVN/GHSA/KEV 未登録の速報情報 (ZDI / 信頼できる報道由来)。詳細に出典を明示 |
| ⚠ KEV | CISA の既知悪用脆弱性カタログ掲載済み(最優先対応) |
| 🔴 P1 / 🟠 P2 … | AI による優先度判定(P1 = 即時対応推奨) |
| 📌 mysql, laravel … | 一致した使用技術の名前(? 付きは推定)。テーブルビューでは専用の「技術」列 |
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

- `scripts/watchlist.json` — 監視キーワード / CVSSしきい値 / 分析件数上限 / バッチサイズ / 速報昇格の上限と信頼フィード (`maxTrendPromoted`, `trustedTrendSources`) / 技術スタック設定(`stack.keywords` にミドルウェア名、`stack.includeDevDependencies` で devDependencies も対象化、`stack.maxMatched` でスタックマッチのみの採用上限)
- `.github/prompts/*.prompt.yml` — AIプロンプトと出力JSONスキーマ(モデル変更もここで: 例 `openai/gpt-4.1-mini`)

## 注意

要約・優先度はAI生成です。対応判断の前に必ず参考リンクの一次情報を確認してください。
