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

X (Twitter) API は有料のため不使用。SNSの話題性は上記の公開APIで代替しています。

### AI処理

`actions/ai-inference@v1`(GitHub Models プロバイダ)。`GITHUB_TOKEN` の `models: read` 権限のみで動作し、**追加のAPIキー・課金は不要**(無料枠: gpt-4.1 は 50リクエスト/日・8K入力/4K出力トークン — 本ワークフローは1日最大7リクエスト)。

- 事前フィルタ: KEV掲載 / CVSS≥7.0 / JVN掲載 / SNS言及 / `scripts/watchlist.json` のキーワード一致 → 上位48件をAI分析
- 出力: 日本語の要約・影響・推奨対応・優先度(根拠付き)+「本日の話題」3〜6トピック

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

- `scripts/watchlist.json` — 監視キーワード / CVSSしきい値 / 分析件数上限 / バッチサイズ
- `.github/prompts/*.prompt.yml` — AIプロンプトと出力JSONスキーマ(モデル変更もここで: 例 `openai/gpt-4.1-mini`)

## 注意

要約・優先度はAI生成です。対応判断の前に必ず参考リンクの一次情報を確認してください。
