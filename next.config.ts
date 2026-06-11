import type { NextConfig } from "next";

// GitHub Pages (プロジェクトページ) 配信用の静的エクスポート設定。
// basePath はリポジトリ名のサブパス。CI では NEXT_PUBLIC_BASE_PATH=/VulnCollector を渡す。
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const nextConfig: NextConfig = {
  output: "export",
  basePath,
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
