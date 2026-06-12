import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "脆弱性インテリジェンスダッシュボード",
  description:
    "NVD・JVN・CISA KEV・GHSAとSNSシグナルから日次収集した脆弱性情報をAIが日本語で要約・トリアージ",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="ja"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <header className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-950">
          <div className="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3">
            <h1 className="text-lg font-bold">🛡 脆弱性インテリジェンス</h1>
            <span className="text-xs text-zinc-500">
              NVD / JVN / CISA KEV / GHSA / ZDI + 報道・SNSシグナル → AI日本語トリアージ
            </span>
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-4">{children}</main>
        <footer className="border-t border-zinc-200 py-3 text-center text-xs text-zinc-400 dark:border-zinc-800">
          データ出典: NVD (NIST) / JVN iPedia (JPCERT/CC・IPA) / CISA KEV / GitHub Security
          Advisories / Zero Day Initiative (Trend Micro) /
          信頼できる報道 (The Hacker News・BleepingComputer・JPCERT/CC)。
          要約はAI生成のため、対応前に必ず一次情報を確認してください。
        </footer>
      </body>
    </html>
  );
}
