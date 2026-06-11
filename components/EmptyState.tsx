export function EmptyState() {
  return (
    <div className="flex flex-col items-center gap-3 py-24 text-center">
      <p className="text-2xl">📭</p>
      <p className="font-medium">まだデータが収集されていません</p>
      <p className="text-sm text-zinc-500">
        GitHub Actions の「Collect vulnerabilities」ワークフローが実行されると、ここに日次の脆弱性情報が表示されます。
      </p>
    </div>
  );
}
