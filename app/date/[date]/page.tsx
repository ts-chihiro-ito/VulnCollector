import { DailyDashboard } from "@/components/DailyDashboard";
import { EmptyState } from "@/components/EmptyState";
import { getDay, getIndex } from "@/lib/data";

export function generateStaticParams() {
  const dates = getIndex().dates;
  // output: export は空のparamsを許さないため、データ未収集時はプレースホルダを生成
  if (dates.length === 0) return [{ date: "no-data" }];
  return dates.map((d) => ({ date: d.date }));
}

export default async function DatePage({
  params,
}: {
  params: Promise<{ date: string }>;
}) {
  const { date } = await params;
  const day = getDay(date);
  if (!day) return <EmptyState />;
  return <DailyDashboard day={day} dates={getIndex().dates} />;
}
