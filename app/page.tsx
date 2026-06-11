import { DailyDashboard } from "@/components/DailyDashboard";
import { EmptyState } from "@/components/EmptyState";
import { getDay, getIndex } from "@/lib/data";

export default function Home() {
  const index = getIndex();
  const latest = index.dates[0]?.date;
  const day = latest ? getDay(latest) : null;

  if (!day) return <EmptyState />;
  return <DailyDashboard day={day} dates={index.dates} />;
}
