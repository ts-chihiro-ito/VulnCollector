// ビルド時に data/ ディレクトリのJSONを読むサーバー専用ヘルパー

import fs from "node:fs";
import path from "node:path";
import type { DailyData, IndexFile } from "./types";

const DATA_DIR = path.join(process.cwd(), "data");

export function getIndex(): IndexFile {
  const file = path.join(DATA_DIR, "index.json");
  if (!fs.existsSync(file)) {
    return { updatedAt: "", dates: [] };
  }
  return JSON.parse(fs.readFileSync(file, "utf8")) as IndexFile;
}

export function getDay(date: string): DailyData | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
  const file = path.join(DATA_DIR, "vulns", `${date}.json`);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8")) as DailyData;
}

export function getLatestDate(): string | null {
  return getIndex().dates[0]?.date ?? null;
}
