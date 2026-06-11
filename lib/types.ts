export type Source = "nvd" | "jvn" | "kev" | "ghsa";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";

export type Priority = "high" | "medium" | "low";

export interface Cvss {
  score: number | null;
  severity: Severity;
  vector: string | null;
  version: string | null;
}

export interface KevInfo {
  cveId: string;
  vendorProject: string | null;
  product: string | null;
  vulnerabilityName: string | null;
  dateAdded: string | null;
  shortDescription: string | null;
  requiredAction: string | null;
  dueDate: string | null;
  knownRansomwareCampaignUse: string | null;
}

export interface Reference {
  url: string;
  label: string;
}

export interface TrendMention {
  source: string;
  title: string;
  url: string;
}

export interface VulnEntry {
  id: string;
  analyzed: boolean;
  sources: Source[];
  kev: boolean;
  kevInfo: KevInfo | null;
  cvss: Cvss | null;
  titleEn: string;
  titleJa: string | null;
  summaryJa: string | null;
  impactJa: string | null;
  recommendedActionJa: string | null;
  priority: Priority | null;
  priorityReasonJa: string | null;
  affectedProducts: string[];
  published: string | null;
  jvnId: string | null;
  ghsaId: string | null;
  references: Reference[];
  trendMentions: TrendMention[];
}

export interface LowPriorityEntry {
  id: string;
  score: number | null;
  severity: Severity;
  titleEn: string;
  sources: Source[];
}

export interface TrendTopic {
  topic: string;
  summaryJa: string;
  relatedCveIds: string[];
  sourceUrls: string[];
}

export interface DailyStats {
  collectedTotal: number;
  analyzed: number;
  kevCount: number;
  bySeverity: Partial<Record<Severity, number>>;
  sourceErrors: string[];
}

export interface DailyData {
  date: string;
  generatedAt: string;
  stats: DailyStats;
  vulns: VulnEntry[];
  lowPriority: LowPriorityEntry[];
  trends: TrendTopic[];
}

export interface IndexEntry {
  date: string;
  analyzed: number;
  collectedTotal: number;
  kevCount: number;
  criticalCount: number;
}

export interface IndexFile {
  updatedAt: string;
  dates: IndexEntry[];
}
