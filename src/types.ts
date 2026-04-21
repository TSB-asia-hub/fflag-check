export type ScanVerdict = "Clean" | "Inconclusive" | "Suspicious" | "Flagged";

export interface ScanFinding {
  module: string;
  verdict: ScanVerdict;
  description: string;
  details: string | null;
  timestamp: string;
}

export interface ScanReport {
  scan_id: string;
  timestamp: string;
  machine_id: string;
  os_info: string;
  overall_verdict: ScanVerdict;
  findings: ScanFinding[];
  hmac_signature: string;
}
