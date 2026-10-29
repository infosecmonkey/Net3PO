// Report model sent to the Rust renderers. Mirrors `report::core` in Rust.

export type ReportSeverity = "pass" | "info" | "warn" | "fail";
export type ReportFormat = "html" | "pdf" | "markdown" | "text";

export interface KeyValue {
  key: string;
  value: string;
}

export interface Finding {
  severity: ReportSeverity;
  category?: string;
  title: string;
  detail?: string;
}

export interface DiffLine {
  kind: "context" | "add" | "del" | "hunk";
  text: string;
}

export type Block =
  | { type: "paragraph"; text: string }
  | { type: "keyValues"; items: KeyValue[] }
  | { type: "table"; headers: string[]; rows: string[][] }
  | { type: "findings"; items: Finding[] }
  | { type: "code"; text: string }
  | { type: "diff"; lines: DiffLine[] };

export interface Section {
  title: string;
  subtitle?: string;
  blocks: Block[];
}

export interface Report {
  title: string;
  subtitle?: string;
  generated?: string;
  tool?: string;
  sections: Section[];
}
