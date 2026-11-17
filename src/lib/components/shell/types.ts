// Types mirroring `tools::shell_explain::core`.

export type ExplainKind =
  | "command"
  | "option"
  | "argument"
  | "operator"
  | "redirect"
  | "assignment"
  | "keyword"
  | "comment"
  | "heredoc";

export type ExplainSource = "builtin" | "man" | "shell" | "unknown";

export interface ExplainEntry {
  term: string;
  text: string;
  source: ExplainSource;
}

export interface ExplainNested {
  label: string;
  explanation: Explanation;
}

export interface ExplainItem {
  id: number;
  kind: ExplainKind;
  label: string;
  entries: ExplainEntry[];
  warn: boolean;
  nested: ExplainNested[];
}

export interface ExplainPiece {
  text: string;
  item: number | null;
}

export interface Explanation {
  pieces: ExplainPiece[];
  items: ExplainItem[];
  notes: string[];
  truncated: boolean;
}
