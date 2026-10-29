// Regex building blocks the builder can insert at the caret, ported from
// macGREP's palette. Recipes (whole expressions) live in Rust so they are
// tested on both engines; these are fragments that do not compile alone.

export interface PaletteToken {
  label: string;
  insert: string;
  help: string;
  /** Caret position inside `insert` after insertion. End when omitted. */
  caret?: number;
  /** Only the PCRE-style engine accepts this token. */
  pcreOnly?: boolean;
}

export interface PaletteGroup {
  name: string;
  tokens: PaletteToken[];
}

export const PALETTE: PaletteGroup[] = [
  {
    name: "Anchors",
    tokens: [
      { label: "^", insert: "^", help: "Start of line (start of text unless multiline)" },
      { label: "$", insert: "$", help: "End of line (end of text unless multiline)" },
      { label: "\\b", insert: "\\b", help: "Word boundary" },
      { label: "\\B", insert: "\\B", help: "Not a word boundary" },
    ],
  },
  {
    name: "Characters",
    tokens: [
      { label: ".", insert: ".", help: "Any single character" },
      { label: "[0-9]", insert: "[0-9]", help: "A digit" },
      { label: "[^0-9]", insert: "[^0-9]", help: "Anything but a digit" },
      { label: "[A-Za-z]", insert: "[A-Za-z]", help: "A letter" },
      { label: "[0-9A-Fa-f]", insert: "[0-9A-Fa-f]", help: "A hex digit" },
      { label: "[[:space:]]", insert: "[[:space:]]", help: "Whitespace (POSIX, works in grep -E)" },
      { label: "[[:alnum:]]", insert: "[[:alnum:]]", help: "Letter or digit (POSIX)" },
      { label: "[[:punct:]]", insert: "[[:punct:]]", help: "Punctuation (POSIX)" },
      { label: "\\d", insert: "\\d", help: "A digit. Not in grep -E" },
      { label: "\\s", insert: "\\s", help: "Whitespace. GNU grep -E and -P only" },
      { label: "\\w", insert: "\\w", help: "Word character. GNU grep -E and -P only" },
      { label: "[...]", insert: "[]", help: "Custom character set", caret: 1 },
      { label: "[^...]", insert: "[^]", help: "Negated character set", caret: 2 },
    ],
  },
  {
    name: "Quantifiers",
    tokens: [
      { label: "*", insert: "*", help: "Zero or more of the previous item" },
      { label: "+", insert: "+", help: "One or more of the previous item" },
      { label: "?", insert: "?", help: "Zero or one of the previous item" },
      { label: "{n}", insert: "{}", help: "Exactly n of the previous item", caret: 1 },
      { label: "{n,}", insert: "{,}", help: "At least n of the previous item", caret: 1 },
      { label: "{n,m}", insert: "{,}", help: "Between n and m of the previous item", caret: 1 },
      { label: "*?", insert: "*?", help: "Lazy: as few as possible. Not in grep -E" },
    ],
  },
  {
    name: "Groups",
    tokens: [
      { label: "(...)", insert: "()", help: "Capturing group", caret: 1 },
      { label: "(?:...)", insert: "(?:)", help: "Non-capturing group. Not in grep -E", caret: 3 },
      { label: "(?<name>...)", insert: "(?<>)", help: "Named group. Not in grep -E", caret: 3 },
      { label: "|", insert: "|", help: "Alternation: match either side" },
      { label: "(a|b)", insert: "(|)", help: "Group with alternatives", caret: 1 },
    ],
  },
  {
    name: "PCRE only",
    tokens: [
      { label: "\\1", insert: "\\1", help: "Back-reference to group 1", pcreOnly: true },
      { label: "(?=...)", insert: "(?=)", help: "Lookahead", caret: 3, pcreOnly: true },
      { label: "(?!...)", insert: "(?!)", help: "Negative lookahead", caret: 3, pcreOnly: true },
      { label: "(?<=...)", insert: "(?<=)", help: "Lookbehind", caret: 4, pcreOnly: true },
      { label: "(?<!...)", insert: "(?<!)", help: "Negative lookbehind", caret: 4, pcreOnly: true },
    ],
  },
  {
    name: "Escapes",
    tokens: [
      { label: "\\.", insert: "\\.", help: "A literal period" },
      { label: "\\\\", insert: "\\\\", help: "A literal backslash" },
      { label: "\\$", insert: "\\$", help: "A literal dollar sign" },
      { label: "\\[", insert: "\\[", help: "A literal opening bracket" },
      { label: "\\(", insert: "\\(", help: "A literal opening parenthesis" },
      { label: "\\*", insert: "\\*", help: "A literal asterisk" },
      { label: "\\+", insert: "\\+", help: "A literal plus sign" },
      { label: "\\?", insert: "\\?", help: "A literal question mark" },
      { label: "\\|", insert: "\\|", help: "A literal vertical bar" },
    ],
  },
];
