// Mirrors `tools::timestamp::core`.

export interface TsFormats {
  isoUtc: string;
  zoned: string;
  zone: string;
  unixSeconds: string;
  unixMillis: string;
  filetime: string;
  ldap: string;
  rfc2822: string;
}

export interface TsReading {
  label: string;
  formats: TsFormats;
  notes: string[];
  plausible: boolean;
}

export interface TsConversion {
  readings: TsReading[];
  error: string | null;
}

export const FORMAT_ROWS: { key: keyof TsFormats; label: string }[] = [
  { key: "isoUtc", label: "UTC (ISO 8601)" },
  { key: "zoned", label: "Selected zone" },
  { key: "unixSeconds", label: "Unix seconds" },
  { key: "unixMillis", label: "Unix milliseconds" },
  { key: "filetime", label: "Windows FILETIME / AD" },
  { key: "ldap", label: "LDAP generalized time" },
  { key: "rfc2822", label: "RFC 2822" },
];
