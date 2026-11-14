// Mirrors the Rust types in `tools::http_client`.

export interface HttpRequest {
  url: string;
  method: string;
  headers: [string, string][];
  body: string;
  connectIp: string;
  followRedirects: boolean;
  maxRedirects: number;
  insecure: boolean;
  timeoutSecs: number;
}

export interface HttpTiming {
  dnsMs: number | null;
  connectMs: number;
  tlsMs: number | null;
  firstByteMs: number;
  totalMs: number;
}

export interface HttpTls {
  protocol: string;
  cipher: string;
  alpn: string;
  validation: string;
  certSubject: string;
  certIssuer: string;
  certNotAfterMs: number;
  certSans: string[];
}

export interface HttpHop {
  url: string;
  method: string;
  requestHeaders: [string, string][];
  requestBodyLen: number;
  address: string;
  status: number;
  reason: string;
  version: string;
  headers: [string, string][];
  interim: number[];
  tls: HttpTls | null;
  timing: HttpTiming;
  contentType: string;
  bodyLen: number;
  bodyTruncated: boolean;
  bodyText: string | null;
  bodyHex: string | null;
  notes: string[];
}

export interface HttpObservation {
  severity: "pass" | "info" | "warn";
  header: string;
  title: string;
  detail: string;
}

export interface HttpResult {
  hops: HttpHop[];
  observations: HttpObservation[];
  error: string | null;
  insecure: boolean;
}
