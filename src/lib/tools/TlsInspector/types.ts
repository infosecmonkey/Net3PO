// Mirrors the Rust types in `tools::tls_inspector`.

export interface Sans {
  dns: string[];
  ip: string[];
  email: string[];
  uri: string[];
}

export interface KeyInfo {
  algorithm: string;
  bits: number;
  curve: string;
  spkiSha256: string;
}

export type CertValidity = "notYetValid" | "valid" | "expired";

export interface CertInfo {
  subject: string;
  subjectCn: string;
  issuer: string;
  serial: string;
  version: number;
  notBeforeMs: number;
  notAfterMs: number;
  validity: CertValidity;
  daysLeft: number;
  sans: Sans;
  key: KeyInfo;
  signatureAlgorithm: string;
  isCa: boolean;
  pathLen: number | null;
  keyUsage: string[];
  extendedKeyUsage: string[];
  subjectKeyId: string;
  authorityKeyId: string;
  ocsp: string[];
  caIssuers: string[];
  crl: string[];
  selfSigned: boolean;
  sha256: string;
  sha1: string;
  notes: string[];
}

export interface CsrInfo {
  subject: string;
  subjectCn: string;
  sans: Sans;
  key: KeyInfo;
  signatureAlgorithm: string;
  signatureValid: boolean;
  notes: string[];
}

export type Decoded =
  | { type: "certificate"; label: string; cert: CertInfo }
  | { type: "csr"; label: string; csr: CsrInfo };

export interface DecodeResult {
  items: Decoded[];
  warnings: string[];
  privateKeySkipped: boolean;
}

export type StartTls = "none" | "smtp" | "imap" | "pop3" | "ftp";

export interface LiveRequest {
  target: string;
  port: number | null;
  connectIp: string;
  sni: boolean;
  starttls: StartTls;
}

export interface LiveResult {
  host: string;
  port: number;
  address: string;
  sniSent: string | null;
  starttls: StartTls;
  transcript: string[];
  protocol: string;
  cipherSuite: string;
  keyExchange: string;
  alpn: string;
  timing: { connectMs: number; starttlsMs: number | null; handshakeMs: number };
  chain: CertInfo[];
  chainNotes: string[];
  trust: {
    chainTrusted: boolean;
    chainError: string;
    nameMatch: string | null;
    checkedName: string;
    store: string;
  };
}

export interface SuiteResult {
  version: string;
  suite: string;
  support: "accepted" | "rejected" | "error";
  detail: string;
}

export const STARTTLS_PORTS: Record<StartTls, number> = {
  none: 443,
  smtp: 587,
  imap: 143,
  pop3: 110,
  ftp: 21,
};
