// Types, apply-command text and the export report for the DNS Benchmark.

import type { Report } from "$lib/report/types";

export type Transport = "udp" | "tcp" | "dot" | "doh";
export const TRANSPORTS: { id: Transport; label: string; hint: string }[] = [
  { id: "udp", label: "UDP", hint: "Plain DNS, port 53" },
  { id: "tcp", label: "TCP", hint: "Plain DNS over TCP, port 53" },
  { id: "dot", label: "DoT", hint: "DNS over TLS, port 853" },
  { id: "doh", label: "DoH", hint: "DNS over HTTPS, port 443 (HTTP/1.1)" },
];
export const TRANSPORT_LABEL: Record<Transport, string> = { udp: "UDP", tcp: "TCP", dot: "DoT", doh: "DoH" };

export interface Provider {
  id: string;
  name: string;
  note: string;
  ipv4: string[];
  ipv6: string[];
  doh: string;
  dot: string;
}

export interface Defaults {
  providers: Provider[];
  system: string[];
}

/** A saved custom resolver. */
export interface Custom {
  id: string;
  name: string;
  ip: string;
  doh: string;
  dot: string;
}

/** What the backend takes. */
export interface ResolverSpec {
  id: string;
  name: string;
  ip: string;
  doh: string;
  dot: string;
}

export interface Stats {
  sent: number;
  ok: number;
  medianMs: number | null;
  p90Ms: number | null;
  minMs: number | null;
  lossPct: number;
}

export type Dnssec = "validating" | "notValidating" | "unknown";

export type BenchEvent =
  | { type: "started"; total: number }
  | {
      type: "result";
      resolverId: string;
      transport: Transport;
      connectMs: number | null;
      cached: Stats;
      uncached: Stats;
      error: string | null;
    }
  | { type: "check"; resolverId: string; dnssec: Dnssec; hijack: boolean | null }
  | { type: "progress"; done: number; total: number }
  | { type: "done"; elapsedMs: number; cancelled: boolean }
  | { type: "error"; message: string };

export interface Row {
  resolverId: string;
  name: string;
  ip: string;
  transport: Transport;
  connectMs: number | null;
  cached: Stats;
  uncached: Stats;
  error: string | null;
}

export interface Check {
  dnssec: Dnssec;
  hijack: boolean | null;
}

export const DNSSEC_LABEL: Record<Dnssec, string> = {
  validating: "Validates",
  notValidating: "Does not validate",
  unknown: "Unknown",
};

export function ms(v: number | null): string {
  return v === null ? "-" : `${v.toFixed(1)}`;
}

/** Commands to point this computer at `ips`, per OS. Placeholders in <>. */
export function applyCommands(ips: string[]): { os: string; label: string; lines: { title: string; cmd: string }[] }[] {
  const v4 = ips.filter((i) => !i.includes(":"));
  const v6 = ips.filter((i) => i.includes(":"));
  const all = [...v4, ...v6];
  const ps = all.map((i) => `"${i}"`).join(",");
  const sp = all.join(" ");
  const nm: { title: string; cmd: string }[] = [];
  if (v4.length) {
    nm.push({
      title: "NetworkManager, IPv4 (persistent)",
      cmd: `nmcli connection modify "<connection>" ipv4.dns "${v4.join(" ")}" ipv4.ignore-auto-dns yes && nmcli connection up "<connection>"`,
    });
  }
  if (v6.length) {
    nm.push({
      title: "NetworkManager, IPv6 (persistent)",
      cmd: `nmcli connection modify "<connection>" ipv6.dns "${v6.join(" ")}" ipv6.ignore-auto-dns yes && nmcli connection up "<connection>"`,
    });
  }
  return [
    {
      os: "windows",
      label: "Windows (PowerShell as administrator)",
      lines: [
        { title: "List interfaces", cmd: "Get-NetAdapter | Select-Object Name, Status" },
        { title: "Apply", cmd: `Set-DnsClientServerAddress -InterfaceAlias "<interface>" -ServerAddresses (${ps})` },
        { title: "Revert to automatic (DHCP)", cmd: `Set-DnsClientServerAddress -InterfaceAlias "<interface>" -ResetServerAddresses` },
        { title: "Flush the cache", cmd: "Clear-DnsClientCache" },
      ],
    },
    {
      os: "macos",
      label: "macOS (Terminal)",
      lines: [
        { title: "List network services", cmd: "networksetup -listallnetworkservices" },
        { title: "Apply", cmd: `sudo networksetup -setdnsservers "<service>" ${sp}` },
        { title: "Revert to automatic (DHCP)", cmd: `sudo networksetup -setdnsservers "<service>" empty` },
        { title: "Flush the cache", cmd: "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder" },
      ],
    },
    {
      os: "linux",
      label: "Linux (systemd-resolved or NetworkManager)",
      lines: [
        { title: "List interfaces and their DNS", cmd: "resolvectl dns" },
        { title: "systemd-resolved (until the link restarts)", cmd: `sudo resolvectl dns <interface> ${sp}` },
        ...nm,
        { title: "Revert (systemd-resolved)", cmd: "sudo resolvectl revert <interface>" },
        { title: "Flush the cache", cmd: "sudo resolvectl flush-caches" },
      ],
    },
  ];
}

export function buildReport(
  rows: Row[],
  checks: Record<string, Check>,
  meta: { transports: Transport[]; rounds: number; elapsedMs: number | null; cancelled: boolean },
): Report {
  const names = new Map(rows.map((r) => [r.resolverId, `${r.name} (${r.ip})`]));
  return {
    title: "DNS benchmark",
    subtitle: `${names.size} resolvers, ${meta.transports.map((t) => TRANSPORT_LABEL[t]).join(", ")}, ${meta.rounds} rounds${meta.cancelled ? " (cancelled)" : ""}`,
    tool: "DNS Benchmark",
    sections: [
      {
        title: "Latency (ms)",
        subtitle: "Cached: popular names. Uncached: random names that force a lookup at the authoritative servers.",
        blocks: [
          {
            type: "table",
            headers: ["Resolver", "Address", "Transport", "Cached median", "Cached p90", "Uncached median", "Uncached p90", "Loss %", "Connect", "Error"],
            rows: rows.map((r) => [
              r.name,
              r.ip,
              TRANSPORT_LABEL[r.transport],
              ms(r.cached.medianMs),
              ms(r.cached.p90Ms),
              ms(r.uncached.medianMs),
              ms(r.uncached.p90Ms),
              String(Math.max(r.cached.lossPct, r.uncached.lossPct)),
              ms(r.connectMs),
              r.error ?? "",
            ]),
          },
        ],
      },
      {
        title: "Checks",
        blocks: [
          {
            type: "findings",
            items: Object.entries(checks).flatMap(([id, c]) => {
              const n = names.get(id) ?? id;
              return [
                {
                  severity: c.dnssec === "validating" ? ("pass" as const) : c.dnssec === "notValidating" ? ("warn" as const) : ("info" as const),
                  category: "DNSSEC",
                  title: `${n}: ${DNSSEC_LABEL[c.dnssec]}`,
                },
                {
                  severity: c.hijack === true ? ("fail" as const) : c.hijack === false ? ("pass" as const) : ("info" as const),
                  category: "NXDOMAIN",
                  title: `${n}: ${c.hijack === true ? "Answers names that do not exist (hijacking)" : c.hijack === false ? "Returns NXDOMAIN correctly" : "Unknown"}`,
                },
              ];
            }),
          },
        ],
      },
    ],
  };
}
