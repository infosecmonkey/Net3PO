<script lang="ts">
  // One certificate or CSR: headline facts up top, details on demand.
  import type { CertInfo, CsrInfo } from "./types";
  import { certRows, csrRows, day, keyText, validityText } from "./report";

  interface Props {
    title: string;
    cert?: CertInfo;
    csr?: CsrInfo;
    open?: boolean;
  }

  let { title, cert, csr, open = false }: Props = $props();

  const rows = $derived(cert ? certRows(cert) : csr ? csrRows(csr) : []);
  const notes = $derived(cert?.notes ?? csr?.notes ?? []);
</script>

<div class="card">
  <div class="head">
    <span class="title">{title}</span>
    {#if cert}
      <span class="pill {cert.validity}">{validityText(cert)}</span>
      {#if cert.isCa}<span class="pill neutral">CA</span>{/if}
      {#if cert.selfSigned}<span class="pill neutral">self-signed</span>{/if}
    {:else if csr}
      <span class="pill {csr.signatureValid ? 'valid' : 'expired'}">{csr.signatureValid ? "signature OK" : "bad signature"}</span>
    {/if}
  </div>
  <div class="line mono">{cert?.subject ?? csr?.subject}</div>
  {#if cert}
    <div class="line muted small">
      Issued by {cert.issuer} · {day(cert.notBeforeMs)} to {day(cert.notAfterMs)} · {keyText(cert.key)} · {cert.signatureAlgorithm}
    </div>
  {:else if csr}
    <div class="line muted small">{keyText(csr.key)} · {csr.signatureAlgorithm}</div>
  {/if}
  {#if notes.length}
    <ul class="notes">
      {#each notes as n (n)}<li>{n}</li>{/each}
    </ul>
  {/if}
  <details {open}>
    <summary>Details</summary>
    <table>
      <tbody>
        {#each rows as r (r.key)}
          <tr><th>{r.key}</th><td class="mono">{r.value}</td></tr>
        {/each}
      </tbody>
    </table>
  </details>
</div>

<style>
  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.7rem 0.9rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .head {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    flex-wrap: wrap;
  }

  .title {
    font-weight: 600;
    font-size: 0.88rem;
  }

  .pill {
    font-size: 0.66rem;
    font-weight: 700;
    padding: 0.08rem 0.4rem;
    border-radius: 4px;
    color: #fff;
  }

  .pill.valid {
    background: #15935a;
  }

  .pill.expired,
  .pill.notYetValid {
    background: #c0392b;
  }

  .pill.neutral {
    background: var(--hover);
    color: var(--fg);
  }

  .line {
    font-size: 0.82rem;
    overflow-wrap: anywhere;
  }

  .small {
    font-size: 0.75rem;
  }

  .muted {
    color: var(--muted);
  }

  .mono {
    font-family: var(--mono);
  }

  .notes {
    margin: 0.2rem 0 0;
    padding-left: 1.1rem;
    font-size: 0.8rem;
    color: #b7791f;
  }

  details {
    margin-top: 0.2rem;
  }

  summary {
    font-size: 0.76rem;
    color: var(--muted);
    cursor: pointer;
  }

  table {
    border-collapse: collapse;
    margin-top: 0.35rem;
    width: 100%;
  }

  th {
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.74rem;
    padding: 0.18rem 0.8rem 0.18rem 0;
    vertical-align: top;
    white-space: nowrap;
  }

  td {
    font-size: 0.76rem;
    padding: 0.18rem 0;
    overflow-wrap: anywhere;
  }
</style>
