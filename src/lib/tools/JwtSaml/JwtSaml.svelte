<script lang="ts">
  // JWT and SAML inspector. Decoding, signature and application checks are
  // shown separately. Keys and tokens stay in memory only; nothing here is
  // saved, logged or fetched.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { buildJwtReport, buildSamlReport, samlFields, SIG_LABEL, type Check, type JwtResult, type SamlResult } from "./model";

  let mode = $state<"jwt" | "saml">("jwt");

  let token = $state("");
  let jIssuer = $state("");
  let jAudience = $state("");
  let jAlg = $state("");
  let jKey = $state("");
  let jSkew = $state(60);
  let jwt = $state<JwtResult | null>(null);
  let jErr = $state("");

  let samlIn = $state("");
  let sIssuer = $state("");
  let sAudience = $state("");
  let sRecipient = $state("");
  let sSkew = $state(60);
  let saml = $state<SamlResult | null>(null);
  let sErr = $state("");

  let jt: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const args = { token, expect: { issuer: jIssuer, audience: jAudience, alg: jAlg, key: jKey, skewSecs: Number(jSkew) || 0 } };
    clearTimeout(jt);
    jt = setTimeout(async () => {
      if (!token.trim()) {
        jwt = null;
        jErr = "";
        return;
      }
      try {
        jwt = await invoke<JwtResult>("jwt_inspect", args);
        jErr = "";
      } catch (e) {
        jwt = null;
        jErr = String(e);
      }
    }, 200);
  });

  let st: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const args = { input: samlIn, expect: { issuer: sIssuer, audience: sAudience, recipient: sRecipient, skewSecs: Number(sSkew) || 0 } };
    clearTimeout(st);
    st = setTimeout(async () => {
      if (!samlIn.trim()) {
        saml = null;
        sErr = "";
        return;
      }
      try {
        saml = await invoke<SamlResult>("saml_inspect", args);
        sErr = "";
      } catch (e) {
        saml = null;
        sErr = String(e);
      }
    }, 250);
  });

  const when = (s: number) => new Date(s * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
</script>

{#snippet checks(list: Check[])}
  <ul class="checks">
    {#each list as c, i (i)}
      <li class={c.status}><strong>{c.name}</strong> <span>{c.detail}</span></li>
    {/each}
    {#if !list.length}<li class="info"><span>No checks apply; fill in the expectations to compare.</span></li>{/if}
  </ul>
{/snippet}

<div class="panel">
  <header>
    <h1>JWT / SAML Inspector</h1>
    <p class="sub">Decode tokens and SAML messages, check signatures with a key you supply, and compare times, issuer and audience with what your app expects. Offline; nothing is saved.</p>
  </header>

  <div class="tabs" role="tablist">
    <button role="tab" aria-selected={mode === "jwt"} class:active={mode === "jwt"} onclick={() => (mode = "jwt")}>JWT</button>
    <button role="tab" aria-selected={mode === "saml"} class:active={mode === "saml"} onclick={() => (mode = "saml")}>SAML</button>
  </div>

  {#if mode === "jwt"}
    <textarea class="mono" rows="4" bind:value={token} spellcheck="false" placeholder="paste a JWT (eyJ...), with or without 'Bearer'"></textarea>
    <details class="exp" open>
      <summary>Expectations and key (optional)</summary>
      <div class="grid2">
        <label>Expected issuer (iss)<input class="mono" bind:value={jIssuer} spellcheck="false" /></label>
        <label>Expected audience (aud)<input class="mono" bind:value={jAudience} spellcheck="false" /></label>
        <label>Expected algorithm
          <select bind:value={jAlg}>
            <option value="">use the header's (not pinned)</option>
            {#each ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"] as a (a)}<option>{a}</option>{/each}
          </select>
        </label>
        <label>Clock skew allowed (s)<input class="mono num" type="number" min="0" max="3600" bind:value={jSkew} use:selectOnFocus /></label>
      </div>
      <label class="full">Key: HMAC secret, or the issuer's PEM public key or certificate
        <textarea class="mono" rows="3" bind:value={jKey} spellcheck="false" placeholder="kept in memory only"></textarea>
      </label>
    </details>
    {#if jErr}<div class="error">{jErr}</div>{/if}
    {#if jwt}
      <div class="bar"><span class="muted">alg {jwt.alg || "(none)"}</span><ExportMenu build={() => (jwt ? buildJwtReport(jwt) : null)} name="jwt" /></div>
      <div class="three">
        <section>
          <h3>Decoded</h3>
          <div class="lbl">Header</div>
          <pre class="mono json">{JSON.stringify(jwt.header, null, 2)}</pre>
          <div class="lbl">Claims</div>
          <pre class="mono json">{JSON.stringify(jwt.claims, null, 2)}</pre>
          {#if jwt.times.length}
            <table class="kv"><tbody>{#each jwt.times as [k, v] (k)}<tr><th>{k}</th><td class="mono">{when(v)}</td></tr>{/each}</tbody></table>
          {/if}
        </section>
        <section>
          <h3>Signature</h3>
          <div class="sig {jwt.signature}">{SIG_LABEL[jwt.signature]}</div>
          <p class="small">{jwt.signatureDetail}</p>
          {#if jwt.keyRefs.length}
            <div class="lbl">Key references in the header</div>
            <ul class="refs">{#each jwt.keyRefs as r (r)}<li class="mono">{r}</li>{/each}</ul>
            <p class="small muted">Shown only. Net3PO never fetches keys a token points to; trusting them would let the token choose its own key.</p>
          {/if}
        </section>
        <section>
          <h3>Application checks</h3>
          {@render checks(jwt.checks)}
        </section>
      </div>
    {/if}
  {:else}
    <textarea class="mono" rows="5" bind:value={samlIn} spellcheck="false" placeholder="paste a SAMLResponse (Base64), a Redirect URL with SAMLRequest=, or raw SAML XML"></textarea>
    <details class="exp" open>
      <summary>Expectations (optional)</summary>
      <div class="grid2">
        <label>Expected IdP issuer<input class="mono" bind:value={sIssuer} spellcheck="false" /></label>
        <label>Expected audience (SP entity ID)<input class="mono" bind:value={sAudience} spellcheck="false" /></label>
        <label>Expected ACS URL (Destination / Recipient)<input class="mono" bind:value={sRecipient} spellcheck="false" /></label>
        <label>Clock skew allowed (s)<input class="mono num" type="number" min="0" max="3600" bind:value={sSkew} use:selectOnFocus /></label>
      </div>
    </details>
    {#if sErr}<div class="error">{sErr}</div>{/if}
    {#if saml}
      <div class="bar"><span class="muted">{saml.binding}</span><ExportMenu build={() => (saml ? buildSamlReport(saml) : null)} name="saml" /></div>
      <div class="two">
        <section>
          <h3>{saml.message}</h3>
          <table class="kv"><tbody>{#each samlFields(saml) as [k, v] (k)}<tr><th>{k}</th><td class="mono">{v}</td></tr>{/each}</tbody></table>
          {#if saml.attributes.length}
            <div class="lbl">Attributes</div>
            <table class="kv"><tbody>{#each saml.attributes as [n, vals], i (i)}<tr><th>{n}</th><td class="mono">{vals.join(", ")}</td></tr>{/each}</tbody></table>
          {/if}
        </section>
        <section>
          <h3>Checks</h3>
          {@render checks(saml.checks)}
          <h3>Signatures</h3>
          {#each saml.signatures as s, i (i)}
            <div class="sigbox">
              <div><strong>On {s.on}</strong>{#if s.weak}<span class="weak">SHA-1</span>{/if}</div>
              <div class="small mono">{s.method.split("#").pop()} / {s.digest.split("#").pop()}</div>
              {#if s.certSubject}<div class="small">Cert: {s.certSubject}{s.certNotAfterMs ? `, expires ${new Date(s.certNotAfterMs).toISOString().slice(0, 10)}` : ""}</div>
                <div class="small mono muted">SHA-256 {s.certSha256}</div>{/if}
            </div>
          {/each}
          <p class="small muted">XML signatures are located and described here, not cryptographically verified. Compare the certificate fingerprint with the one your SP trusts.</p>
        </section>
      </div>
      <details><summary>Decoded XML</summary><pre class="mono xml">{saml.xml}</pre></details>
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1200px;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.8rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  textarea,
  input,
  select {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    color: var(--fg);
    font-size: 0.8rem;
  }

  textarea {
    resize: vertical;
  }

  textarea:focus,
  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .num {
    width: 6rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .exp {
    margin: 0.6rem 0;
  }

  summary {
    font-size: 0.78rem;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: 0.4rem;
  }

  .grid2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.5rem 1rem;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.76rem;
    color: var(--muted);
  }

  .full {
    margin-top: 0.5rem;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.84rem;
    margin: 0.5rem 0;
  }

  .bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 0.6rem 0;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .small {
    font-size: 0.76rem;
  }

  .three {
    display: grid;
    grid-template-columns: 1.2fr 1fr 1fr;
    gap: 1rem;
  }

  .two {
    display: grid;
    grid-template-columns: 1.3fr 1fr;
    gap: 1rem;
  }

  section {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    min-width: 0;
  }

  h3 {
    margin: 0 0 0.4rem;
    font-size: 0.9rem;
  }

  .lbl {
    font-size: 0.72rem;
    color: var(--muted);
    margin: 0.4rem 0 0.2rem;
  }

  .json,
  .xml {
    margin: 0;
    padding: 0.4rem 0.5rem;
    background: var(--input-bg);
    border-radius: 4px;
    font-size: 0.76rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 16rem;
    overflow: auto;
  }

  .kv {
    border-collapse: collapse;
    width: 100%;
    margin-top: 0.3rem;
  }

  .kv th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    font-size: 0.74rem;
    padding: 0.15rem 0.8rem 0.15rem 0;
    vertical-align: top;
    white-space: nowrap;
    width: 1%;
  }

  .kv td {
    font-size: 0.78rem;
    padding: 0.15rem 0;
    overflow-wrap: anywhere;
  }

  .sig {
    font-weight: 700;
    font-size: 0.95rem;
  }

  .sig.valid {
    color: #15935a;
  }

  .sig.invalid,
  .sig.unsigned {
    color: #c0392b;
  }

  .sig.notChecked,
  .sig.unsupported {
    color: #b7791f;
  }

  .refs {
    margin: 0;
    padding-left: 1rem;
    font-size: 0.76rem;
  }

  .checks {
    list-style: none;
    margin: 0;
    padding: 0;
    font-size: 0.8rem;
  }

  .checks li {
    border-left: 3px solid var(--border);
    padding: 0.2rem 0.5rem;
    margin-bottom: 0.25rem;
  }

  .checks li.pass {
    border-color: #15935a;
  }

  .checks li.fail {
    border-color: #c0392b;
  }

  .checks li.info {
    border-color: #2563eb;
  }

  .sigbox {
    border-top: 1px solid var(--border);
    padding: 0.35rem 0;
  }

  .weak {
    margin-left: 0.4rem;
    font-size: 0.68rem;
    color: #c0392b;
    border: 1px solid #c0392b;
    border-radius: 3px;
    padding: 0 0.25rem;
  }
</style>
