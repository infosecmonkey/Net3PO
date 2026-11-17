<script lang="ts">
  // One explanation: the command line with each part underlined, and the
  // list of parts below. Hovering either side highlights the other.
  import ExplainView from "./ExplainView.svelte";
  import type { ExplainKind, Explanation } from "./types";

  let { ex }: { ex: Explanation } = $props();
  let hover = $state<number | null>(null);

  const KIND: Record<ExplainKind, string> = {
    command: "command",
    option: "option",
    argument: "argument",
    operator: "operator",
    redirect: "redirect",
    assignment: "variable",
    keyword: "keyword",
    comment: "comment",
    heredoc: "here-document",
  };

  const hue = (id: number) => (id * 67) % 360;
</script>

{#if ex.notes.length > 0}
  <ul class="notes">
    {#each ex.notes as n (n)}<li>{n}</li>{/each}
  </ul>
{/if}

<pre class="line mono">{#each ex.pieces as p, i (i)}{#if p.item === null}{p.text}{:else}<span
        class="tok"
        class:hl={hover === p.item}
        class:warn={ex.items[p.item]?.warn}
        style="--h: {hue(p.item)}"
        role="presentation"
        onmouseenter={() => (hover = p.item)}
        onmouseleave={() => (hover = null)}>{p.text}</span
      >{/if}{/each}</pre>

<ol class="items">
  {#each ex.items as it (it.id)}
    <li
      class:hl={hover === it.id}
      class:warn={it.warn}
      style="--h: {hue(it.id)}"
      onmouseenter={() => (hover = it.id)}
      onmouseleave={() => (hover = null)}
    >
      <div class="head">
        <code class="label mono">{it.label}</code>
        <span class="kind">{KIND[it.kind]}</span>
        {#if it.warn}<span class="flag">check</span>{/if}
      </div>
      {#each it.entries as e, ei (ei)}
        <div class="entry">
          {#if e.term && e.term !== it.label}<code class="term mono">{e.term}</code>{/if}
          <span class:unknown={e.source === "unknown"}>{e.text}</span>
          {#if e.source === "man"}<span class="src" title="From the man page on this computer">man page</span>{/if}
        </div>
      {/each}
      {#each it.nested as n, ni (ni)}
        <details class="nested" open>
          <summary>{n.label}</summary>
          <ExplainView ex={n.explanation} />
        </details>
      {/each}
    </li>
  {/each}
</ol>

{#if ex.truncated}
  <p class="muted">The input is long; only the first part is explained.</p>
{/if}

<style>
  .mono {
    font-family: var(--mono);
  }

  .muted {
    color: var(--muted);
    font-size: 0.76rem;
  }

  .notes {
    margin: 0 0 0.5rem;
    padding-left: 1.1rem;
    font-size: 0.78rem;
    color: #b45309;
  }

  .line {
    margin: 0 0 0.6rem;
    padding: 0.5rem 0.6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.8rem;
    line-height: 1.7;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 14rem;
    overflow: auto;
  }

  .tok {
    border-bottom: 2px solid hsl(var(--h) 65% 50%);
    border-radius: 2px;
    cursor: default;
  }

  .tok.warn {
    border-bottom-style: double;
    border-bottom-width: 3px;
  }

  .tok.hl {
    background: hsl(var(--h) 65% 50% / 0.22);
  }

  .items {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  .items li {
    border-left: 3px solid hsl(var(--h) 65% 50%);
    padding: 0.25rem 0.6rem;
    border-radius: 0 4px 4px 0;
  }

  .items li.hl {
    background: hsl(var(--h) 65% 50% / 0.12);
  }

  .items li.warn .label {
    color: #b45309;
  }

  .head {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .label {
    font-size: 0.8rem;
    font-weight: 600;
    overflow-wrap: anywhere;
  }

  .kind {
    font-size: 0.66rem;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.3rem;
  }

  .flag {
    font-size: 0.66rem;
    font-weight: 700;
    color: #fff;
    background: #b45309;
    border-radius: 3px;
    padding: 0 0.3rem;
  }

  .entry {
    font-size: 0.78rem;
    margin-top: 0.15rem;
  }

  .term {
    font-size: 0.74rem;
    margin-right: 0.35rem;
    color: var(--muted);
  }

  .unknown {
    color: var(--muted);
    font-style: italic;
  }

  .src {
    font-size: 0.64rem;
    color: var(--muted);
    border: 1px dashed var(--border);
    border-radius: 3px;
    padding: 0 0.25rem;
    margin-left: 0.3rem;
  }

  .nested {
    margin: 0.35rem 0 0.15rem;
    padding: 0.35rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  .nested summary {
    font-size: 0.74rem;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: 0.35rem;
  }
</style>
