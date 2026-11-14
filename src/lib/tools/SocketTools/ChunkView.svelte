<script lang="ts">
  // Received bytes as escaped text or a hex dump. Never rendered as HTML.
  import type { Chunk } from "./types";

  let { chunk, hex = false }: { chunk: Chunk; hex?: boolean } = $props();
</script>

<pre class="chunk mono">{hex ? chunk.hex : chunk.text}{chunk.truncated ? `\n... first 4096 of ${chunk.bytes} bytes shown` : ""}</pre>

<style>
  .chunk {
    margin: 0.15rem 0 0.4rem 6.2rem;
    padding: 0.35rem 0.5rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.74rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 18rem;
    overflow: auto;
  }
</style>
