<script lang="ts">
  // An editable text area with match highlights drawn behind it. The caller
  // passes match ranges as character (Unicode scalar) offsets, which is what
  // the Rust regex core returns.
  interface Range {
    start: number;
    end: number;
  }

  interface Props {
    text: string;
    matches: Range[];
    placeholder?: string;
    minHeight?: string;
  }

  let {
    text = $bindable(""),
    matches,
    placeholder = "",
    minHeight = "9rem",
  }: Props = $props();

  interface Segment {
    text: string;
    match: boolean;
  }

  // Code points so slicing lines up with the backend's char offsets.
  let codePoints = $derived([...text]);

  let segments = $derived.by<Segment[]>(() => {
    if (matches.length === 0) {
      return [{ text, match: false }];
    }
    const segs: Segment[] = [];
    let cursor = 0;
    for (const m of matches) {
      if (m.start > cursor) {
        segs.push({ text: codePoints.slice(cursor, m.start).join(""), match: false });
      }
      segs.push({ text: codePoints.slice(m.start, m.end).join(""), match: true });
      cursor = m.end;
    }
    if (cursor < codePoints.length) {
      segs.push({ text: codePoints.slice(cursor).join(""), match: false });
    }
    return segs;
  });

  let highlightEl = $state<HTMLPreElement | null>(null);
  function syncScroll(e: Event) {
    const ta = e.currentTarget as HTMLTextAreaElement;
    if (highlightEl) {
      highlightEl.scrollTop = ta.scrollTop;
      highlightEl.scrollLeft = ta.scrollLeft;
    }
  }
</script>

<div class="editor" style="--min-height: {minHeight}">
  <pre class="highlight mono" aria-hidden="true" bind:this={highlightEl}>{#each segments as seg (seg)}{#if seg.match}<mark>{seg.text}</mark>{:else}{seg.text}{/if}{/each}<br /></pre>
  <textarea
    class="mono"
    bind:value={text}
    onscroll={syncScroll}
    {placeholder}
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
  ></textarea>
</div>

<style>
  .editor {
    position: relative;
  }

  .highlight,
  .editor textarea {
    margin: 0;
    padding: 0.5rem 0.6rem;
    font-size: 0.9rem;
    line-height: 1.45;
    border: 1px solid var(--border);
    border-radius: 6px;
    white-space: pre-wrap;
    overflow-wrap: break-word;
    min-height: var(--min-height);
  }

  .mono {
    font-family: var(--mono);
  }

  .highlight {
    position: absolute;
    inset: 0;
    color: var(--fg);
    background: var(--input-bg);
    pointer-events: none;
    overflow: hidden;
  }

  .editor textarea {
    position: relative;
    background: transparent;
    color: transparent;
    caret-color: var(--fg);
    resize: vertical;
    width: 100%;
    box-sizing: border-box;
  }

  .editor textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  mark {
    background: var(--accent);
    color: #fff;
    border-radius: 2px;
  }
</style>
