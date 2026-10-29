// Svelte action: select an input's whole value when it gains focus, so a
// default such as "public" is replaced by typing instead of deleted first.

export function selectOnFocus(node: HTMLInputElement) {
  // A click that focuses the field would collapse the selection on mouseup;
  // swallow that one mouseup.
  let justFocused = false;

  function onFocus() {
    node.select();
    justFocused = true;
  }
  function onMouseUp(e: MouseEvent) {
    if (justFocused) {
      e.preventDefault();
      justFocused = false;
    }
  }
  function onBlur() {
    justFocused = false;
  }

  node.addEventListener("focus", onFocus);
  node.addEventListener("mouseup", onMouseUp);
  node.addEventListener("blur", onBlur);
  return {
    destroy() {
      node.removeEventListener("focus", onFocus);
      node.removeEventListener("mouseup", onMouseUp);
      node.removeEventListener("blur", onBlur);
    },
  };
}
