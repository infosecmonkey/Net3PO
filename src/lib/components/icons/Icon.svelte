<script lang="ts">
  // Stroke icon from the bundled Lucide set. Inherits color from the parent.
  import { ICONS, type IconName } from "./icons";

  interface Props {
    name: IconName;
    size?: number;
  }
  let { name, size = 16 }: Props = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <!-- Constant markup from icons.ts; never user input. -->
  {@html ICONS[name]}
</svg>

<style>
  svg {
    flex: 0 0 auto;
    display: block;
  }
</style>
