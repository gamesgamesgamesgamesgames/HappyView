/** Resolve a CSS value (including CSS variables) to a hex color string via DOM. */
export function resolveCssColor(value: string): string {
  const el = document.createElement("div");
  el.style.backgroundColor = value;
  document.body.appendChild(el);
  const computed = getComputedStyle(el).backgroundColor;
  el.remove();
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = 1;
  const ctx = canvas.getContext("2d");
  if (!ctx) return "#1e1e1e";
  ctx.fillStyle = computed;
  ctx.fillRect(0, 0, 1, 1);
  const [r, g, b] = ctx.getImageData(0, 0, 1, 1).data;
  return "#" + [r, g, b].map((c) => c.toString(16).padStart(2, "0")).join("");
}
