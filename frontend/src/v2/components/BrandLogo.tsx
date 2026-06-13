/**
 * BrandLogo — Nᵗʰ DAO 标记(手绘 A 形,三段笔刷描边)。
 *
 * 矢量、背景透明,stroke=currentColor 跟随父级 color 着色,方便在深/浅
 * 底上换色。与文字标 <BrandMark/> 配套:logo 图标 + 文字。
 */
export function BrandLogo({
  size = 24,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      viewBox="192 188 640 640"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      role="img"
      aria-label="Nth DAO"
    >
      <path d="M252 479 Q514 531 772 621" strokeWidth={36} />
      <path d="M449 319 Q439 491 402 759" strokeWidth={28} />
      <path d="M552 266 Q604 421 654 581" strokeWidth={44} />
    </svg>
  );
}
