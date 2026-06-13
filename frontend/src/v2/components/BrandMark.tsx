/**
 * BrandMark — 品牌正字 "Nᵗʰ DAO"。
 *
 * 正确写法是 N + 上标 th + 空格 + DAO。用 <sup> 而非 unicode 上标字符,
 * 这样在任意字体下都是真上标、清晰可控;aria-label 给读屏软件念回
 * 普通的 "Nth DAO"。需要纯文本场景(document.title)用 unicode "Nᵗʰ DAO"。
 */
export function BrandMark({ className }: { className?: string }) {
  return (
    <span className={className} aria-label="Nth DAO">
      N<sup className="brand-th">th</sup> DAO
    </span>
  );
}
