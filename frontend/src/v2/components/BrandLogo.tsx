/** BrandLogo — the project-supplied Nth DAO brand artwork. */
export function BrandLogo({
  size = 24,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <img
      src="/nth-dao-logo.jpg"
      width={size}
      height={size}
      className={className}
      alt="Nth DAO"
    />
  );
}
