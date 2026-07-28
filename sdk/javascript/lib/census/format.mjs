/**
 * Formatting shared by the census report renderers.
 *
 * This is all that survives of the CLI's own aggregator. The census is
 * aggregated once, where it is collected, and published as a dated snapshot;
 * this package renders that snapshot and computes nothing from it.
 */

/** Format a large number with a suffix (B, M, K). */
export function formatNumber(n) {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}
