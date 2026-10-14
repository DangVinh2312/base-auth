import type { ProductTransactionOptions } from '@base-authorization/typeorm-postgres';
/** Handler-facing token: only the snapshot, not the transaction observer. */
export const METRICS_SNAPSHOT = Symbol('METRICS_SNAPSHOT');
export type MetricsSnapshot = Pick<ProductMetrics, 'snapshot'>;
const buckets = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000] as const;
/** Fixed metric/mode labels from the transaction adapter, with bounded cumulative histograms. */
export class ProductMetrics {
  private readonly values = new Map<string, { count: number; sum: number; buckets: number[] }>();
  readonly observe: NonNullable<ProductTransactionOptions['onMetric']> = (metric, mode, value) => {
    const key = `${metric}:${mode}`;
    let row = this.values.get(key);
    if (!row) {
      row = { count: 0, sum: 0, buckets: buckets.map(() => 0) };
      this.values.set(key, row);
    }
    row.count++;
    row.sum += value;
    for (let i = 0; i < buckets.length; i++)
      if (value <= buckets[i]!) row.buckets[i] = row.buckets[i]! + 1;
  };
  snapshot() {
    return [...this.values]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => ({
        metric: key.split(':')[0]!,
        mode: key.split(':')[1]!,
        count: value.count,
        sum: value.sum,
        buckets: buckets.map((upper, i) => ({ upper, count: value.buckets[i]! })),
      }));
  }
}
