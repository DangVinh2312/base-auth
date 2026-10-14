export type Comparison = -1 | 0 | 1;

/** Pure value codec: no clock, timezone, trimming or lenient parsing. */
export interface ScalarCodec<T extends string | boolean> {
  /** Canonical value, or undefined when the input is not a valid value of this kind. */
  normalize(input: unknown): T | undefined;
  /** Compares two already-normalized values. */
  compare(left: T, right: T): Comparison;
}

export interface ValueCodecs {
  readonly timestamp: ScalarCodec<string>;
  readonly integer: ScalarCodec<string>;
  readonly decimal: ScalarCodec<string>;
  readonly uuid: ScalarCodec<string>;
  readonly string: ScalarCodec<string>;
  readonly boolean: ScalarCodec<boolean>;
}
