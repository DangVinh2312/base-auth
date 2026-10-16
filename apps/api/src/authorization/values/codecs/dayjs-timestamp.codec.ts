import type { Comparison, ScalarCodec } from '../../core/ports/value-codecs.port.js';
import dayjs from 'dayjs';
import customParseFormat from 'dayjs/plugin/customParseFormat.js';
import utc from 'dayjs/plugin/utc.js';

// Plugin registration is idempotent and only adds parsing capabilities to the shared dayjs.
dayjs.extend(customParseFormat);
dayjs.extend(utc);

// Syntax only (ASCII digits, fixed shape); calendar validity is delegated to Day.js below.
const shape = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/;
const SECONDS_FORMAT = 'YYYY-MM-DD[T]HH:mm:ss';

/** Strict UTC calendar check through Day.js; whole seconds only, the fraction never enters it. */
function isRealUtcSecond(year: number, rest: string): boolean {
  // Date.UTC maps years 0..99 to 1900..1999, which Day.js strict then rejects. The Gregorian
  // calendar repeats every 400 years, so validate the same month/day/time in year + 400.
  const probe = year < 100 ? year + 400 : year;
  const text = `${String(probe).padStart(4, '0')}${rest}`;
  return dayjs.utc(text, SECONDS_FORMAT, true).isValid();
}

/**
 * Timestamp codec: UTC `YYYY-MM-DDTHH:mm:ss[.f{1..6}]Z`, years 0001..9999, canonical output has
 * exactly six fractional digits. Microseconds stay a validated string (Day.js stops at ms).
 */
export function createDayjsTimestampCodec(): ScalarCodec<string> {
  return {
    normalize(input) {
      if (typeof input !== 'string') return undefined;
      const match = shape.exec(input);
      if (!match) return undefined;
      const [, year = '', month = '', day = '', hh = '', mm = '', ss = '', fraction = ''] = match;
      const y = Number(year);
      if (y < 1) return undefined;
      if (!isRealUtcSecond(y, `-${month}-${day}T${hh}:${mm}:${ss}`)) return undefined;
      return `${year}-${month}-${day}T${hh}:${mm}:${ss}.${fraction.padEnd(6, '0')}Z`;
    },

    // Canonical strings are fixed-width UTC, so lexicographic order is chronological order.
    compare: (left, right): Comparison => (left === right ? 0 : left < right ? -1 : 1),
  };
}
