/**
 * node-postgres already parses JSON/JSONB columns into JS values. Calling
 * JSON.parse() on the parsed value (an array/object) throws, so models must
 * only parse when the driver actually handed back a string.
 */
export function parseJsonColumn<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}
