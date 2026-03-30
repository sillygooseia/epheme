/**
 * PluginDb — dialect-neutral database interface for BafGo plugins.
 *
 * The host operator selects the backing engine (SQLite or Postgres) once via
 * createPluginHost({ db: { dialect, ... } }). Plugin code never imports
 * a DB driver directly.
 *
 * Migrations
 * ----------
 * Call ctx.db.migrate([]) early in register(). Steps are run in order, and
 * each step is tracked by its 0-based index — already-applied steps are skipped.
 * Steps must be idempotent DDL that works on both SQLite and Postgres
 * (CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS, etc.).
 *
 * SQL compatibility notes
 * -----------------------
 * - Use ? placeholders for SQLite, $1/$2/... for Postgres.
 *   PluginDb normalises this: always write ? and the adapter translates.
 * - Avoid engine-specific types: use TEXT, INTEGER, REAL, BLOB.
 * - JSON columns: store as TEXT and parse in application code.
 */
export interface PluginDb {
  /**
   * Run a SELECT-like query and return all matching rows.
   * Always uses ? placeholders regardless of backing dialect.
   */
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;

  /**
   * Run a non-SELECT statement (INSERT, UPDATE, DELETE, etc.).
   */
  run(sql: string, params?: unknown[]): Promise<void>;

  /**
   * Execute multiple statements atomically. The callback receives the same
   * PluginDb interface so existing query/run helpers work inside transactions.
   */
  transaction<T>(fn: (db: PluginDb) => Promise<T>): Promise<T>;

  /**
   * Apply migration steps. Steps are plain SQL strings run in order.
   * Already-applied steps (by index) are skipped on restart.
   * Call once at the start of register() before touching any tables.
   *
   * @example
   * await ctx.db.migrate([
   *   `CREATE TABLE IF NOT EXISTS items (
   *      id TEXT PRIMARY KEY,
   *      device_id TEXT NOT NULL,
   *      content TEXT,
   *      created_at INTEGER NOT NULL
   *    )`,
   *   `CREATE INDEX IF NOT EXISTS idx_items_device ON items(device_id)`,
   * ]);
   */
  migrate(steps: string[]): Promise<void>;
}
