/**
 * BafgoDb — internal interface implemented by both the SQLite and Postgres adapters.
 * This mirrors PluginDb from @epheme/plugin-sdk exactly, plus the internal
 * lifecycle methods the plugin host needs.
 *
 * Plugin code only ever sees PluginDb (from the SDK). This file is core-internal.
 */

'use strict';

/**
 * Create a SQLite-backed BafgoDb for a specific plugin.
 *
 * @param {object} options
 * @param {string} options.pluginId   - Used to scope the migrations table and log prefix
 * @param {string} options.file       - Path to the SQLite database file
 * @returns {BafgoDbInstance}
 */
function createSqliteDb({ pluginId, file }) {
  // Lazy-require so hosts that only use Postgres never load better-sqlite3
  const Database = require('better-sqlite3');
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Migrations tracking table (one per plugin, scoped by pluginId in the filename)
  db.exec(`
    CREATE TABLE IF NOT EXISTS _bafgo_migrations (
      idx     INTEGER PRIMARY KEY,
      applied INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    )
  `);

  /**
   * SQLite uses ? placeholders. The unified API always receives ? — no translation needed.
   * We wrap the synchronous better-sqlite3 API in async functions to match the interface.
   */

  async function query(sql, params = []) {
    const stmt = db.prepare(sql);
    return stmt.all(...params);
  }

  async function run(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.run(...params);
  }

  async function transaction(fn) {
    // better-sqlite3 transactions are synchronous, but our fn is async.
    // We run the fn and collect its operations, then commit.
    // This wraps the async fn in a begin/commit/rollback manually.
    db.exec('BEGIN');
    try {
      const result = await fn(instance);
      db.exec('COMMIT');
      return result;
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  async function migrate(steps) {
    const applied = new Set(
      db.prepare('SELECT idx FROM _bafgo_migrations').all().map(r => r.idx)
    );
    for (let i = 0; i < steps.length; i++) {
      if (applied.has(i)) continue;
      db.exec(steps[i]);
      db.prepare('INSERT INTO _bafgo_migrations (idx) VALUES (?)').run(i);
    }
  }

  function close() {
    db.close();
  }

  const instance = { query, run, transaction, migrate, close };
  return instance;
}

/**
 * Create a Postgres-backed BafgoDb for a specific plugin.
 *
 * @param {object} options
 * @param {string} options.pluginId   - Used to scope the migrations table
 * @param {string} options.url        - Postgres connection string
 * @returns {BafgoDbInstance}
 */
function createPostgresDb({ pluginId, url }) {
  // Lazy-require so hosts that only use SQLite never load pg
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url });

  // Migrations table — one per database, keyed by pluginId
  let migrationTableReady = false;

  async function ensureMigrationTable(client) {
    if (migrationTableReady) return;
    await client.query(`
      CREATE TABLE IF NOT EXISTS _bafgo_migrations (
        plugin_id TEXT NOT NULL,
        idx       INTEGER NOT NULL,
        applied   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (plugin_id, idx)
      )
    `);
    migrationTableReady = true;
  }

  /**
   * Postgres uses $1, $2, ... placeholders. The unified API sends ?.
   * We translate here so plugin code stays dialect-neutral.
   */
  function translatePlaceholders(sql) {
    let i = 0;
    return sql.replace(/\?/g, () => `$${++i}`);
  }

  async function query(sql, params = []) {
    const { rows } = await pool.query(translatePlaceholders(sql), params);
    return rows;
  }

  async function run(sql, params = []) {
    await pool.query(translatePlaceholders(sql), params);
  }

  async function transaction(fn) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Expose a thin PluginDb backed by this client for the duration
      const txDb = {
        query:       (s, p = []) => client.query(translatePlaceholders(s), p).then(r => r.rows),
        run:         (s, p = []) => client.query(translatePlaceholders(s), p).then(() => undefined),
        transaction: (innerFn)   => innerFn(txDb), // flat — nested TX not supported
        migrate:     ()          => Promise.reject(new Error('migrate() cannot be called inside a transaction')),
        close:       ()          => {},
      };
      const result = await fn(txDb);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async function migrate(steps) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await ensureMigrationTable(client);
      const { rows: applied } = await client.query(
        'SELECT idx FROM _bafgo_migrations WHERE plugin_id = $1',
        [pluginId]
      );
      const appliedSet = new Set(applied.map(r => r.idx));
      for (let i = 0; i < steps.length; i++) {
        if (appliedSet.has(i)) continue;
        await client.query(translatePlaceholders(steps[i]));
        await client.query(
          'INSERT INTO _bafgo_migrations (plugin_id, idx) VALUES ($1, $2)',
          [pluginId, i]
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async function close() {
    await pool.end();
  }

  return { query, run, transaction, migrate, close };
}

/**
 * Factory used by createPluginHost to build the right adapter.
 *
 * @param {object} options
 * @param {'sqlite'|'postgres'} options.dialect
 * @param {string} [options.file]   - Required when dialect === 'sqlite'
 * @param {string} [options.url]    - Required when dialect === 'postgres'
 * @param {string} options.pluginId
 */
function createPluginDb({ dialect, file, url, pluginId }) {
  if (dialect === 'sqlite') {
    if (!file) throw new Error(`createPluginDb: 'file' is required for sqlite dialect (plugin: ${pluginId})`);
    return createSqliteDb({ pluginId, file });
  }
  if (dialect === 'postgres') {
    if (!url) throw new Error(`createPluginDb: 'url' is required for postgres dialect (plugin: ${pluginId})`);
    return createPostgresDb({ pluginId, url });
  }
  throw new Error(`createPluginDb: unknown dialect '${dialect}' (plugin: ${pluginId})`);
}

module.exports = { createPluginDb };
