interface HttpInput {
  params: Record<string, string>;
  headers: Record<string, string>;
}

interface Database {
  execute(sql: string, values?: unknown[]): unknown;
}

interface RawQuery {
  havingRaw(sql: string, values?: unknown[]): unknown;
}

function typedExecute(incoming: HttpInput, db: Database) {
  const supplied: string = incoming.params.id;
  const alias = supplied;
  const sql = `SELECT * FROM users WHERE id = ${alias}`;
  // ruleid: javascript-sql-tainted-query
  return db.execute(sql);
}

function typedHaving(incoming: HttpInput, query: RawQuery) {
  const supplied = incoming.headers["x-min-total"];
  const sql = `COUNT(*) > ${supplied}`;
  // ruleid: javascript-knex-sqli-taint
  return query.havingRaw(sql);
}

export { typedExecute, typedHaving };
