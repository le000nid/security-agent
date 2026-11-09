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
  // ok: javascript-sql-tainted-query
  return db.execute("SELECT * FROM users WHERE id = ?", [alias]);
}

function typedHaving(incoming: HttpInput, query: RawQuery) {
  const supplied = incoming.headers["x-min-total"];
  // ok: javascript-knex-sqli-taint
  return query.havingRaw("COUNT(*) > ?", [supplied]);
}

export { typedExecute, typedHaving };
