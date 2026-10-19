function templateExecute(incoming, db) {
  const supplied = incoming.query.name;
  const alias = supplied;
  // ok: javascript-sql-tainted-query
  return db.execute("SELECT * FROM users WHERE name = ?", [alias]);
}

function bracketQuery(incoming, db) {
  const supplied = incoming.body["email"];
  // ok: javascript-sql-tainted-query
  return db.query("SELECT * FROM users WHERE email = ?", [supplied]);
}

function headerExecute(incoming, db) {
  const supplied = incoming.headers["x-user-name"];
  // ok: javascript-sql-tainted-query
  return db.execute("SELECT * FROM users WHERE name = ?", [supplied]);
}

function rawCondition(incoming, knex) {
  const supplied = incoming.body.name;
  // ok: javascript-knex-sqli-taint
  return knex("users").orWhereRaw("name = ?", [supplied]);
}

module.exports = { templateExecute, bracketQuery, headerExecute, rawCondition };
