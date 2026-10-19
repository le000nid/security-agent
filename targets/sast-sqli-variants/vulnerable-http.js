// Independent functions: request aliases, intermediate values and SQL variants.
function templateExecute(incoming, db) {
  const supplied = incoming.query.name;
  const alias = supplied;
  const sql = `SELECT * FROM users WHERE name = '${alias}'`;
  // ruleid: javascript-sql-tainted-query
  return db.execute(sql);
}

function bracketQuery(incoming, db) {
  const supplied = incoming.body["email"];
  const sql = "SELECT * FROM users WHERE email = '" + supplied + "'";
  // ruleid: javascript-sql-tainted-query
  return db.query(sql);
}

function headerExecute(incoming, db) {
  const supplied = incoming.headers["x-user-name"];
  const sql = `SELECT * FROM users WHERE name = '${supplied}'`;
  // ruleid: javascript-sql-tainted-query
  return db.execute(sql);
}

function rawCondition(incoming, knex) {
  const supplied = incoming.body.name;
  const condition = `name = '${supplied}'`;
  // ruleid: javascript-knex-sqli-taint
  return knex("users").orWhereRaw(condition);
}

module.exports = { templateExecute, bracketQuery, headerExecute, rawCondition };
