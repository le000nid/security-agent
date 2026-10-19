// Case 1: bound parameter in raw
function safeRaw(req, knex) {
  return knex.raw(
    "SELECT * FROM users WHERE name = ?",
    [req.query.name]
  );
}

// Case 2: bound parameter in whereRaw
function safeWhereRaw(req, knex) {
  return knex("users").whereRaw(
    "id = ?",
    [req.params.id]
  );
}

module.exports = { safeRaw, safeWhereRaw };