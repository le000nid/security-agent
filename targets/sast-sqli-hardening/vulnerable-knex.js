// Case 1: unsafe Knex raw query
function unsafeRaw(req, knex) {
  const name = req.query.name;

  return knex.raw(
    `SELECT * FROM users WHERE name = '${name}'`
  );
}

// Case 2: unsafe Knex whereRaw
function unsafeWhereRaw(req, knex) {
  const id = req.params.id;
  const condition = "id = " + id;

  return knex("users").whereRaw(condition);
}

module.exports = { unsafeRaw, unsafeWhereRaw };