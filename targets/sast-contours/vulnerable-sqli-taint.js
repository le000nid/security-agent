// Educational, never executed by the web app.
function unsafeLookup(req, database) {
  const name = req.query.name;
  const sql = `SELECT * FROM users WHERE name = '${name}'`;
  return database.query(sql);
}

module.exports = { unsafeLookup };