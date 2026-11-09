// Bound values do not change the SQL query text.
function safeLookup(req, database) {
  return database.query(
    "SELECT * FROM users WHERE name = ?",
    [req.query.name]
  );
}

module.exports = { safeLookup };