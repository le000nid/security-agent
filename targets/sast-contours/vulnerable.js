// Intentionally insecure educational fixture; never use as application code.

const database = {
  query(sql, params) {
    return { sql, params };
  },
};

function unsafeUserLookup(userId) {
  return database.query("SELECT * FROM users WHERE id = " + userId);
}

module.exports = { unsafeUserLookup };
