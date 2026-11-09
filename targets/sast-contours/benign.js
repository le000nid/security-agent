const database = {
  query(sql, params) {
    return { sql, params };
  },
};

function safeUserLookup(userId) {
  return database.query("SELECT * FROM users WHERE id = ?", [userId]);
}

module.exports = { safeUserLookup };
