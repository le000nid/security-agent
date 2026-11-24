const fs = require("fs");

function download(req, res) {
  const name = req.query.name;
  res.sendFile("/srv/uploads/" + name);
  return fs.readFileSync("/srv/uploads/" + name);
}
