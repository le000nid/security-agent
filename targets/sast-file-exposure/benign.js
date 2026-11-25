const fs = require("fs");

function download(req, res) {
  const requestedName = req.query.name;
  res.setHeader("X-Requested-Name", requestedName);
  return fs.readFileSync("/srv/uploads/manual.txt");
}
