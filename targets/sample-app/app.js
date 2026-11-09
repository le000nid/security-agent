// Intentionally insecure educational fixtures; never use as application code.
const child_process = require("child_process");
const apiKey = "training-secret-value";
const options = { rejectUnauthorized: false };

function examples(expression) {
  child_process.exec("echo training");
  return eval(expression);
}

module.exports = { apiKey, options, examples };
