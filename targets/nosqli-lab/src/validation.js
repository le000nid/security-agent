export class InputError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

export function requireObject(value, name = "body") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InputError(`${name} must be an object`);
  }
}

export function requireKeys(value, allowed) {
  requireObject(value);
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new InputError("Unexpected input field");
  }
}

export function requireString(value, name) {
  if (typeof value !== "string" || value.length < 1 || value.length > 80) {
    throw new InputError(`${name} must be a string of 1 to 80 characters`);
  }
}
