// Reading and writing one key inside a JSON settings file, as pure functions.
//
// Chromium-family browsers keep their preferences as one minified JSON object
// and rewrite the whole file themselves, so parsing and re-serialising it is
// exactly what the browser does. That is the only reason this is safe: the file
// has no comments and no formatting worth preserving.
//
// It is deliberately NOT used on hand-edited settings files (a VS Code
// settings.json, for instance) — those hold comments and an ordering their
// author chose, and reformatting someone's file to change one key is damage.

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

const isObject = (v: Json): v is { [k: string]: Json } =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** The value at a dotted path, as a JSON literal, or null when the path is not
 *  present. A key holding JSON `null` reads back as the string "null", which is
 *  a value; absence is the JavaScript null. */
export function readJsonPath(text: string, path: string): string | null {
  let node: Json;
  try {
    node = JSON.parse(text);
  } catch {
    return null;
  }
  for (const part of path.split(".")) {
    if (!isObject(node) || !(part in node)) return null;
    node = node[part]!;
  }
  return JSON.stringify(node);
}

/** Set a dotted path, creating intermediate objects, and return the file's new
 *  text. `literal` is JSON source: `true`, `2`, `"text"`.
 *
 *  Throws rather than guessing when the file is not JSON, or when a path
 *  segment holds something that is not an object — silently replacing a value
 *  with an object would corrupt the profile. */
export function upsertJsonPath(
  text: string,
  path: string,
  literal: string,
): string {
  const root: Json = text.trim() === "" ? {} : JSON.parse(text);
  if (!isObject(root)) throw new Error("settings file is not a JSON object");

  const parts = path.split(".");
  const last = parts.pop()!;
  let node: { [k: string]: Json } = root;
  for (const part of parts) {
    const next = node[part];
    if (next === undefined) node[part] = {};
    else if (!isObject(next)) {
      throw new Error(`${path}: ${part} is not an object`);
    }
    node = node[part] as { [k: string]: Json };
  }
  node[last] = JSON.parse(literal) as Json;
  return JSON.stringify(root);
}
