/** Extract Lua identifier names (variables, functions, parameters). */
export function parseLuaIdentifiers(source: string): Set<string> {
  const ids = new Set<string>();
  // local var, local var = ..., local var1, var2 = ...
  for (const m of source.matchAll(/\blocal\s+([\w,\s]+?)(?:\s*=|$)/gm)) {
    for (const name of m[1].split(",")) {
      const trimmed = name.trim();
      if (trimmed && /^\w+$/.test(trimmed)) ids.add(trimmed);
    }
  }
  // function name(...), local function name(...)
  for (const m of source.matchAll(/\bfunction\s+(\w+)\s*\(([^)]*)\)/g)) {
    ids.add(m[1]);
    for (const p of m[2].split(",")) {
      const trimmed = p.trim();
      if (trimmed && /^\w+$/.test(trimmed)) ids.add(trimmed);
    }
  }
  // for var [, var...] in/=
  for (const m of source.matchAll(/\bfor\s+([\w,\s]+?)\s+in\b/g)) {
    for (const name of m[1].split(",")) {
      const trimmed = name.trim();
      if (trimmed && /^\w+$/.test(trimmed)) ids.add(trimmed);
    }
  }
  return ids;
}

/** Parse Lua source for `Record("collection")` variable assignments. */
export function parseRecordVariables(source: string): Record<string, string> {
  const map: Record<string, string> = {};
  // Match: local var = Record("collection" and var = Record("collection"
  const re = /(?:local\s+)?(\w+)\s*=\s*Record\(\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    map[m[1]] = m[2];
  }
  return map;
}

/** Parse Lua source for `db.query({ collection = "..." })` assignments.
 *  Returns a map of variable name → collection NSID. */
export function parseDbQueryVariables(
  source: string,
): Record<string, string | null> {
  const map: Record<string, string | null> = {};
  const re = /(?:local\s+)?(\w+)\s*=\s*db\.query\s*\(\s*\{([^}]*)\}/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    const varName = m[1];
    const body = m[2];
    const colMatch = body.match(/collection\s*=\s*"([^"]+)"/);
    map[varName] = colMatch ? colMatch[1] : null;
  }
  return map;
}

/** Parse `for _, var in ipairs(result.records)` loops and resolve the
 *  iterator variable back to the collection from a db.query result.
 *  Returns a map of iterator variable name → collection NSID. */
export function parseDbQueryRecordIterators(
  source: string,
  queryVars: Record<string, string | null>,
): Record<string, string> {
  const map: Record<string, string> = {};
  const re =
    /\bfor\s+(?:\w+\s*,\s*)?(\w+)\s+in\s+i?pairs\s*\(\s*(\w+)\.records\s*\)/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    const iterVar = m[1];
    const resultVar = m[2];
    const collection = queryVars[resultVar];
    if (collection) {
      map[iterVar] = collection;
    }
  }
  return map;
}
