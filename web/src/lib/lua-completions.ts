export interface LuaCompletionEntry {
  label: string;
  detail?: string;
  description?: string;
  insertText?: string;
}

export interface LuaSnippetEntry {
  label: string;
  insertText: string;
  detail: string;
  description?: string;
}

export const LUA_KEYWORDS = [
  "and", "break", "do", "else", "elseif", "end", "false",
  "for", "function", "goto", "if", "in", "local", "nil",
  "not", "or", "repeat", "return", "then", "true", "until", "while",
];

export const LUA_BUILTINS = [
  "print", "tostring", "tonumber", "type", "pairs", "ipairs", "next",
  "select", "unpack", "error", "pcall", "xpcall", "assert",
  "setmetatable", "getmetatable", "rawget", "rawset", "rawequal",
  // Standard library modules
  "string", "table", "math", "coroutine", "utf8",
  // HappyView sandbox globals
  "input", "params", "caller_did", "collection", "method",
  "now", "log", "TID",
];

export const LUA_SNIPPETS: LuaSnippetEntry[] = [
  {
    label: "if",
    insertText: "if ${1:condition} then\n\t$0\nend",
    detail: "if ... then ... end",
  },
  {
    label: "if",
    insertText: "if ${1:condition} then\n\t$2\nelse\n\t$0\nend",
    detail: "if ... then ... else ... end",
  },
  {
    label: "if",
    insertText: "if ${1:condition} then\n\t$2\nelseif ${3:condition} then\n\t$0\nend",
    detail: "if ... then ... elseif ... end",
  },
  {
    label: "elseif",
    insertText: "elseif ${1:condition} then\n\t$0",
    detail: "elseif ... then",
  },
  {
    label: "for",
    insertText: "for ${1:i} = ${2:1}, ${3:10} do\n\t$0\nend",
    detail: "for i = start, stop do ... end",
  },
  {
    label: "for",
    insertText: "for ${1:i}, ${2:v} in ipairs(${3:t}) do\n\t$0\nend",
    detail: "for i, v in ipairs(t) do ... end",
  },
  {
    label: "for",
    insertText: "for ${1:k}, ${2:v} in pairs(${3:t}) do\n\t$0\nend",
    detail: "for k, v in pairs(t) do ... end",
  },
  {
    label: "while",
    insertText: "while ${1:condition} do\n\t$0\nend",
    detail: "while ... do ... end",
  },
  {
    label: "repeat",
    insertText: "repeat\n\t$0\nuntil ${1:condition}",
    detail: "repeat ... until ...",
  },
  {
    label: "function",
    insertText: "function ${1:name}(${2:})\n\t$0\nend",
    detail: "function name(...) ... end",
  },
  {
    label: "function",
    insertText: "local function ${1:name}(${2:})\n\t$0\nend",
    detail: "local function name(...) ... end",
  },
  {
    label: "local",
    insertText: "local ${1:name} = ${0}",
    detail: "local name = ...",
  },
  {
    label: "return",
    insertText: "return ${0}",
    detail: "return ...",
  },
];

export type LuaCompletions = Record<string, LuaCompletionEntry[]>;

/** Map of collection NSID → record property completions */
export type CollectionSchemas = Record<string, LuaCompletionEntry[]>;

const STATIC_COMPLETIONS: LuaCompletions = {
  Record: [
    { label: "save_all", detail: "function", description: "Save multiple records in parallel — Record.save_all({ r1, r2 })" },
    { label: "load", detail: "function", description: "Load a record from the database by AT URI — Record.load(uri)" },
    { label: "load_all", detail: "function", description: "Load multiple records from the database — Record.load_all({ uri1, uri2 })" },
    { label: "save", detail: "method", description: "Save this record (creates or updates) — r:save()" },
    { label: "delete", detail: "method", description: "Delete this record from PDS and database — r:delete()" },
    { label: "set_key_type", detail: "method", description: "Set the record key type (tid, any, nsid, literal:*) — r:set_key_type(type)" },
    { label: "set_rkey", detail: "method", description: "Set a specific rkey for this record — r:set_rkey(key)" },
    { label: "generate_rkey", detail: "method", description: "Generate an rkey based on _key_type — r:generate_rkey()" },
    { label: "_uri", detail: "string?", description: "AT URI of the record (set after save)" },
    { label: "_cid", detail: "string?", description: "CID of the record (set after save)" },
    { label: "_key_type", detail: "string?", description: "Record key type from lexicon (tid, any, nsid, literal:*)" },
    { label: "_rkey", detail: "string?", description: "Record key (set via set_rkey or generate_rkey)" },
  ],
  db: [
    {
      label: "query",
      detail: "function",
      description: "Query records — db.query({ collection, did?, limit?, offset? }) → { records, cursor? }",
      insertText: "query({\n\tcollection = ${1:collection},\n})",
    },
    {
      label: "get",
      detail: "function",
      description: "Get a single record by AT URI — db.get(uri) → record or nil",
      insertText: "get(${1:uri})",
    },
    {
      label: "count",
      detail: "function",
      description: "Count records — db.count(collection, did?) → integer",
      insertText: "count(${1:collection})",
    },
  ],
  "db.query": [
    { label: "collection", detail: "string", description: "Collection NSID (required)" },
    { label: "did", detail: "string?", description: "Filter records by DID" },
    { label: "limit", detail: "integer?", description: "Max records to return (max 100, default 20)" },
    { label: "offset", detail: "integer?", description: "Pagination offset (default 0)" },
  ],
  "db.query_result": [
    { label: "records", detail: "table[]", description: "Array of record tables (each includes uri)" },
    { label: "cursor", detail: "string?", description: "Pagination cursor (present when more results exist)" },
  ],
  // Lua standard library modules
  string: [
    { label: "byte", detail: "function", description: "Returns internal numeric codes of characters — string.byte(s [, i [, j]])" },
    { label: "char", detail: "function", description: "Returns a string from character codes — string.char(···)" },
    { label: "find", detail: "function", description: "Find first match of pattern — string.find(s, pattern [, init [, plain]])" },
    { label: "format", detail: "function", description: "Format a string — string.format(formatstring, ···)" },
    { label: "gmatch", detail: "function", description: "Returns an iterator for all matches — string.gmatch(s, pattern)" },
    { label: "gsub", detail: "function", description: "Global substitution — string.gsub(s, pattern, repl [, n])" },
    { label: "len", detail: "function", description: "Returns the length of a string — string.len(s)" },
    { label: "lower", detail: "function", description: "Returns lowercase copy — string.lower(s)" },
    { label: "match", detail: "function", description: "Find first match and return captures — string.match(s, pattern [, init])" },
    { label: "rep", detail: "function", description: "Returns a repeated copy — string.rep(s, n [, sep])" },
    { label: "reverse", detail: "function", description: "Returns reversed string — string.reverse(s)" },
    { label: "sub", detail: "function", description: "Returns a substring — string.sub(s, i [, j])" },
    { label: "upper", detail: "function", description: "Returns uppercase copy — string.upper(s)" },
  ],
  table: [
    { label: "concat", detail: "function", description: "Concatenate table elements — table.concat(list [, sep [, i [, j]]])" },
    { label: "insert", detail: "function", description: "Insert element — table.insert(list, [pos,] value)" },
    { label: "move", detail: "function", description: "Move elements between tables — table.move(a1, f, e, t [, a2])" },
    { label: "pack", detail: "function", description: "Pack arguments into table with n field — table.pack(···)" },
    { label: "remove", detail: "function", description: "Remove element — table.remove(list [, pos])" },
    { label: "sort", detail: "function", description: "Sort table in-place — table.sort(list [, comp])" },
    { label: "unpack", detail: "function", description: "Unpack table elements — table.unpack(list [, i [, j]])" },
  ],
  math: [
    { label: "abs", detail: "function", description: "Absolute value — math.abs(x)" },
    { label: "acos", detail: "function", description: "Arc cosine — math.acos(x)" },
    { label: "asin", detail: "function", description: "Arc sine — math.asin(x)" },
    { label: "atan", detail: "function", description: "Arc tangent — math.atan(y [, x])" },
    { label: "ceil", detail: "function", description: "Round up — math.ceil(x)" },
    { label: "cos", detail: "function", description: "Cosine — math.cos(x)" },
    { label: "deg", detail: "function", description: "Radians to degrees — math.deg(x)" },
    { label: "exp", detail: "function", description: "e^x — math.exp(x)" },
    { label: "floor", detail: "function", description: "Round down — math.floor(x)" },
    { label: "fmod", detail: "function", description: "Remainder — math.fmod(x, y)" },
    { label: "log", detail: "function", description: "Logarithm — math.log(x [, base])" },
    { label: "max", detail: "function", description: "Maximum value — math.max(x, ···)" },
    { label: "maxinteger", detail: "number", description: "Maximum integer value" },
    { label: "min", detail: "function", description: "Minimum value — math.min(x, ···)" },
    { label: "mininteger", detail: "number", description: "Minimum integer value" },
    { label: "modf", detail: "function", description: "Integer and fractional parts — math.modf(x)" },
    { label: "rad", detail: "function", description: "Degrees to radians — math.rad(x)" },
    { label: "random", detail: "function", description: "Generate random number — math.random([m [, n]])" },
    { label: "randomseed", detail: "function", description: "Set random seed — math.randomseed([x [, y]])" },
    { label: "sin", detail: "function", description: "Sine — math.sin(x)" },
    { label: "sqrt", detail: "function", description: "Square root — math.sqrt(x)" },
    { label: "tan", detail: "function", description: "Tangent — math.tan(x)" },
    { label: "tointeger", detail: "function", description: "Convert to integer or nil — math.tointeger(x)" },
    { label: "type", detail: "function", description: "Number type (\"integer\", \"float\", or false) — math.type(x)" },
    { label: "ult", detail: "function", description: "Unsigned integer comparison — math.ult(m, n)" },
    { label: "huge", detail: "number", description: "Infinity value" },
    { label: "pi", detail: "number", description: "Pi constant (3.14159...)" },
  ],
  coroutine: [
    { label: "create", detail: "function", description: "Create a coroutine — coroutine.create(f)" },
    { label: "resume", detail: "function", description: "Resume a coroutine — coroutine.resume(co [, val1, ···])" },
    { label: "yield", detail: "function", description: "Suspend coroutine — coroutine.yield(···)" },
    { label: "status", detail: "function", description: "Coroutine status — coroutine.status(co)" },
    { label: "wrap", detail: "function", description: "Create iterator from coroutine — coroutine.wrap(f)" },
    { label: "isyieldable", detail: "function", description: "Check if running coroutine can yield — coroutine.isyieldable()" },
    { label: "running", detail: "function", description: "Returns running coroutine — coroutine.running()" },
    { label: "close", detail: "function", description: "Close a coroutine — coroutine.close(co)" },
  ],
  utf8: [
    { label: "char", detail: "function", description: "UTF-8 string from codepoints — utf8.char(···)" },
    { label: "charpattern", detail: "string", description: "Pattern matching one UTF-8 character" },
    { label: "codepoint", detail: "function", description: "Codepoints from string — utf8.codepoint(s [, i [, j [, lax]]])" },
    { label: "codes", detail: "function", description: "Iterator over UTF-8 codepoints — utf8.codes(s [, lax])" },
    { label: "len", detail: "function", description: "UTF-8 string length — utf8.len(s [, i [, j [, lax]]])" },
    { label: "offset", detail: "function", description: "Byte offset of nth character — utf8.offset(s, n [, i])" },
  ],
};

/** Extract property completions from a record schema object (`defs.main.record`). */
export function extractSchemaProperties(
  schema: Record<string, unknown> | null | undefined,
): LuaCompletionEntry[] {
  if (!schema) return [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const props = (schema as any)?.properties;
  if (!props || typeof props !== "object") return [];

  return Object.keys(props).map((key) => ({
    label: key,
    detail: props[key]?.type ?? "property",
    description: props[key]?.description,
  }));
}

/** Build a collection → property completions map from lexicon details.
 *  Extracts record properties from `lexicon_json.defs.main.record`. */
export function buildCollectionSchemas(
  lexicons: {
    id: string;
    lexicon_json?: Record<string, unknown> | null;
  }[],
): CollectionSchemas {
  const schemas: CollectionSchemas = {};
  for (const lex of lexicons) {
    if (!lex.lexicon_json) continue;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mainDef = (lex.lexicon_json as any)?.defs?.main;
    if (mainDef?.type === "record") {
      const props = extractSchemaProperties(mainDef.record);
      if (props.length) schemas[lex.id] = props;
    }
  }
  return schemas;
}

export function extractLuaCompletions(lexiconJson: string): LuaCompletions {
  const completions: LuaCompletions = { ...STATIC_COMPLETIONS };

  try {
    const parsed = JSON.parse(lexiconJson);
    const mainDef = parsed?.defs?.main;
    if (!mainDef) return completions;

    if (mainDef.type === "procedure") {
      const props = mainDef.input?.schema?.properties;
      if (props && typeof props === "object") {
        completions.input = Object.keys(props).map((key) => ({
          label: key,
          detail: props[key]?.type ?? "property",
          description: props[key]?.description,
        }));
      }
    } else if (mainDef.type === "query") {
      const props = mainDef.parameters?.properties;
      if (props && typeof props === "object") {
        completions.params = Object.keys(props).map((key) => ({
          label: key,
          detail: props[key]?.type ?? "property",
          description: props[key]?.description,
        }));
      }
    }
  } catch {
    // Invalid JSON — return static completions only
  }

  return completions;
}
