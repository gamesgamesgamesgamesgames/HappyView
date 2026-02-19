export const LEXICON_TEMPLATE = JSON.stringify(
  {
    $type: "com.atproto.lexicon.schema",
    lexicon: 1,
    id: "",
    defs: {
      main: {
        type: "record",
        key: "tid",
        record: {
          type: "object",
          required: [],
          properties: {},
        },
      },
    },
  },
  null,
  2,
)

export function procedureScript(collection: string): string {
  const target = collection || "COLLECTION"
  return `function handle()
\tlocal r = Record("${target}", input)
\tr:save()
\treturn { uri = r._uri, cid = r._cid }
end
`
}

export function queryScript(collection: string): string {
  const target = collection || "COLLECTION"
  return `collection = "${target}"

function handle()
\tif params.uri then
\t\tlocal record = db.get(params.uri)
\t\tif not record then
\t\t\terror("record not found")
\t\tend
\t\treturn { record = record }
\tend

\treturn db.query({
\t\tcollection = collection,
\t\tdid = params.did,
\t\tlimit = params.limit,
\t\tcursor = params.cursor,
\t})
end
`
}
