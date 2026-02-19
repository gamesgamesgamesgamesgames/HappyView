"use client";

import { useEffect, useRef } from "react";
import dynamic from "next/dynamic";
import { useTheme } from "next-themes";
import type { editor, Position } from "monaco-editor";
import {
  LUA_KEYWORDS,
  LUA_BUILTINS,
  LUA_SNIPPETS,
  type LuaCompletions,
} from "@/lib/lua-completions";
import { lexiconJsonSchema, LEXICON_SCHEMA_URI } from "@/lib/lexicon-schema";
import { resolveCssColor } from "@/lib/css-utils";
import { parseLuaIdentifiers, parseRecordVariables } from "@/lib/lua-parser";

const Editor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

interface MonacoEditorProps {
  value: string;
  onChange?: (value: string) => void;
  language: string;
  readOnly?: boolean;
  className?: string;
  completions?: LuaCompletions;
  collections?: string[];
  tabSize?: number;
}

export function MonacoEditor({
  value,
  onChange,
  language,
  readOnly,
  className,
  completions,
  collections,
  tabSize = 2,
}: MonacoEditorProps) {
  const { resolvedTheme } = useTheme();
  const completionsRef = useRef(completions);
  const collectionsRef = useRef(collections);
  const disposablesRef = useRef<{ dispose(): void }[]>([]);

  // Sync refs during render (not in useEffect) so the completion
  // provider closure always reads the latest values immediately.
  completionsRef.current = completions;
  collectionsRef.current = collections;

  useEffect(() => {
    return () => {
      for (const d of disposablesRef.current) d.dispose();
      disposablesRef.current = [];
    };
  }, []);

  return (
    <div className={`relative ${className ?? ""}`}>
      <div className="absolute inset-0">
        <Editor
          height="100%"
          language={language}
          value={value}
          theme={resolvedTheme === "dark" ? "happyview-dark" : "vs"}
          onChange={(v) => onChange?.(v ?? "")}
          loading="Loading editor..."
          path={language === "json" ? "lexicon.json" : undefined}
          beforeMount={(monaco) => {
            const bg = resolveCssColor("var(--sidebar)");
            monaco.editor.defineTheme("happyview-dark", {
              base: "vs-dark",
              inherit: true,
              rules: [],
              colors: { "editor.background": bg },
            });

            // Configure JSON language service with Lexicon schema
            if (language === "json") {
              monaco.languages.json.jsonDefaults.setDiagnosticsOptions({
                validate: true,
                allowComments: false,
                trailingCommas: "error",
                schemas: [
                  {
                    uri: LEXICON_SCHEMA_URI,
                    fileMatch: ["lexicon.json"],
                    schema: lexiconJsonSchema,
                  },
                ],
              });
            }
          }}
          onMount={(_editor, monaco) => {
            if (language !== "lua") return;

            // Provider 1: Lua keywords, builtins, and snippets
            disposablesRef.current.push(
              monaco.languages.registerCompletionItemProvider("lua", {
                provideCompletionItems(
                  model: editor.ITextModel,
                  position: Position,
                ) {
                  const word = model.getWordUntilPosition(position);
                  const range = {
                    startLineNumber: position.lineNumber,
                    endLineNumber: position.lineNumber,
                    startColumn: word.startColumn,
                    endColumn: word.endColumn,
                  };

                  const lineContent = model.getLineContent(position.lineNumber);
                  const textBeforeCursor = lineContent.substring(
                    0,
                    position.column - 1,
                  );

                  // Don't suggest keywords after . or : (those are member access)
                  if (/[.:]$/.test(textBeforeCursor.trimEnd())) {
                    return { suggestions: [] };
                  }

                  // Extract identifiers from the current document
                  const staticLabels = new Set([
                    ...LUA_KEYWORDS,
                    ...LUA_BUILTINS,
                    ...LUA_SNIPPETS.map((s) => s.label),
                  ]);
                  const fullSource = model.getValue();
                  const identifiers = parseLuaIdentifiers(fullSource);
                  // Remove the word currently being typed
                  if (word.word) identifiers.delete(word.word);

                  const suggestions = [
                    ...LUA_KEYWORDS.map((kw) => ({
                      label: kw,
                      kind: monaco.languages.CompletionItemKind.Keyword,
                      insertText: kw,
                      detail: "keyword",
                      range,
                    })),
                    ...LUA_BUILTINS.map((fn) => ({
                      label: fn,
                      kind: monaco.languages.CompletionItemKind.Function,
                      insertText: fn,
                      detail: "function",
                      range,
                    })),
                    ...LUA_SNIPPETS.map((snip) => ({
                      label: snip.label,
                      kind: monaco.languages.CompletionItemKind.Snippet,
                      insertText: snip.insertText,
                      insertTextRules:
                        monaco.languages.CompletionItemInsertTextRule
                          .InsertAsSnippet,
                      detail: snip.detail,
                      documentation: snip.description,
                      range,
                    })),
                    ...[...identifiers]
                      .filter((id) => !staticLabels.has(id))
                      .map((id) => ({
                        label: id,
                        kind: monaco.languages.CompletionItemKind.Variable,
                        insertText: id,
                        detail: "identifier",
                        range,
                      })),
                  ];

                  return { suggestions };
                },
              }),
            );

            // Provider 2: HappyView-specific completions (Record, db, collections)
            if (!completions) return;
            disposablesRef.current.push(
              monaco.languages.registerCompletionItemProvider("lua", {
                triggerCharacters: [".", ":", '"'],
                provideCompletionItems(
                  model: editor.ITextModel,
                  position: Position,
                ) {
                  const lineContent = model.getLineContent(position.lineNumber);
                  const textBeforeCursor = lineContent.substring(
                    0,
                    position.column - 1,
                  );

                  // Record("...") collection completions
                  const recordMatch =
                    textBeforeCursor.match(/Record\(\s*"([^"]*)$/);
                  if (recordMatch) {
                    const cols = collectionsRef.current;
                    if (!cols?.length) return { suggestions: [] };
                    const quoteCol = textBeforeCursor.lastIndexOf('"');
                    const range = {
                      startLineNumber: position.lineNumber,
                      endLineNumber: position.lineNumber,
                      startColumn: quoteCol + 2, // after the opening "
                      endColumn: position.column,
                    };
                    return {
                      suggestions: cols.map((col) => ({
                        label: col,
                        kind: monaco.languages.CompletionItemKind.Value,
                        insertText: col,
                        range,
                      })),
                    };
                  }

                  // Dot or colon-triggered completions (Record., r:, db., etc.)
                  const dotMatch = textBeforeCursor.match(/(\w+)\.\w*$/);
                  const colonMatch = textBeforeCursor.match(/(\w+):\w*$/);
                  const match = dotMatch || colonMatch;
                  const isColon = !!colonMatch;
                  if (!match) return { suggestions: [] };

                  const prefix = match[1];

                  // Build entries based on context
                  let entries = completionsRef.current?.[prefix];

                  if (!entries && prefix !== "Record" && prefix !== "db") {
                    // Variable access — check if it's a Record variable
                    const fullSource = model.getValue();
                    const varMap = parseRecordVariables(fullSource);
                    const collection = varMap[prefix];

                    if (collection) {
                      // Record instance methods/fields
                      const instanceEntries =
                        completionsRef.current?.["Record"]?.filter(
                          (e) =>
                            e.detail === "method" || e.detail?.endsWith("?"),
                        ) ?? [];

                      // Collection-specific record properties (merged into completions by parent)
                      const schemaEntries =
                        completionsRef.current?.[collection] ?? [];

                      entries = [...instanceEntries, ...schemaEntries];
                    }
                  }

                  if (isColon && !entries) {
                    // Colon on unknown variable — show Record instance methods + string methods
                    const recordMethods =
                      completionsRef.current?.["Record"]?.filter(
                        (e) => e.detail === "method",
                      ) ?? [];
                    const stringMethods =
                      completionsRef.current?.["string"] ?? [];
                    entries = [...recordMethods, ...stringMethods];
                  }

                  if (!entries?.length) return { suggestions: [] };

                  const word = model.getWordUntilPosition(position);
                  const range = {
                    startLineNumber: position.lineNumber,
                    endLineNumber: position.lineNumber,
                    startColumn: word.startColumn,
                    endColumn: word.endColumn,
                  };

                  return {
                    suggestions: entries.map((entry) => ({
                      label: entry.label,
                      kind:
                        entry.detail === "method" || entry.detail === "function"
                          ? monaco.languages.CompletionItemKind.Method
                          : monaco.languages.CompletionItemKind.Field,
                      detail: entry.detail,
                      documentation: entry.description,
                      insertText: entry.label,
                      range,
                    })),
                  };
                },
              }),
            );
          }}
          options={{
            readOnly,
            minimap: { enabled: false },
            automaticLayout: true,
            scrollBeyondLastLine: false,
            wordWrap: "on",
            fontSize: 12,
            tabSize,
            snippetSuggestions: "inline",
            renderLineHighlight: readOnly ? "none" : "line",
            hideCursorInOverviewRuler: readOnly,
            overviewRulerLanes: readOnly ? 0 : 3,
            quickSuggestions: true,
          }}
        />
      </div>
    </div>
  );
}
