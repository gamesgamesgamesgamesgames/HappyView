"use client";

import { useEffect, useMemo, useState } from "react";

import { getLexicons } from "@/lib/api";
import type { LexiconSummary } from "@/types/lexicons";

/**
 * Loads the dashboard's lexicon list once on mount and exposes the NSIDs
 * grouped by the kinds the scope builder needs.
 *
 * - `records`        → lexicons with `lexicon_type === "record"` (Repository tab)
 * - `methods`        → query + procedure lexicons (RPC tab)
 * - `permissionSets` → lexicons with `lexicon_type === "definitions"`
 *   (Permission Set tab — see TODO below).
 *
 * @remarks Mirrors the fetch-on-mount pattern used by `useLuaCompletions`
 * (`web/src/hooks/use-lua-completions.ts`).
 *
 * TODO: Permission-set discovery is currently loose: we expose every
 * `definitions` lexicon as a candidate.  The precise filter is
 * `defs.main.type === "permission-set"` which would require either a
 * per-lexicon detail fetch or a backend filter; tracked as a follow-up.
 */
export function useLexiconNsids() {
  const [lexicons, setLexicons] = useState<LexiconSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getLexicons()
      .then((items) => {
        if (!cancelled) setLexicons(items);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return useMemo(() => {
    const records: string[] = [];
    const methods: string[] = [];
    const permissionSets: string[] = [];

    if (lexicons) {
      for (const l of lexicons) {
        switch (l.lexicon_type) {
          case "record":
            records.push(l.id);
            break;
          case "query":
          case "procedure":
            methods.push(l.id);
            break;
          case "definitions":
            permissionSets.push(l.id);
            break;
        }
      }
      records.sort();
      methods.sort();
      permissionSets.sort();
    }

    return {
      records,
      methods,
      permissionSets,
      isLoading: lexicons === null && error === null,
      error,
    };
  }, [lexicons, error]);
}
