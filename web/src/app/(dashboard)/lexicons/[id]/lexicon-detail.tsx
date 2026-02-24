"use client";

import { useCallback, useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import { useAuth } from "@/lib/auth-context";
import { CodePanels } from "@/components/code-panels";
import {
  deleteLexicon,
  deleteNetworkLexicon,
  getLexicon,
  uploadLexicon,
  type LexiconDetail,
} from "@/lib/api";
import { procedureScript, queryScript } from "@/lib/lua-templates";
import { useLuaCompletions } from "@/hooks/use-lua-completions";
import { SiteHeader } from "@/components/site-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

export default function LexiconDetailPage() {
  const pathname = usePathname();
  const id = decodeURIComponent(pathname.split("/").filter(Boolean).pop() ?? "");
  const { getToken } = useAuth();
  const router = useRouter();
  const [lexicon, setLexicon] = useState<LexiconDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [saving, setSaving] = useState(false);

  // Editable text state
  const [jsonText, setJsonText] = useState("");
  const [luaText, setLuaText] = useState("");
  const [originalJson, setOriginalJson] = useState("");
  const [originalLua, setOriginalLua] = useState("");
  const { luaCompletions, collections } = useLuaCompletions(jsonText);

  const load = useCallback(() => {
    getLexicon(getToken, id)
      .then((lex) => {
        setLexicon(lex);
        const json = JSON.stringify(lex.lexicon_json, null, 2);
        setJsonText(json);
        setOriginalJson(json);

        // If lexicon has no script but is a query/procedure, auto-generate one
        if (
          !lex.script &&
          (lex.lexicon_type === "query" || lex.lexicon_type === "procedure")
        ) {
          const generated =
            lex.lexicon_type === "procedure"
              ? procedureScript(lex.target_collection ?? "")
              : queryScript(lex.target_collection ?? "");
          setLuaText(generated);
          // Set originalLua to "" so isDirty becomes true, prompting user to save
          setOriginalLua("");
        } else {
          setLuaText(lex.script ?? "");
          setOriginalLua(lex.script ?? "");
        }
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [getToken, id]);

  useEffect(() => {
    load();
  }, [load]);

  const isDirty = jsonText !== originalJson || luaText !== originalLua;

  async function handleSave() {
    if (!lexicon) return;
    setSaving(true);
    setError(null);
    try {
      const lexiconJson = JSON.parse(jsonText);
      await uploadLexicon(getToken, {
        lexicon_json: lexiconJson,
        backfill: lexicon.backfill,
        script: luaText || undefined,
      });
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!lexicon) return;
    setDeleting(true);
    try {
      if (lexicon.source === "network") {
        await deleteNetworkLexicon(getToken, lexicon.id);
      } else {
        await deleteLexicon(getToken, lexicon.id);
      }
      router.push("/lexicons");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setDeleting(false);
    }
  }

  if (error && !lexicon) {
    return (
      <>
        <SiteHeader title="Lexicon" backHref="/lexicons" />
        <div className="p-4 md:p-6">
          <p className="text-destructive text-sm">{error}</p>
        </div>
      </>
    );
  }

  if (!lexicon) {
    return (
      <>
        <SiteHeader title="Lexicon" backHref="/lexicons" />
        <div className="p-4 md:p-6">
          <p className="text-muted-foreground text-sm">Loading...</p>
        </div>
      </>
    );
  }

  const isNetwork = lexicon.source === "network";
  const showLua =
    lexicon.has_script ||
    lexicon.lexicon_type === "query" ||
    lexicon.lexicon_type === "procedure";

  return (
    <div className="flex flex-col h-full max-h-screen md:max-h-[calc(100vh-((var(--spacing)*2)*2))] overflow-hidden">
      <SiteHeader title={lexicon.id} backHref="/lexicons" />
      <div className="flex flex-col flex-1 min-h-0 gap-6 items-stretch overflow-hidden">
        <div className="p-4 md:p-6">
          {error && <p className="text-destructive text-sm mb-4">{error}</p>}

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-3 lg:grid-cols-4">
            <div>
              <Label className="text-muted-foreground">Type</Label>
              <div className="mt-1">
                <Badge variant="outline">{lexicon.lexicon_type}</Badge>
              </div>
            </div>
            <div>
              <Label className="text-muted-foreground">Source</Label>
              <div className="mt-1">
                <Badge variant={isNetwork ? "secondary" : "outline"}>
                  {lexicon.source}
                </Badge>
              </div>
            </div>
            <div>
              <Label className="text-muted-foreground">Revision</Label>
              <p className="mt-1 tabular-nums">{lexicon.revision}</p>
            </div>
            {lexicon.lexicon_type === "record" && (
              <div>
                <Label className="text-muted-foreground">Backfill</Label>
                <p className="mt-1">{lexicon.backfill ? "Yes" : "No"}</p>
              </div>
            )}
            {lexicon.authority_did && (
              <div className="col-span-2">
                <Label className="text-muted-foreground">Authority DID</Label>
                <p className="mt-1 font-mono text-sm break-all">
                  {lexicon.authority_did}
                </p>
              </div>
            )}
            <div>
              <Label className="text-muted-foreground">Created</Label>
              <p className="mt-1 text-sm">
                {new Date(lexicon.created_at).toLocaleString()}
              </p>
            </div>
            <div>
              <Label className="text-muted-foreground">Updated</Label>
              <p className="mt-1 text-sm">
                {new Date(lexicon.updated_at).toLocaleString()}
              </p>
            </div>
            {lexicon.last_fetched_at && (
              <div>
                <Label className="text-muted-foreground">Last Fetched</Label>
                <p className="mt-1 text-sm">
                  {new Date(lexicon.last_fetched_at).toLocaleString()}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Code Panels */}
        <CodePanels
          className="flex-1 min-h-0 px-4 md:px-6"
          jsonValue={jsonText}
          onJsonChange={isNetwork ? undefined : setJsonText}
          jsonReadOnly={isNetwork}
          luaValue={showLua ? luaText : undefined}
          onLuaChange={showLua ? setLuaText : undefined}
          luaCompletions={showLua ? luaCompletions : undefined}
          collections={showLua ? collections : undefined}
        />

        {/* Actions */}
        <footer className="bg-sidebar-accent flex justify-between gap-2 ps-4 py-2 md:px-6 md:py-4 rounded-b-md">
          <Button
            variant="destructive"
            onClick={handleDelete}
            disabled={deleting}
          >
            {deleting ? "Deleting..." : "Delete Lexicon"}
          </Button>

          <Button onClick={handleSave} disabled={!isDirty || saving}>
            {saving ? "Saving..." : "Save"}
          </Button>
        </footer>
      </div>
    </div>
  );
}
