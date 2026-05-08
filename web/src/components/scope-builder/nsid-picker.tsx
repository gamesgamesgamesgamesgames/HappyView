"use client";

import { Asterisk, X } from "lucide-react";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from "@/components/ui/combobox";

const WILDCARD = "*";

export interface NsidPickerProps {
  values: string[];
  onChange: (next: string[]) => void;
  /** Registered NSIDs available to pick. Wildcard `*` is added separately via `allowWildcard`. */
  options: string[];
  placeholder?: string;
  /** When true, prepend a synthetic `*` (all) option. Defaults to true. */
  allowWildcard?: boolean;
  /** Disables the picker (used while loading). */
  disabled?: boolean;
  /** Called whenever the input changes for outer error messaging if needed. */
  inputId?: string;
  /** Hint shown when there are no registered lexicons of this kind. */
  emptyHint?: string;
}

/**
 * A multi-value NSID picker.  Renders existing chips and a single-select
 * Combobox below for adding more.  In strict mode (the only mode), only
 * registered options + the wildcard `*` are addable.
 */
export function NsidPicker({
  values,
  onChange,
  options,
  placeholder = "Select an NSID…",
  allowWildcard = true,
  disabled = false,
  inputId,
  emptyHint,
}: NsidPickerProps) {
  const [query, setQuery] = useState("");

  const choices = useMemo(() => {
    const list = [...options];
    if (allowWildcard) list.unshift(WILDCARD);
    return list.filter((o) => !values.includes(o));
  }, [options, values, allowWildcard]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return choices;
    return choices.filter((c) => c.toLowerCase().includes(q));
  }, [choices, query]);

  function add(value: string) {
    if (!value) return;
    if (values.includes(value)) return;
    onChange([...values, value]);
    setQuery("");
  }

  function remove(value: string) {
    onChange(values.filter((v) => v !== value));
  }

  const noOptions = options.length === 0;

  return (
    <div className="flex flex-col gap-2">
      {values.length > 0 && (
        <ul className="flex flex-wrap gap-1.5">
          {values.map((v) => (
            <li
              key={v}
              className="bg-muted text-foreground inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs font-medium font-mono"
            >
              {v === WILDCARD ? (
                <span className="inline-flex items-center gap-1">
                  <Asterisk className="size-3" /> all
                </span>
              ) : (
                v
              )}
              <Button
                type="button"
                variant="ghost"
                size="icon-xs"
                className="-mr-0.5 size-4 opacity-50 hover:opacity-100"
                title="Remove"
                onClick={() => remove(v)}
                disabled={disabled}
              >
                <X className="size-3" />
              </Button>
            </li>
          ))}
        </ul>
      )}
      <Combobox
        items={filtered}
        inputValue={query}
        onInputValueChange={(v, details) => {
          if (details?.reason === "input-change") setQuery(v);
        }}
        onValueChange={(v) => {
          if (typeof v === "string") add(v);
        }}
        filter={null}
        disabled={disabled || noOptions}
      >
        <ComboboxInput
          className="w-full"
          id={inputId}
          placeholder={noOptions ? (emptyHint ?? "No registered NSIDs") : placeholder}
          disabled={disabled || noOptions}
        />
        <ComboboxContent className="min-w-(--anchor-width)">
          <ComboboxList>
            {(item: string) => (
              <ComboboxItem key={item} value={item}>
                <span className="font-mono text-xs">
                  {item === WILDCARD ? "* — all" : item}
                </span>
              </ComboboxItem>
            )}
          </ComboboxList>
          <ComboboxEmpty>No matches.</ComboboxEmpty>
        </ComboboxContent>
      </Combobox>
    </div>
  );
}
