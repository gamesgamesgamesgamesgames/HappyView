"use client";

import { useEffect, useState } from "react";
import type { BundledLanguage } from "shiki/bundle/web";
import type React from "react";
import { cn } from "@/lib/utils";

async function highlight(code: string, lang: BundledLanguage) {
  const { codeToHast } = await import("shiki/bundle/web");
  const { toJsxRuntime } = await import("hast-util-to-jsx-runtime");
  const { Fragment, jsx, jsxs } = await import("react/jsx-runtime");

  const hast = await codeToHast(code, {
    lang,
    themes: {
      light: "github-light",
      dark: "github-dark",
    },
    defaultColor: false,
  });

  return toJsxRuntime(hast, {
    Fragment,
    jsx,
    jsxs,
    components: {
      pre: ({ style, ...props }: React.ComponentProps<"pre">) => (
        <pre
          className="p-4 text-xs"
          style={{
            ...style,
            backgroundColor: "transparent",
          }}
          {...props}
        />
      ),
      code: (props: React.ComponentProps<"code">) => (
        <code className="whitespace-pre" {...props} />
      ),
    },
  }) as React.JSX.Element;
}

interface CodeBlockProps {
  code: string;
  lang?: BundledLanguage;
  className?: string;
}

export function CodeBlock({ code, lang = "json", className }: CodeBlockProps) {
  const [nodes, setNodes] = useState<React.JSX.Element | null>(null);

  useEffect(() => {
    void highlight(code, lang).then(setNodes);
  }, [code, lang]);

  return (
    <div
      className={cn(
        "bg-muted min-w-0 max-h-[70vh] overflow-auto rounded-md",
        className,
      )}
    >
      <div className="w-fit min-w-full">
        <div className="bg-muted-foreground/10 sticky top-0 px-4 py-2 text-xs font-medium text-muted-foreground">
          {lang}
        </div>
        {nodes ?? (
          <pre className="p-4 text-xs">
            <code className="whitespace-pre">{code}</code>
          </pre>
        )}
      </div>
    </div>
  );
}
