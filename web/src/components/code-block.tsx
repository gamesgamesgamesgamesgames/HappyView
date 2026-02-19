"use client";

import type { BundledLanguage } from "shiki/bundle/web";
import { codeToHast } from "shiki/bundle/web";
import { cn } from "@/lib/utils";
import { ComponentProps, type ReactNode, useEffect, useState } from "react";
import { Fragment, jsx, jsxs } from "react/jsx-runtime";
import { toJsxRuntime } from "hast-util-to-jsx-runtime";

async function highlight(code: string, lang: BundledLanguage) {
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
      pre: ({ className, style, ...props }: ComponentProps<"pre">) => (
        <pre
          className={cn(className, "p-4 text-xs")}
          style={{
            ...style,
            backgroundColor: "transparent",
          }}
          {...props}
        />
      ),
      code: (props: ComponentProps<"code">) => (
        <code className="whitespace-pre" {...props} />
      ),
    },
  }) as ReactNode;
}

interface CodeBlockProps {
  code: string;
  lang?: string;
  className?: string;
}

export function CodeBlock({ code, lang = "json", className }: CodeBlockProps) {
  const [nodes, setNodes] = useState<ReactNode | null>(null);

  useEffect(() => {
    void highlight(code, lang as BundledLanguage)
      .then(setNodes)
      .catch(() => {
        // Unsupported language — leave plain text fallback
      });
  }, [code, lang]);

  return (
    <div className={cn("bg-muted min-w-0 overflow-auto", className)}>
      <div className="w-fit min-w-full">
        {nodes ?? (
          <pre className="p-4 text-xs">
            <code className="whitespace-pre">{code}</code>
          </pre>
        )}
      </div>
    </div>
  );
}
