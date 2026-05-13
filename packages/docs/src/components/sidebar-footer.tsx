'use client';

import { SidebarCollapseTrigger } from 'fumadocs-ui/components/sidebar/base';
import { ThemeSwitch } from 'fumadocs-ui/layouts/shared/slots/theme-switch';
import { SidebarIcon, Zap, ZapOff } from 'lucide-react';
import { useReducedMotion } from '@/lib/reduced-motion';

export function SidebarFooter() {
  const { reducedMotion, override, setOverride } = useReducedMotion();

  function cycleMotion() {
    if (override === null) {
      setOverride(!reducedMotion);
    } else {
      setOverride(null);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <ThemeSwitch />
      <button
        type="button"
        onClick={cycleMotion}
        aria-label="Toggle Motion"
        title={
          override === null
            ? 'Motion: system preference'
            : reducedMotion
              ? 'Motion: reduced'
              : 'Motion: full'
        }
        className="inline-flex items-center rounded-full border p-1 overflow-hidden *:rounded-full"
      >
        <ZapOff
          fill="currentColor"
          className={`size-6.5 p-1.5 ${reducedMotion ? 'bg-fd-accent text-fd-accent-foreground' : 'text-fd-muted-foreground'}`}
        />
        <Zap
          fill="currentColor"
          className={`size-6.5 p-1.5 ${!reducedMotion ? 'bg-fd-accent text-fd-accent-foreground' : 'text-fd-muted-foreground'}`}
        />
      </button>
      <div className="flex-1" />
      <SidebarCollapseTrigger className="inline-flex items-center justify-center rounded-md p-1.5 text-fd-muted-foreground hover:bg-fd-accent hover:text-fd-accent-foreground transition-colors max-md:hidden">
        <SidebarIcon className="size-4" />
      </SidebarCollapseTrigger>
    </div>
  );
}
