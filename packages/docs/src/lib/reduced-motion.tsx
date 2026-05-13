'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

type ReducedMotionContextValue = {
  reducedMotion: boolean;
  override: boolean | null;
  setOverride: (value: boolean | null) => void;
};

const ReducedMotionContext = createContext<ReducedMotionContextValue>({
  reducedMotion: false,
  override: null,
  setOverride: () => {},
});

const STORAGE_KEY = 'happyview-reduced-motion';

export function ReducedMotionProvider({ children }: { children: ReactNode }) {
  const [systemPreference, setSystemPreference] = useState(false);
  const [override, setOverrideState] = useState<boolean | null>(null);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setSystemPreference(mq.matches);
    const onChange = () => setSystemPreference(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored !== null) setOverrideState(stored === 'true');
  }, []);

  function setOverride(value: boolean | null) {
    setOverrideState(value);
    if (value === null) {
      localStorage.removeItem(STORAGE_KEY);
    } else {
      localStorage.setItem(STORAGE_KEY, String(value));
    }
  }

  const reducedMotion = override ?? systemPreference;

  return (
    <ReducedMotionContext value={{ reducedMotion, override, setOverride }}>
      {children}
    </ReducedMotionContext>
  );
}

export function useReducedMotion() {
  return useContext(ReducedMotionContext);
}
