import { useEffect, useRef, useState } from "react"

export interface TypeaheadActor {
  did: string
  handle: string
  displayName?: string
  avatar?: string
}

export function useHandleTypeahead(query: string, delay = 200) {
  const [actors, setActors] = useState<TypeaheadActor[]>([])
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (query.length < 2) {
      setActors([])
      return
    }

    abortRef.current?.abort()

    const timeout = setTimeout(() => {
      const controller = new AbortController()
      abortRef.current = controller

      fetch(
        `https://typeahead.waow.tech/xrpc/app.bsky.actor.searchActorsTypeahead?q=${encodeURIComponent(query)}&limit=8`,
        {
          signal: controller.signal,
          headers: { "X-Client": "happyview" },
        },
      )
        .then((res) => (res.ok ? res.json() : Promise.reject()))
        .then((data) => setActors(data.actors ?? []))
        .catch((e) => {
          if (!(e instanceof DOMException && e.name === "AbortError")) {
            setActors([])
          }
        })
    }, delay)

    return () => {
      clearTimeout(timeout)
      abortRef.current?.abort()
    }
  }, [query, delay])

  return { actors }
}
