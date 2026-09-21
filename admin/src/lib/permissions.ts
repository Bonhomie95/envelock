import { useEffect, useState } from "react";
import { api, type Me } from "./api";

/** The signed-in operator, cached for the session.
 *
 * `whoami` is already fetched once by the route guard; caching it here means a
 * page can ask "may I show this button?" without another round-trip, and every
 * page gets the same answer. The server still enforces every check — hiding a
 * control the operator cannot use is a courtesy, not the control.
 */
let cached: Me | null = null;
let inFlight: Promise<Me> | null = null;
const listeners = new Set<(me: Me | null) => void>();

export function setMe(me: Me | null): void {
  cached = me;
  for (const listener of listeners) listener(me);
}

export function getMe(): Me | null {
  return cached;
}

async function load(): Promise<Me> {
  if (cached) return cached;
  inFlight ??= api.whoami().then((me) => {
    setMe(me);
    inFlight = null;
    return me;
  });
  return inFlight;
}

/** Subscribe to the operator, fetching once if the guard hasn't already. */
export function useMe(): Me | null {
  const [me, setLocal] = useState<Me | null>(cached);
  useEffect(() => {
    listeners.add(setLocal);
    if (!cached) void load().catch(() => {});
    return () => {
      listeners.delete(setLocal);
    };
  }, []);
  return me;
}

/** Whether the operator holds a permission. Unknown (still loading) reads as
 *  false, so a control never flashes into existence before we know. */
export function useCan(permission: string): boolean {
  const me = useMe();
  return Boolean(me && (me.break_glass || me.permissions.includes(permission)));
}
