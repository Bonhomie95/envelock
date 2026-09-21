/** A tiny toast bus.
 *
 * The app previously reported success by silently refreshing and failure by
 * `window.confirm`/inline text that scrolled out of view — so a destructive
 * action gave no confirmation it had happened, and an action taken at the bottom
 * of a long dashboard gave no feedback at all. This is the minimum that fixes
 * that: a module-level event bus any component can publish to, rendered once at
 * the root. No dependency, no context threading.
 */

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  /** Milliseconds before auto-dismiss. Errors stay longer; 0 means sticky. */
  ttl: number;
}

type Listener = (toasts: Toast[]) => void;

let items: Toast[] = [];
let nextId = 1;
const listeners = new Set<Listener>();

function emit(): void {
  const snapshot = items;
  for (const listener of listeners) listener(snapshot);
}

export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  listener(items);
  return () => listeners.delete(listener);
}

export function dismiss(id: number): void {
  items = items.filter((t) => t.id !== id);
  emit();
}

function push(kind: ToastKind, message: string, ttl: number): number {
  const id = nextId++;
  // Cap the stack: a burst of failures should not bury the page.
  items = [...items.slice(-3), { id, kind, message, ttl }];
  emit();
  if (ttl > 0) setTimeout(() => dismiss(id), ttl);
  return id;
}

export const toast = {
  success: (message: string) => push("success", message, 4000),
  /** Errors linger — they usually carry an instruction the user has to read. */
  error: (message: string) => push("error", message, 9000),
  info: (message: string) => push("info", message, 5000),
};
