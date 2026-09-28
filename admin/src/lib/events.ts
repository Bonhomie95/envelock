/**
 * Live operator notifications over Server-Sent Events.
 *
 * Deliberately NOT `EventSource`. It cannot set request headers, so the only
 * way to authenticate one is to put the staff token in the query string —
 * where it lands in nginx access logs, browser history and any proxy in
 * between. `fetch` with a streaming reader carries the same Authorization
 * header as every other call.
 *
 * The cost of doing it this way is that reconnection is ours to handle, since
 * `EventSource`'s automatic retry comes with the thing we are not using.
 */
import { auth } from "./api";

type Handler = (event: string, data: unknown) => void;

const PATH = "/api/v1/admin/events";

//: Backoff between reconnects. Starts quick so a deploy restart is invisible,
//: and caps low enough that a console left open overnight is live again within
//: half a minute of the server coming back.
const RETRY_MIN_MS = 1_000;
const RETRY_MAX_MS = 30_000;

/**
 * Subscribe until the returned function is called.
 *
 * `onEvent` is called with the event name and its parsed payload. The special
 * `stale` event means the server dropped messages for this connection and the
 * caller should do a full refetch rather than trusting an incremental update.
 */
export function subscribeToEvents(onEvent: Handler): () => void {
  let stopped = false;
  let controller: AbortController | null = null;
  let retry = RETRY_MIN_MS;
  let timer: ReturnType<typeof setTimeout> | null = null;

  async function connect(): Promise<void> {
    if (stopped || !auth.token) return;
    controller = new AbortController();
    try {
      const res = await fetch(PATH, {
        headers: {
          Authorization: `Bearer ${auth.token}`,
          Accept: "text/event-stream",
        },
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new Error(`stream failed: ${res.status}`);

      // Connected: reset the backoff so the NEXT drop retries quickly.
      retry = RETRY_MIN_MS;

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done || stopped) break;
        buffer += decoder.decode(value, { stream: true });

        // SSE frames are separated by a blank line. Anything after the last
        // separator is a partial frame and stays in the buffer.
        const frames = buffer.split("\n\n");
        buffer = frames.pop() ?? "";
        for (const frame of frames) {
          let name = "message";
          let payload = "";
          for (const line of frame.split("\n")) {
            // Lines starting ":" are comments — the server's keepalives.
            if (line.startsWith("event:")) name = line.slice(6).trim();
            else if (line.startsWith("data:")) payload += line.slice(5).trim();
          }
          if (!payload && name === "message") continue;
          try {
            onEvent(name, payload ? JSON.parse(payload) : {});
          } catch {
            // A malformed frame must not kill the stream.
          }
        }
      }
    } catch {
      // Network drop, deploy restart, laptop lid closed. Fall through to retry.
    }
    if (stopped) return;
    timer = setTimeout(() => void connect(), retry);
    retry = Math.min(retry * 2, RETRY_MAX_MS);
  }

  void connect();

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    controller?.abort();
  };
}
