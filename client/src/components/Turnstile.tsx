/**
 * Cloudflare Turnstile widget.
 *
 * Renders nothing at all when the deployment has no site key, so development
 * and any deployment that has not enabled it keep working unchanged — the
 * server treats a missing secret as "check disabled" and accepts the request.
 *
 * The script is loaded once, lazily, on first use rather than from index.html:
 * a third-party script on every page load is a third party who can watch every
 * page load, and it is only needed on three forms.
 */
import { useEffect, useRef, useState } from "react";

const SCRIPT_SRC =
  "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      remove: (id: string) => void;
    };
  }
}

let scriptPromise: Promise<void> | null = null;

function loadScript(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  scriptPromise ??= new Promise<void>((resolve, reject) => {
    const el = document.createElement("script");
    el.src = SCRIPT_SRC;
    el.async = true;
    el.defer = true;
    el.onload = () => resolve();
    el.onerror = () => {
      // Let the next attempt retry rather than caching the failure forever.
      scriptPromise = null;
      reject(new Error("turnstile script failed to load"));
    };
    document.head.appendChild(el);
  });
  return scriptPromise;
}

export function Turnstile({
  siteKey,
  onToken,
}: {
  siteKey: string | null;
  onToken: (token: string | null) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!siteKey || !host.current) return;
    let widgetId: string | null = null;
    let live = true;
    const el = host.current;

    void loadScript()
      .then(() => {
        if (!live || !window.turnstile) return;
        widgetId = window.turnstile.render(el, {
          sitekey: siteKey,
          callback: (token: string) => onToken(token),
          // A solved challenge is single-use and expires. Clearing the token
          // on either event stops the form submitting one the server will
          // reject, which would read to the person as "it just failed".
          "expired-callback": () => onToken(null),
          "error-callback": () => onToken(null),
          theme: "auto",
        });
      })
      .catch(() => {
        if (!live) return;
        // Cloudflare unreachable. The server fails open in the same situation,
        // so say so quietly rather than blocking the form.
        setFailed(true);
        onToken(null);
      });

    return () => {
      live = false;
      if (widgetId && window.turnstile) window.turnstile.remove(widgetId);
    };
  }, [siteKey, onToken]);

  if (!siteKey) return null;
  return (
    <div>
      <div ref={host} />
      {failed && (
        <p className="fg-3 mt-2 text-xs">
          The anti-spam check couldn&rsquo;t load. You can still continue.
        </p>
      )}
    </div>
  );
}
