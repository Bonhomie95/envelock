import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "./primitives";

/** Catches a render-time throw so one bad value cannot blank the application.
 *
 * There was no boundary anywhere in the app. React's default on an uncaught
 * render error is to unmount the entire tree, so a single unexpected shape from
 * the API — an alert missing a field, a null where an array was assumed —
 * replaced the whole console with a blank white page. No message, no way back
 * except a manual reload, and nothing recorded.
 *
 * That is bad in any product. In this one the blank page is the alert queue,
 * and the customer's conclusion is that Envelock is down at the moment they
 * were being defrauded.
 */
interface Props {
  children: ReactNode;
  /** Shown instead of the default panel, e.g. to scope a boundary to one card. */
  fallback?: (reset: () => void) => ReactNode;
}

interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Keep this: without a console record, a white page is unreportable and
    // unreproducible. When an error tracker is wired, this is its call site.
    console.error("Unhandled render error", error, info.componentStack);
  }

  private reset = (): void => this.setState({ error: null });

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(this.reset);

    return (
      <div
        role="alert"
        className="mx-auto my-16 max-w-lg px-4 text-center"
      >
        <AlertTriangle
          size={28}
          className="mx-auto mb-4"
          style={{ color: "var(--danger, #dc2626)" }}
          aria-hidden
        />
        <h1 className="mb-2 text-lg font-semibold">Something broke on this page</h1>
        <p className="fg-3 mb-6 text-sm">
          The rest of Envelock is still running and your mailboxes are still
          being monitored — this is a fault in the page, not in your protection.
          Try again, and if it keeps happening, email{" "}
          <a href="mailto:security@envelock.org" className="underline">
            security@envelock.org
          </a>{" "}
          with what you were doing.
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          <Button size="sm" variant="line" onClick={this.reset}>
            TRY AGAIN
          </Button>
          <Button
            size="sm"
            variant="quiet"
            onClick={() => window.location.assign("/dashboard")}
          >
            BACK TO DASHBOARD
          </Button>
        </div>
        {import.meta.env.DEV && (
          <pre className="fg-3 mono-xs mt-6 overflow-x-auto whitespace-pre-wrap text-left">
            {error.stack ?? String(error)}
          </pre>
        )}
      </div>
    );
  }
}
