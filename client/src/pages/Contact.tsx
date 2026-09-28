/**
 * The public contact form.
 *
 * One form, a topic dropdown, and an acknowledgement — rather than a mailto:
 * link, which loses anyone without a desktop mail client configured, and
 * rather than a bare address, which gets scraped.
 *
 * The topics come from the server so the list cannot drift from the one the
 * API will accept, and the CAPTCHA site key comes with them: when the
 * deployment has not enabled Turnstile the widget renders nothing and the
 * server accepts the submission unchallenged.
 */
import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight, Check, Loader2 } from "lucide-react";

import { ApiError, api } from "../lib/api";
import { Button } from "../components/primitives";
import { Turnstile } from "../components/Turnstile";

export default function Contact() {
  const [topics, setTopics] = useState<{ id: string; label: string }[]>([]);
  const [siteKey, setSiteKey] = useState<string | null>(null);
  const [topic, setTopic] = useState("account");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .contactOptions()
      .then((r) => {
        if (!live) return;
        setTopics(r.topics);
        setSiteKey(r.captcha_site_key);
        if (r.topics[0]) setTopic(r.topics[0].id);
      })
      // The form still works without the list — the server validates the topic
      // either way, and a blank page because one GET failed helps nobody.
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.submitContact({
        topic,
        email: email.trim(),
        ...(name.trim() ? { name: name.trim() } : {}),
        subject: subject.trim(),
        message: message.trim(),
        ...(token ? { captcha_token: token } : {}),
      });
      setSent(true);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "We couldn't send that. Please try again in a moment.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (sent) {
    return (
      <main className="shell py-20 md:py-28">
        <div className="mx-auto max-w-lg text-center">
          <Check size={30} className="mx-auto text-emerald-500" aria-hidden />
          <h1 className="headline mt-5">Message sent</h1>
          <p className="lede mt-4 text-base">
            We&rsquo;ve emailed you a copy for your records, and we&rsquo;ll come
            back to you at <span className="font-semibold">{email}</span>.
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="shell py-16 md:py-24">
      <div className="mx-auto max-w-xl">
        <div className="flex items-center gap-3">
          <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
          <span className="sect-label">Contact</span>
        </div>
        <h1 className="headline mt-5">Talk to us</h1>
        <p className="lede mt-4 text-base">
          Billing, a bug, a suggestion or a complaint — pick what it&rsquo;s
          about and it reaches the right person.
        </p>

        <form onSubmit={(e) => void submit(e)} className="mt-10 flex flex-col gap-5">
          <div>
            <label htmlFor="topic" className="block text-sm font-semibold">
              What is it about?
            </label>
            <select
              id="topic"
              value={topic}
              onChange={(e) => setTopic(e.target.value)}
              className="field mt-2 w-full"
            >
              {topics.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>

          <div className="grid gap-5 sm:grid-cols-2">
            <div>
              <label htmlFor="c-email" className="block text-sm font-semibold">
                Your email
              </label>
              <input
                id="c-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                className="field mt-2 w-full"
              />
            </div>
            <div>
              <label htmlFor="c-name" className="block text-sm font-semibold">
                Your name <span className="fg-3 font-normal">(optional)</span>
              </label>
              <input
                id="c-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                className="field mt-2 w-full"
              />
            </div>
          </div>

          <div>
            <label htmlFor="c-subject" className="block text-sm font-semibold">
              Subject
            </label>
            <input
              id="c-subject"
              required
              minLength={3}
              maxLength={200}
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              className="field mt-2 w-full"
            />
          </div>

          <div>
            <label htmlFor="c-message" className="block text-sm font-semibold">
              Message
            </label>
            <textarea
              id="c-message"
              required
              minLength={10}
              maxLength={5000}
              rows={7}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="field mt-2 w-full resize-y"
            />
            <p className="fg-3 mt-1.5 text-xs">{message.length}/5000</p>
          </div>

          <Turnstile siteKey={siteKey} onToken={setToken} />

          {error && (
            <p className="text-sm text-red-500" aria-live="polite">
              {error}
            </p>
          )}

          <Button
            type="submit"
            variant="accent"
            size="lg"
            className="self-start"
            disabled={busy}
          >
            {busy ? (
              <>
                <Loader2 size={14} className="animate-spin" aria-hidden />
                SENDING
              </>
            ) : (
              <>
                SEND MESSAGE
                <ArrowRight size={14} aria-hidden />
              </>
            )}
          </Button>

          <p className="fg-3 text-xs leading-relaxed">
            If this is about a suspected fraud in progress, don&rsquo;t wait for
            a reply — ring the number you hold on file for the supplier, not one
            from the email.
          </p>
        </form>
      </div>
    </main>
  );
}
