import type { MailboxRecord } from "./api";

/** Mailboxes that are not protecting anything: lost their connection, or were
 *  added and never connected. */
export function mailboxIssues(mailboxes: MailboxRecord[], mailSources: Set<string>) {
  const broken = mailboxes.filter((m) => m.needs_reconnect);
  const unconnected = mailboxes.filter(
    (m) => !m.needs_reconnect && !m.sources.some((s) => mailSources.has(s)),
  );
  return { broken, unconnected };
}
