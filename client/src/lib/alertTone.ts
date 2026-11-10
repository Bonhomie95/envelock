/* A short chime when an alert reaches an open Envelock tab.
 *
 * A web notification cannot bring a sound of its own: browsers ignore the spec's
 * `sound` option, and whether the system plays its alert sound is the system's
 * setting. So the page plays one too, through Web Audio (no file to fetch). The
 * service worker picks one open tab to ring (sw.js), so three tabs chime once.
 * Browsers allow it once the user has used the page; the first click or key
 * press unlocks it for Safari, which wants that inside the gesture itself.
 */

const OFF_KEY = "envelock:alert-tone-off";

let ctx: AudioContext | null = null;

export function alertToneOn(): boolean {
  try {
    return localStorage.getItem(OFF_KEY) !== "1";
  } catch {
    return true;
  }
}

export function setAlertTone(on: boolean): void {
  try {
    if (on) localStorage.removeItem(OFF_KEY);
    else localStorage.setItem(OFF_KEY, "1");
  } catch {
    /* storage blocked: the chime stays on */
  }
}

function context(): AudioContext | null {
  const Ctor =
    window.AudioContext ??
    (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  ctx ??= new Ctor();
  return ctx;
}

/** Unlock audio on the first click or key press. Call once per page. */
export function primeAlertTone(): void {
  const unlock = () => {
    try {
      void context()?.resume();
    } catch {
      /* no audio on this device */
    }
  };
  window.addEventListener("pointerdown", unlock, { once: true, capture: true });
  window.addEventListener("keydown", unlock, { once: true, capture: true });
}

/** Two rising notes, 0.6 s. False when muted or when the browser refuses audio. */
export async function playAlertTone(): Promise<boolean> {
  if (!alertToneOn()) return false;
  try {
    const ac = context();
    if (!ac) return false;
    // Without a gesture yet, resume() can wait forever: give up instead of
    // chiming late, at the user's first click.
    if (ac.state !== "running")
      await Promise.race([ac.resume(), new Promise((done) => setTimeout(done, 300))]);
    if (ac.state !== "running") return false;
    const t = ac.currentTime;
    for (const [freq, at] of [
      [880, 0],
      [1320, 0.18],
    ] as const) {
      const osc = ac.createOscillator();
      const gain = ac.createGain();
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, t + at);
      gain.gain.exponentialRampToValueAtTime(0.3, t + at + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + at + 0.4);
      osc.connect(gain).connect(ac.destination);
      osc.start(t + at);
      osc.stop(t + at + 0.42);
    }
    return true;
  } catch {
    return false;
  }
}
