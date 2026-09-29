import { useEffect, useRef } from "react";

/** Reveal offscreen marketing content once; keep it readable without browser support. */
export function useScrollReveal() {
  const root = useRef<HTMLElement>(null);
  useEffect(() => {
    const element = root.current;
    if (!element || !window.IntersectionObserver) return;
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    const targets = [...element.querySelectorAll<HTMLElement>("[data-reveal]")];
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            (entry.target as HTMLElement).dataset.motion = "revealed";
            observer.unobserve(entry.target);
          }
        }
      },
      { threshold: 0.08 },
    );
    const showAll = () => {
      if (!preference.matches) return;
      observer.disconnect();
      targets.forEach((target) => delete target.dataset.motion);
    };
    if (!preference.matches) {
      targets.forEach((target) => {
        // Above-the-fold content is immediately usable. Only defer content below it.
        if (target.getBoundingClientRect().top >= window.innerHeight) {
          target.dataset.motion = "pending";
          observer.observe(target);
        }
      });
    }
    preference.addEventListener("change", showAll);
    return () => {
      observer.disconnect();
      preference.removeEventListener("change", showAll);
      targets.forEach((target) => delete target.dataset.motion);
    };
  }, []);
  return root;
}
