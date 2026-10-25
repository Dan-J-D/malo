// Shared timing for Svelte transitions. Svelte animates with generated keyframes, so the
// reduced-motion rule in global.css would freeze them mid-way; durations collapse to 0 instead.
import { cubicOut } from 'svelte/easing';

const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

/** Duration in ms, or 0 when the user prefers reduced motion. */
export const ms = (n: number) => (reduced ? 0 : n);

export const ease = cubicOut;
