// The app's own confirmation dialog, in place of the browser's `confirm()`: themed, with room
// for a warning and a list, and the safe choice focused. `await ask({...})` is true when confirmed.

export type Ask = {
  title: string;
  /** The main text; `mono` shows it as code (a link, a path). */
  body?: string;
  mono?: boolean;
  /** Points shown as a list, e.g. what is wrong with an attachment. */
  list?: string[];
  /** Shown in a red box above the buttons. */
  warning?: string;
  /** Smaller text under the body. */
  detail?: string;
  /** The confirm button's label (default "Continue"). */
  confirm?: string;
  /** The confirm button's label for "no" (default "Cancel"). */
  cancel?: string;
  /** Destructive or risky: the confirm button is red. */
  danger?: boolean;
};

export const dialog = $state({ current: null as (Ask & { resolve: (ok: boolean) => void }) | null });

export function ask(a: Ask): Promise<boolean> {
  // A second question while one is open answers the first with "no".
  dialog.current?.resolve(false);
  return new Promise((resolve) => {
    dialog.current = {
      ...a,
      resolve: (ok) => {
        dialog.current = null;
        resolve(ok);
      },
    };
  });
}
