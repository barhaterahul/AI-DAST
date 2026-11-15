// UI string lookup for the dashboard (English only).
//
// Components call useI18n().t(key) so labels live in one dictionary
// (./translations) instead of being scattered through the JSX.

import { translations } from "./translations";

/** Look up a UI string, falling back to the key itself when missing. */
export function translate(key: string): string {
  return translations[key] ?? key;
}

export interface I18n {
  t: (key: string) => string;
}

const i18n: I18n = { t: translate };

/** React hook exposing the `t()` string lookup. */
export function useI18n(): I18n {
  return i18n;
}
