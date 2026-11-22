/**
 * Undo the cheap disguises that defeat plain pattern matching.
 *
 * An attacker does not need a new attack to get past a regex, only a new
 * spelling: an invisible character mid-word, a Cyrillic "о" for a Latin "o",
 * full-width letters, "1gn0re", s p a c e d letters, or the whole thing in
 * base64. Each view below removes one class of disguise, and the payload
 * signal scans all of them.
 *
 * Everything is bounded: the input is already length-capped by the caller,
 * at most MAX_DECODED encoded segments are decoded, and decoding is one level
 * deep, so a hostile payload cannot make this do unbounded work.
 */

export interface View {
  text: string;
  /** how the text was disguised, for the explanation; null when it was not */
  disguise: string | null;
  /** exact characters preserved (original or decoded), not case- or letter-folded */
  raw: boolean;
}

const MAX_DECODED = 8;
const MIN_ENCODED = 16;

/** Zero-width, joiner, bidi-control, soft-hyphen and BOM characters. */
const INVISIBLE = /[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

/** Look-alike letters from Cyrillic and Greek that NFKC leaves alone. */
const CONFUSABLES: Record<string, string> = {
  а: "a", в: "b", е: "e", ё: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c",
  т: "t", у: "y", х: "x", і: "i", ї: "i", ј: "j", ѕ: "s", ԁ: "d", ɡ: "g", һ: "h",
  α: "a", β: "b", ε: "e", η: "n", ι: "i", κ: "k", ν: "v", ο: "o", ρ: "p", τ: "t",
  υ: "u", χ: "x", ω: "w",
};

const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s", "!": "i", "|": "l",
};

const mapChars = (text: string, table: Record<string, string>): string =>
  [...text].map((c) => table[c] ?? c).join("");

/** NFKC folds full-width and stylised letters; then strip and fold look-alikes. */
function canonical(text: string): string {
  return mapChars(text.normalize("NFKC").replace(INVISIBLE, "").toLowerCase(), CONFUSABLES);
}

/** Punctuation wedged between letters ("ignore.previous", "i-g-n-o-r-e")
 *  becomes a space; ordinary sentence punctuation is left alone. */
const spaced = (text: string): string =>
  text
    .replace(/(?<=[a-z0-9])[._*~|/\\+-]+(?=[a-z0-9])/g, " ")
    .replace(/\s+/g, " ")
    .trim();

/** Runs of single letters ("i g n o r e") are rejoined into words. Only runs:
 *  squashing the whole text would join words across sentences. */
const joinSingles = (text: string): string =>
  text.replace(/(?:\b[a-z]\b ?){3,}/g, (run) => `${run.replace(/ /g, "")} `).trim();

function printableRatio(text: string): number {
  if (text.length === 0) return 0;
  let printable = 0;
  for (const c of text) {
    const code = c.charCodeAt(0);
    if ((code >= 32 && code < 127) || c === "\n" || c === "\t") printable++;
  }
  return printable / text.length;
}

function decodeBase64(segment: string): string | null {
  try {
    const normal = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normal + "=".repeat((4 - (normal.length % 4)) % 4);
    const decoded = atob(padded);
    return printableRatio(decoded) > 0.9 ? decoded : null;
  } catch {
    return null;
  }
}

function decodePercent(text: string): string | null {
  if (!/%[0-9a-f]{2}/i.test(text)) return null;
  try {
    const decoded = decodeURIComponent(text);
    return decoded !== text ? decoded : null;
  } catch {
    return null;
  }
}

/**
 * Every view worth scanning, original first. `raw` views keep exact characters,
 * which secret detection depends on; the folded views are for wording.
 */
export function views(text: string): View[] {
  const raw: View[] = [{ text, disguise: null, raw: true }];

  const percent = decodePercent(text);
  if (percent) raw.push({ text: percent, disguise: "URL encoding", raw: true });
  const segments = text.match(new RegExp(`[A-Za-z0-9+/_-]{${MIN_ENCODED},}={0,2}`, "g")) ?? [];
  for (const segment of segments.slice(0, MAX_DECODED)) {
    const decoded = decodeBase64(segment);
    if (decoded) raw.push({ text: decoded, disguise: "base64 encoding", raw: true });
  }

  const folded: View[] = [];
  for (const view of raw) {
    const base = canonical(view.text);
    const tags = view.disguise ? [view.disguise] : [];
    if (base !== view.text.toLowerCase()) tags.push("look-alike or invisible characters");
    const words = base.replace(/\s+/g, " ").trim();
    const separated = spaced(base);
    if (separated !== words) tags.push("punctuation between words");
    const joined = joinSingles(separated);
    if (joined !== separated) tags.push("spaced-out letters");
    folded.push({ text: joined, disguise: tags.join(" and ") || null, raw: false });

    const leet = joinSingles(spaced(mapChars(base, LEET)));
    if (leet !== joined) {
      folded.push({
        text: leet,
        disguise: [...tags, "numbers in place of letters"].join(" and "),
        raw: false,
      });
    }
  }
  return [...raw, ...folded];
}
