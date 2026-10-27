// Sender authentication as the receiving mail server recorded it (Authentication-Results,
// RFC 8601). Only that server's verdict counts: a sender can write any Authentication-Results
// header into its own message, but the receiving server adds its own on top, so the first one
// in the message is the one to read.

export type Method = 'spf' | 'dkim' | 'dmarc';
export type Tone = 'ok' | 'warn' | 'bad' | 'muted';

export interface Check {
  method: Method;
  /** pass, fail, softfail, neutral, none, temperror, permerror, policy… */
  result: string;
  /** The domain the check was about (envelope sender, signing domain, From domain). */
  domain: string;
  /** Other properties, e.g. `smtp.mailfrom`, `header.d`, `header.s`. */
  props: [string, string][];
  /** The server's own comment, e.g. "google.com: domain of … designates … as permitted sender". */
  comment: string;
}

export interface AuthReport {
  /** The server that checked the message, e.g. mx.google.com. */
  by: string;
  checks: Check[];
  /** The header the report was read from. */
  raw: string;
  /** More Authentication-Results headers further down (added by servers on the way). */
  others: number;
}

const METHODS: Method[] = ['spf', 'dkim', 'dmarc'];

/** Splits on `;` outside quotes and comments. */
function parts(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let depth = 0;
  let quoted = false;
  for (const c of s) {
    if (c === '"' && depth === 0) quoted = !quoted;
    else if (c === '(' && !quoted) depth++;
    else if (c === ')' && !quoted && depth > 0) depth--;
    if (c === ';' && depth === 0 && !quoted) {
      out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function parseCheck(part: string): Check | null {
  const comments: string[] = [];
  const bare = part.replace(/\(([^()]*)\)/g, (_, c: string) => (comments.push(c.trim()), ' ')).trim();
  const m = /^([a-z0-9-]+)\s*=\s*([a-z0-9-]+)\b(.*)$/i.exec(bare);
  if (!m) return null;
  const method = m[1].toLowerCase() as Method;
  if (!METHODS.includes(method)) return null;
  const props: [string, string][] = [];
  for (const p of m[3].matchAll(/([a-z0-9_.-]+)\s*=\s*("[^"]*"|\S+)/gi)) {
    props.push([p[1].toLowerCase(), p[2].replace(/^"|"$/g, '')]);
  }
  const prop = (k: string) => props.find(([n]) => n === k)?.[1];
  const domain = (
    method === 'spf' ? prop('smtp.mailfrom')?.split('@').pop() ?? prop('smtp.helo')
    : method === 'dkim' ? prop('header.d') ?? prop('header.i')?.split('@').pop()
    : prop('header.from')
  ) ?? '';
  return { method, result: m[2].toLowerCase(), domain, props, comment: comments.join(' ') };
}

/** The receiving server's report: the first Authentication-Results, or failing that the first
 *  ARC-Authentication-Results (its `i=N;` prefix removed). */
export function authReport(results: string[]): AuthReport | null {
  if (!results.length) return null;
  const plain = results.filter((r) => !/^\s*i\s*=\s*\d+\s*;/i.test(r));
  const raw = plain[0] ?? results[0];
  const body = raw.replace(/^\s*i\s*=\s*\d+\s*;/i, '');
  const [head, ...rest] = parts(body);
  // The first part is the server's id, optionally with a version: "mx.google.com" or "mx 1".
  const by = head.replace(/\([^)]*\)/g, '').trim().split(/\s+/)[0] ?? '';
  const checks = rest.map(parseCheck).filter((c): c is Check => c !== null);
  return { by, checks, raw, others: results.length - 1 };
}

/** SPF from a Received-SPF header, for servers that only write that one. */
export function receivedSpf(headers: [string, string][]): Check | null {
  const h = headers.find(([k]) => k.toLowerCase() === 'received-spf');
  if (!h) return null;
  const m = /^\s*([a-z]+)\b\s*(?:\(([^)]*)\))?(.*)$/i.exec(h[1]);
  if (!m) return null;
  const from = /envelope-from=("?)([^";\s]+)\1/i.exec(m[3])?.[2] ?? '';
  return { method: 'spf', result: m[1].toLowerCase(), domain: from.split('@').pop() ?? '', props: [], comment: m[2]?.trim() ?? '' };
}

export function tone(result: string | undefined): Tone {
  switch (result) {
    case 'pass': return 'ok';
    case 'fail': case 'permerror': return 'bad';
    case 'softfail': case 'temperror': case 'policy': return 'warn';
    default: return 'muted';
  }
}

/** Each method's results, the one that decides first: a pass (one good DKIM signature is enough,
 *  and a message often has several), otherwise the most serious problem. */
export function verdicts(report: AuthReport | null, fallbackSpf: Check | null): Record<Method, Check[]> {
  const out: Record<Method, Check[]> = { spf: [], dkim: [], dmarc: [] };
  for (const c of report?.checks ?? []) out[c.method].push(c);
  if (!out.spf.length && fallbackSpf) out.spf.push(fallbackSpf);
  const order = ['pass', 'fail', 'permerror', 'softfail', 'temperror', 'policy', 'neutral', 'none'];
  const rank = (c: Check) => (order.includes(c.result) ? order.indexOf(c.result) : order.length);
  for (const m of METHODS) out[m].sort((a, b) => rank(a) - rank(b));
  return out;
}

/** What a result means, in a few words. */
export function meaning(c: Check | undefined, method: Method): string {
  if (!c) return method === 'dkim' ? 'Not signed, or not checked' : 'Not checked';
  const what = {
    spf: { pass: 'Sent from a server the domain allows', fail: 'Sent from a server the domain does not allow', softfail: 'The domain doesn’t vouch for this server', neutral: 'The domain makes no claim about this server', none: 'The domain publishes no SPF record' },
    dkim: { pass: 'Signed by the domain and unchanged since', fail: 'Signature doesn’t match: changed on the way, or forged', none: 'Not signed', neutral: 'Signature couldn’t be checked' },
    dmarc: { pass: 'The From domain matches a passing SPF or DKIM check', fail: 'The From domain isn’t backed by SPF or DKIM', none: 'The From domain publishes no DMARC policy' },
  }[method] as Record<string, string>;
  return what[c.result] ?? (c.result === 'temperror' ? 'Temporary error while checking' : c.result === 'permerror' ? 'The domain’s record is broken' : c.result);
}
