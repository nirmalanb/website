/**
 * Tailwind class strings for the JWT tool.
 *
 * Markup in `src/components/tools/*.astro` and HTML generated at runtime by
 * `jwt-decoder.ts` both pull from here, so the two can never drift. Tailwind v4
 * scans this file the same way it scans `search.ts`, so every literal below is
 * emitted — which is why no class is ever built with string concatenation
 * (e.g. `'pl-' + depth` would be invisible to the compiler).
 */

const FIELD =
  'w-full resize-y rounded-[10px] border border-rule bg-paper px-3 py-2 font-mono text-[13px] leading-relaxed text-body outline-none transition-colors focus:border-accent focus:ring-[3px] focus:ring-accent/15';

const BTN =
  'cursor-pointer rounded-[10px] border-0 bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent/90';
const BTN_GHOST =
  'cursor-pointer rounded-[10px] border border-rule bg-transparent px-4 py-2.5 text-sm font-semibold text-ink transition-colors hover:bg-rule/40';

export const CLS = {
  /* page chrome */
  tabNav: 'mt-7 mb-5 inline-flex gap-0.5 rounded-full border border-rule bg-paper p-0.5',
  tab: 'cursor-pointer rounded-full border-0 bg-transparent px-5 py-2 text-sm font-semibold text-mute aria-selected:bg-ink aria-selected:text-white',
  card: 'mb-[18px] rounded-2xl border border-rule/80 bg-white p-[18px] shadow-sm',
  cardHead:
    'mb-3 text-[14px] font-bold uppercase tracking-[0.08em] text-mute',
  cardHeadOpt: 'font-normal normal-case tracking-normal text-mute/80',

  /* layout helpers */
  toolbar: 'mb-2.5 flex flex-wrap items-center gap-2',
  spacer: 'flex-1',
  stack: 'flex flex-col gap-3.5',
  genrow: 'mt-2 flex flex-wrap items-center gap-2',
  fieldLabel:
    'mb-1.5 block text-xs font-semibold tracking-[0.03em] text-mute',
  fieldLabelInline: 'block text-xs font-semibold tracking-[0.03em] text-mute',
  hint: 'mb-3 -mt-1 text-[13px] text-mute',
  hintInline: 'text-[13px] text-mute',
  status: 'mt-3 flex flex-wrap items-center gap-2.5',
  tokWrap: 'relative overflow-hidden rounded-[10px] border border-rule bg-paper',

  /* buttons + field */
  field: FIELD,
  select: `${FIELD} font-sans text-sm`,
  btn: BTN,
  btnGhost: BTN_GHOST,
  btnSm: 'px-[11px] py-1.5 text-xs',

  /* token input overlay: TOKLAYER is applied to BOTH the <pre> and the <textarea>
     so their metrics stay identical, otherwise the coloured overlay drifts. */
  tokLayer:
    'm-0 px-[14px] py-[12px] font-mono text-[13.5px] leading-[1.7] whitespace-pre-wrap break-all [overflow-wrap:anywhere]',
  tokBack: 'absolute inset-0 overflow-auto text-transparent pointer-events-none',
  tokInput:
    'relative block h-[88px] min-h-[88px] w-full resize-y border-0 bg-transparent text-transparent caret-ink placeholder:text-mute selection:bg-accent/25 focus:outline-none focus:ring-0',

  /* segment colours (jwt.io's red / violet / blue, as a functional affordance) */
  seg: {
    h: 'text-rose-600',
    p: 'text-violet-600',
    s: 'text-sky-700',
    dot: 'font-bold text-mute',
  } as Record<string, string>,

  /* panes */
  pane: 'flex flex-col overflow-hidden rounded-[10px] border border-rule bg-paper',
  paneHead: 'flex items-center gap-2 border-b border-rule/70 bg-rule/30 px-2.5 py-2',
  paneTitle: 'text-[13px] font-bold tracking-[0.02em]',
  paneHeadPlain: 'mb-2.5 flex items-center gap-2',
  segTab: 'ml-auto flex gap-0.5 rounded-lg border border-rule/70 bg-white p-0.5',
  segTabBtn:
    'cursor-pointer rounded-md border-0 bg-transparent px-2.5 py-1 text-xs font-semibold text-mute [&.active]:bg-ink [&.active]:text-white',

  /* JSON tree */
  tree: 'max-h-[340px] overflow-auto px-[14px] py-2.5 font-mono text-[13px] leading-[1.7]',
  jtLine: 'whitespace-pre-wrap break-words',
  jtSummary: 'cursor-pointer',
  jtKey: 'text-violet-600',
  jtIdx: 'text-mute',
  jtStr: 'text-accent',
  jtNum: 'text-sky-700',
  jtBool: 'text-amber-700',
  jtNull: 'text-mute',
  jtPunct: 'text-mute',
  jtCount: 'mx-[3px] text-[11.5px] text-mute',

  /* claims table */
  claimsTable: 'w-full border-collapse text-[13px]',
  claimsWrap: 'max-h-[340px] overflow-auto',
  claimsTh:
    'border-b border-rule/70 px-[14px] py-2 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-mute',
  claimsTd: 'border-b border-rule/70 px-[14px] py-2 align-top break-words',
  claimsK: 'whitespace-nowrap font-mono text-violet-600',
  claimsV: 'font-mono',
  claimsD: 'text-mute',

  /* badges + messages */
  badgeBase:
    'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[12.5px] font-bold',
  badge: {
    ok: 'border-accent/35 bg-accent/10 text-accent',
    bad: 'border-rose-600/35 bg-rose-600/10 text-rose-700',
    warn: 'border-amber-600/35 bg-amber-600/10 text-amber-700',
    neutral: 'border-rule bg-paper text-mute',
  } as Record<string, string>,
  dotm: 'h-[7px] w-[7px] rounded-full bg-current',
  empty: 'px-[14px] py-5 text-[13px] text-mute',
  err: 'mt-2 block whitespace-pre-wrap text-[13px] text-rose-700',
  okmsg: 'mt-2 text-[13px] text-accent',
  kv: 'text-[13px] text-mute',
  okText: 'text-accent',
  badText: 'text-rose-700',
  warnText: 'text-amber-700',

  /* encoder output */
  outToken:
    'max-h-[240px] overflow-auto whitespace-pre-wrap break-all rounded-[10px] border border-rule bg-paper px-[14px] py-3 font-mono text-[13px] leading-[1.7]',
};

/** Indentation ladder for the JSON tree; index by depth, clamped. */
export const TREE_PL = [
  'pl-0',
  'pl-[14px]',
  'pl-[28px]',
  'pl-[42px]',
  'pl-[56px]',
  'pl-[70px]',
  'pl-[84px]',
  'pl-[98px]',
];
