# Nirmala NB — Cyber Security

One-page professional site plus an MDX guide section for a cyber security engineer, built with **Astro 7** and **Tailwind CSS v4**. No client-side framework; the core page ships no JavaScript (~14 KB HTML, one stylesheet). Guide pages lazily render Mermaid diagrams client-side; everything else, including syntax-highlighted code blocks, is build-time HTML/CSS. The Mermaid integration injects its client module into every page, so a build hook in `astro.config.mjs` strips it back off every page without a diagram — and enforces a one-script budget on pages marked `data-search-mount`, failing the build if anything unexpected turns up.

## Stack

| Piece | Version |
| --- | --- |
| Astro | 7.3.8 |
| Tailwind CSS | 4.3.3 (via `@tailwindcss/vite`) |
| @astrojs/mdx | 8.x (guides) |
| @astrojs/markdown-satteri | 0.4.x (markdown processor) |
| astro-mermaid-satteri | 0.3.x (Mermaid in guides) |
| Package manager | pnpm |
| Shipped JS | none on the core page; guide pages load the Mermaid runtime |

Tailwind v4 runs as a Vite plugin, so there is **no `tailwind.config.js` and no `postcss.config.js`**. Design tokens live in the `@theme` block of `src/styles/global.css`.

## Design

Typography-led and personal rather than a marketing landing page: one 672 px column, hairline rules between sections, a rounded display face over a warm sans, and a single dark band to close the page. No decorative glows, gradient meshes, pull-quotes, badges or scroll animation.

Structure and palette are inspired by [sijosam.com](https://www.sijosam.com/) — name, role, intro and contact row reading top to bottom as one continuous flow; deep-teal ink on cool off-white with a dark rounded contact block.

Emphasis is carried by size, weight and colour only. Nothing on the page competes with the name.

### Voice

First person, concrete, dry confidence; one flash of wit per surface, at most three on the page. Personality lives in the frame (intro, footer, 404 copy, a view-source comment in `index.astro`, the pulsing "present" marker, the NB favicon), never in the resume bullets, which stay factual claims for recruiters.

### Guides

MDX content collection (`src/content/guides`), rendered with the Sätteri processor and `@astrojs/mdx`. The listing at `/guides/` numbers entries like a pentest report's findings index and shows date and read time; posts keep the one-column type treatment with a `.prose` scope in `global.css`.

Guide search is a filter on the listing, built on a static index at `/search-index.json` (a `src/pages/search-index.json.ts` endpoint that reads the collection, so frontmatter and published state stay in sync with the page). The script in `src/scripts/search.ts` fetches it, matches space-separated terms across title, excerpt, tags and body, and hides non-matching entries, with an `aria-live` count.

**It is currently hidden.** `SEARCH_ENABLED` at the top of `src/pages/guides/index.astro` is `false`, which skips the mount point and the script at build time — Astro does not bundle the script, so the page ships zero JavaScript. Flip it to `true` to bring the box back; nothing else needs touching.

Mermaid diagrams are themed to the site palette (`astro.config.mjs`, `themeVariables`), with `autoTheme: false` so dark-mode browsers never get dark diagrams on a light page. Code fences are highlighted by shiki at build time; `.prose pre` overrides shiki's inline background with the brand `deep` token.

### Interaction & accessibility

- Sticky nav from `sm` up (static on phones so it doesn't eat viewport); anchors land below it via `scroll-mt-16`
- Smooth scrolling, guarded by `prefers-reduced-motion`
- Visible `:focus-visible` outlines in resume green
- Skip-to-content link
- Print stylesheet — hides chrome and the dark band, prints as a plain document
- `<details>` expanders: native, no JavaScript on the core page
- Guide search is wired but hidden (`SEARCH_ENABLED`); when on, it filters the listing in place with an `aria-live` count and Esc to clear
- 404 page included

### Colour

| Token | Hex | Source | Use |
| --- | --- | --- | --- |
| `ink` | `#004747` | inspired | headings, primary text |
| `body` | `#1c2524` | inspired | body copy |
| `mute` | `#52706d` | derived | dates, secondary text |
| `paper` | `#f6f9f9` | inspired | page background |
| `rule` | `#dbe7e7` | derived | hairline borders |
| `accent` | `#007a54` | **resume** (`007a54`) | links |
| `accent-bright` | `#009669` | **resume** (`009669`) | "present" marker |
| `mint` | `#92efc5` | inspired | links on the dark band |
| `deep` / `fog` | `#0f1716` / `#cfe3df` | inspired | contact band |

Resume values come from `build_master_resume.py` (`GREEN = 009669`, `DARK = 111111`, `GREY = 666666`).

### Type

- **Baloo 2** (600/700/800) — display: name, headings
- **Nunito** (400–700) — body

Both are loaded from Google Fonts. To change the pairing, edit the `<link>` in `src/layouts/Layout.astro` and `--font-display` / `--font-sans` in `global.css`.

## Commands

```bash
pnpm install
pnpm dev        # http://localhost:4321
pnpm build      # static output in dist/
pnpm preview    # serve dist/
```

## Structure

```
src/
├─ content.config.ts         # guides collection (glob loader, zod schema)
├─ content/guides/            # MDX guides — frontmatter + Mermaid diagrams
├─ data/resume.ts            # all content + contact links — single source of truth
├─ layouts/Layout.astro      # html shell, fonts, meta, OG tags, skip link
├─ pages/index.astro         # page composition
├─ pages/guides/             # guide listing + [slug].astro post pages
├─ pages/search-index.json.ts # build-time JSON index for guide search
├─ pages/404.astro           # not-found page
├─ scripts/search.ts         # guide search filter (the one allowed script)
├─ styles/global.css         # @theme tokens, .link, .prose, mermaid + code styles, print block
└─ components/
   ├─ Header.astro           # monogram, name, sticky nav
   ├─ Intro.astro            # name, role, summary, contact
   ├─ Section.astro          # section heading + rule + scroll offset
   ├─ Experience.astro       # roles, dates right-aligned
   ├─ Skills.astro           # category + joined skill list
   ├─ Education.astro
   └─ Footer.astro           # dark contact band
```

Experience entries show three bullets; the rest sit behind a native `<details>` element, so expanding costs no JavaScript.

## Content

Resume copy is sourced from `Master Resume/Nirmala_NB_Master_Resume.docx`. To update the site, edit `src/data/resume.ts` — no component changes needed. Guides are MDX files in `src/content/guides/`; drop a new file in with frontmatter matching the schema in `src/content.config.ts` and it appears on `/guides/` automatically.
