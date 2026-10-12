# PRODUCT.md

## Product

One-page personal site for Nirmala NB, cyber security engineer (banking, Dubai). Doubles as resume and first impression; recruiters scan it in under a minute.

## Users

- Recruiters and hiring managers in security and banking, scanning fast and looking for signal.
- Security peers and engineers who care about craft and will read the source.

## Register

brand — the design is the product. Typography-led, personal, not a marketing landing page.

## Voice

First person, concrete, dry confidence. The wit budget is one flash per surface, three per page. No exclamation marks, no emoji, no "passionate about security" filler. Personality lives in the frame (intro, footer, 404, micro-details); resume bullets stay factual claims.

## Anti-references

AI slop in all forms: gradient text, glassmorphism, badge grids, chip clouds, decorative glows, editorial-magazine cliché, generic hero sections. Nothing competes with the name.

## Non-negotiables

The core page ships zero JavaScript (~14 KB HTML, one stylesheet) — the build strips the Mermaid client module from every page without a diagram. Guides may lazily load the Mermaid runtime client-side; everything else stays build-time HTML/CSS. Guide search exists but ships disabled. One 672 px column. Print stylesheet keeps working. Design language is committed (Baloo 2 + Nunito, teal ink on cool paper, mint accent) — identity-preservation wins over trend updates.