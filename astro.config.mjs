// @ts-check
import { defineConfig } from 'astro/config';
import { satteri } from '@astrojs/markdown-satteri';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import mermaid from 'astro-mermaid-satteri';
import tailwindcss from '@tailwindcss/vite';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// astro-mermaid-satteri injects its client module into every page via injectScript('page'),
// but that module does nothing unless a `pre.mermaid` is in the DOM. Stripping it from
// diagram-less pages keeps the core page's zero-JavaScript guarantee true. Built output
// only — dev still serves the script everywhere.
/** @returns {import('astro').AstroIntegration} */
function stripMermaidScript() {
  const MODULE = /<script type="module" src="\/_astro\/page\.[^"]*\.js"[^>]*><\/script>/g;

  /**
   * @param {string} dir
   * @returns {Promise<string[]>}
   */
  async function htmlFiles(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    const found = await Promise.all(
      entries.map((entry) => {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) return htmlFiles(path);
        return Promise.resolve(entry.name.endsWith('.html') ? [path] : []);
      }),
    );
    return found.flat();
  }

  return {
    name: 'strip-mermaid-script',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        let stripped = 0;
        for (const file of await htmlFiles(fileURLToPath(dir))) {
          const html = await readFile(file, 'utf8');
          if (html.includes('class="mermaid"')) continue; // diagrams render here; runtime stays

          const next = html.replace(MODULE, '');
          // /guides/ opts into one script for guide search via the data-search-mount
          // marker; the JWT tool page opts into one for its own app via data-tool-mount.
          // Every other diagram-less page still ships none.
          const isToolPage = next.includes('data-tool-mount');
          const scriptBudget = next.includes('data-search-mount') || isToolPage ? 1 : 0;
          // JSON-LD blocks are inert data, not executable JavaScript. The zero-JS
          // guarantee in PRODUCT.md is about runtime scripts, so they don't count.
          const EXECUTABLE_SCRIPT = /<script\b(?![^>]*type="application\/ld\+json")/gi;
          const scriptCount = (next.match(EXECUTABLE_SCRIPT) ?? []).length;
          if (scriptCount > scriptBudget) {
            throw new Error(
              `${file} ships ${scriptCount} script(s), budget is ${scriptBudget}. ` +
                'Update the strip-mermaid-script integration in astro.config.mjs before shipping it.',
            );
          }
          // A tool page must keep exactly its own bundle. MODULE targets /_astro/page.*.js,
          // which is the Mermaid injectScript chunk today; if Astro ever renames the tool
          // page's bundle to match, the strip above would silently delete the app.
          if (isToolPage && scriptCount !== 1) {
            throw new Error(
              `${file} is a data-tool-mount page but ships ${scriptCount} script(s); expected exactly 1. ` +
                'Check whether its bundle was named /_astro/page.*.js and stripped by MODULE.',
            );
          }
          if (next === html) continue;
          await writeFile(file, next);
          stripped += 1;
        }
        logger.info(`stripped the Mermaid client module from ${stripped} diagram-less page(s)`);
      },
    },
  };
}

export default defineConfig({
  site: 'https://nirmala.mrsamdev.xyz',
  markdown: {
    processor: satteri(),
  },
  integrations: [
    mdx(),
    sitemap(),
    mermaid({
      theme: 'base',
      // The site is light-only; never follow prefers-color-scheme into dark diagrams
      // on a light page.
      autoTheme: false,
      themeVariables: {
        primaryColor: '#e4f7ef',
        primaryTextColor: '#004747',
        primaryBorderColor: '#007a54',
        lineColor: '#52706d',
        secondaryColor: '#dbe7e7',
        tertiaryColor: '#f6f9f9',
        textColor: '#1c2524',
        noteBkgColor: '#dbe7e7',
        noteTextColor: '#1c2524',
        noteBorderColor: '#52706d',
        fontSize: '16px',
        fontFamily: 'Nunito, Helvetica, Arial, sans-serif',
      },
    }),
    stripMermaidScript(),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});