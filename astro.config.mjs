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

/** @returns {import('astro').AstroIntegration} */
function stripMermaidScript() {
  const MODULE_TAG = /<script type="module" src="([^"]+)"[^>]*><\/script>/g;

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
        const root = fileURLToPath(dir);
        const mermaidChunks = new Set();

        /** @param {string} src */
        const isMermaidChunk = async (src) => {
          if (!src.startsWith('/_astro/')) return false;
          if (mermaidChunks.has(src)) return true;
          try {
            const code = await readFile(join(root, src.replace(/^\//, '')), 'utf8');
            if (code.includes('pre.mermaid') && code.includes('data-processed')) {
              mermaidChunks.add(src);
              return true;
            }
          } catch {}
          return false;
        };

        let stripped = 0;
        for (const file of await htmlFiles(root)) {
          const html = await readFile(file, 'utf8');
          if (html.includes('class="mermaid"')) continue;

          let next = html;
          for (const [tag, src] of [...html.matchAll(MODULE_TAG)].map((m) => [m[0], m[1]])) {
            if (await isMermaidChunk(src)) next = next.replace(tag, '');
          }

          const isToolPage = next.includes('data-tool-mount');
          const scriptBudget =
            (next.includes('data-search-mount') ? 1 : 0) + (isToolPage ? 1 : 0);
          const EXECUTABLE_SCRIPT = /<script\b(?![^>]*type="application\/ld\+json")/gi;
          const scriptCount = (next.match(EXECUTABLE_SCRIPT) ?? []).length;
          if (scriptCount > scriptBudget) {
            throw new Error(
              `${file} ships ${scriptCount} script(s), budget is ${scriptBudget}. ` +
                'Update the strip-mermaid-script integration in astro.config.mjs before shipping it.',
            );
          }
          if (isToolPage && scriptCount !== 1) {
            throw new Error(
              `${file} is a data-tool-mount page but ships ${scriptCount} script(s); expected exactly 1. ` +
                'Check whether its bundle was mistaken for the Mermaid client chunk.',
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