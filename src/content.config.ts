import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const guides = defineCollection({
  loader: glob({ pattern: '**/*.mdx', base: './src/content/guides' }),
  schema: z.object({
    title: z.string(),
    excerpt: z.string(),
    publishDate: z.coerce.date(),
    tags: z.array(z.string()).default([]),
    isPublished: z.boolean().default(true),
    seo: z
      .object({
        image: z.object({ src: z.string().url(), alt: z.string() }).optional(),
      })
      .optional(),
  }),
});

export const collections = { guides };