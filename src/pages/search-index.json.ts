import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

export const GET: APIRoute = async () => {
  const guides = await getCollection('guides', ({ data }) => data.isPublished !== false);

  const index = guides
    .sort((a, b) => b.data.publishDate.valueOf() - a.data.publishDate.valueOf())
    .map((guide) => ({
      id: guide.id,
      href: `/guides/${guide.id}/`,
      title: guide.data.title,
      excerpt: guide.data.excerpt,
      tags: guide.data.tags,
      body: guide.body ?? '',
    }));

  return new Response(JSON.stringify(index), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
};
