import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

// Build-time index for the guide search box. Content layer + zod are the source of
// truth, so published state and frontmatter stay in sync with the listing page.
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
      // Raw body, code fences included: header names and payloads are
      // exactly the things people search a security guide for.
      body: guide.body ?? '',
    }));

  return new Response(JSON.stringify(index), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
};
