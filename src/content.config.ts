import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blog = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/blog' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    tags: z.array(z.string()).default([]),
    readingTime: z.string().optional(),
    draft: z.boolean().default(false),
    // Explicit URL slug - referenced by index.astro, rss.xml.js, and the
    // dynamic [...slug].astro route so we don't depend on Astro's internal id
    // resolution (which changed between content collection versions).
    slug: z.string(),
    // Listing order: higher = closer to top of the feed. Auto-assigned by
    // scripts/medium-convert.mjs as max(existing) + 1 so each new post lands
    // on top regardless of pubDate.
    order: z.number().int(),
  }),
});

export const collections = { blog };
