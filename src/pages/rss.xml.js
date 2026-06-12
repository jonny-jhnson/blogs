import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';

export async function GET(context) {
  const posts = await getCollection('blog', ({ data }) => !data.draft);
  return rss({
    title: 'Jonathan Johnson',
    description: 'Windows internals and detection research.',
    site: context.site,
    items: posts
      .sort((a, b) => {
        const ao = a.data.order ?? Infinity;
        const bo = b.data.order ?? Infinity;
        if (ao !== bo) return ao - bo;
        return b.data.pubDate.valueOf() - a.data.pubDate.valueOf();
      })
      .map((post) => ({
        title: post.data.title,
        description: post.data.description,
        pubDate: post.data.pubDate,
        link: `/blog/${post.data.slug}/`,
      })),
  });
}
