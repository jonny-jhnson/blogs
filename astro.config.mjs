import { defineConfig } from 'astro/config';
import remarkDirective from 'remark-directive';
import remarkCallout from './src/plugins/remark-callout.mjs';

// Update `site` to your real domain once DNS is pointed.
export default defineConfig({
  site: 'https://jonny-johnson.dev',
  markdown: {
    // remarkDirective parses the `:::name` syntax; remarkCallout turns the
    // recognized ones (danger/warning/info/note) into styled callout boxes.
    remarkPlugins: [remarkDirective, remarkCallout],
    shikiConfig: {
      // Dark code theme to match the post layout. Browse themes at:
      // https://shiki.style/themes  — e.g. 'vesper', 'github-dark', 'night-owl'.
      theme: 'github-dark',
      wrap: false,
    },
  },
});
