import { defineConfig } from 'astro/config';

// Update `site` to your real domain once DNS is pointed.
export default defineConfig({
  site: 'https://jonny-johnson.dev',
  markdown: {
    shikiConfig: {
      // Dark code theme to match the post layout. Browse themes at:
      // https://shiki.style/themes
      theme: 'github-dark',
      wrap: false,
    },
  },
});
