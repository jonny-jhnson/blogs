import { visit } from 'unist-util-visit';

/**
 * Turns container directives into styled callout boxes.
 *
 *   :::danger[Privilege escalation]
 *   Watch for unsigned DLLs created from medium/high integrity...
 *   :::
 *
 * Renders as:
 *   <aside class="callout callout-danger">
 *     <div class="callout-head">
 *       <span class="callout-badge">High</span>
 *       <span class="callout-title">Privilege escalation</span>   (only if [Title] given)
 *     </div>
 *     <p>Watch for unsigned DLLs...</p>
 *   </aside>
 *
 * Severity tiers (the badge word is fixed per tier; the optional
 * [bracket] text becomes the title beside it):
 *   :::danger   → "High"
 *   :::warning  → "Medium"
 *   :::info     → "Info"
 *   :::note     → "Note"
 *
 * Styling lives in src/styles/global.css (.callout / .callout-*).
 * Plain `> blockquotes` are untouched — use those for genuine quotes.
 */
const TIERS = {
  danger:  'High',
  warning: 'Medium',
  info:    'Info',
  note:    'Note',
};

export default function remarkCallout() {
  return (tree) => {
    visit(tree, 'containerDirective', (node) => {
      const badge = TIERS[node.name];
      if (!badge) return; // ignore unknown directive names

      // Optional title from :::danger[My Title]
      let title = '';
      const first = node.children[0];
      if (first && first.data && first.data.directiveLabel) {
        const label = node.children.shift();
        title = (label.children || []).map((c) => c.value || '').join('');
      }

      node.data = node.data || {};
      node.data.hName = 'aside';
      node.data.hProperties = { className: ['callout', `callout-${node.name}`] };

      // Header row: badge chip + optional title.
      const headChildren = [
        {
          type: 'strong',
          data: { hName: 'span', hProperties: { className: ['callout-badge'] } },
          children: [{ type: 'text', value: badge }],
        },
      ];
      if (title) {
        headChildren.push({
          type: 'strong',
          data: { hName: 'span', hProperties: { className: ['callout-title'] } },
          children: [{ type: 'text', value: title }],
        });
      }

      node.children.unshift({
        type: 'paragraph',
        data: { hName: 'div', hProperties: { className: ['callout-head'] } },
        children: headChildren,
      });
    });
  };
}
